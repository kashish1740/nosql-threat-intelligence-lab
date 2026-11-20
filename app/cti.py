"""Experiment 7 — cyber threat analysis of a submitted URL.

Two independent analyses are run and then merged:

1. Threat-feed analysis: URLhaus and ThreatFox (live abuse.ch API lookups, which need a
   free ABUSECH_AUTH_KEY) and the Botvrij.eu OSINT feed (imported into MongoDB and
   matched locally).
2. Vulnerability analysis with GCVE (db.gcve.eu): products recognised in the URL,
   sightings that reference the site, and enrichment of every CVE found (CVSS, EPSS,
   known-exploited status).

Findings from both analyses are de-duplicated by a canonical key and stored in the
MongoDB database ``threat_intelligence`` (browse it in MongoDB Compass).

The submitted URL itself is never fetched or opened: only the intelligence sources are
queried about it, so analysing a malicious link is safe.
"""
import concurrent.futures as futures
import datetime as dt
import ipaddress
import os
import re
import socket
import threading
import uuid
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from pymongo import ASCENDING, DESCENDING, MongoClient, UpdateOne

DB_NAME = os.getenv("CTI_DB", "threat_intelligence")
GCVE = os.getenv("GCVE_BASE_URL", "https://db.gcve.eu/api").rstrip("/")
BOTVRIJ = "https://www.botvrij.eu/data/feed-osint"
URLHAUS = "https://urlhaus-api.abuse.ch/v1"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
VIRUSTOTAL = "https://www.virustotal.com/api/v3"
USER_AGENT = "NoSQL-Lab-CTI/1.0 (educational threat analysis)"
TIMEOUT = httpx.Timeout(25.0, connect=10.0)
BOTVRIJ_MAX_AGE = dt.timedelta(hours=24)
THREATFOX_MAX_AGE = dt.timedelta(hours=6)
MAX_CVE_LOOKUPS = 12
HOST_SIGHTING_LIMIT = 25
EXPLOIT_SIGHTINGS = {"published-proof-of-concept", "exploited", "confirmed"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
NETWORK_TYPES = {"url", "uri", "link-malicious", "domain", "hostname", "ip-dst", "ip-src",
                 "domain|ip", "hostname|port", "ip-dst|port", "ip-src|port"}
# Popular shared platforms: a host-level hit there says little about the specific URL.
SHARED_HOSTS = {"github.com", "raw.githubusercontent.com", "gist.github.com", "google.com", "docs.google.com",
                "drive.google.com", "dropbox.com", "www.dropbox.com", "onedrive.live.com", "1drv.ms",
                "pastebin.com", "discord.com", "cdn.discordapp.com", "t.me", "bit.ly", "microsoft.com",
                "sharepoint.com", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "youtube.com",
                "twitter.com", "x.com", "facebook.com", "linkedin.com", "mediafire.com", "web.archive.org"}
# URL path/host signatures -> (vendor, product) names as used by GCVE / NVD CPE.
PRODUCT_SIGNATURES = [
    (r"/wp-(content|admin|includes|login\.php|json)|xmlrpc\.php", "wordpress", "wordpress", "WordPress"),
    (r"phpmyadmin", "phpmyadmin", "phpmyadmin", "phpMyAdmin"),
    (r"/sites/default/|/user/login|drupal", "drupal", "drupal", "Drupal"),
    (r"/administrator/|option=com_|joomla", "joomla", "joomla", "Joomla!"),
    (r"\.action($|\?)|struts", "apache", "struts", "Apache Struts"),
    (r"/manager/html|tomcat", "apache", "tomcat", "Apache Tomcat"),
    (r"jenkins|/job/[^/]+/build", "jenkins", "jenkins", "Jenkins"),
    (r"/owa/|/ecp/|/autodiscover/|exchange", "microsoft", "exchange_server", "Microsoft Exchange"),
    (r"/remote/(login|fgt_lang)|fortigate|fortinet", "fortinet", "fortios", "Fortinet FortiOS"),
    (r"/global-protect/|/ssl-vpn/|globalprotect", "paloaltonetworks", "pan-os", "Palo Alto PAN-OS"),
    (r"/tmui/|big-?ip", "f5", "big-ip_local_traffic_manager", "F5 BIG-IP"),
    (r"/logon/logonpoint|/vpn/index|netscaler|citrix", "citrix", "netscaler_gateway", "Citrix NetScaler"),
    (r"/dana-na/|pulse ?secure|ivanti", "ivanti", "connect_secure", "Ivanti Connect Secure"),
    (r"confluence|/wiki/spaces", "atlassian", "confluence_server", "Atlassian Confluence"),
    (r"gitlab|/users/sign_in", "gitlab", "gitlab", "GitLab"),
    (r"/solr/", "apache", "solr", "Apache Solr"),
    (r"geoserver", "osgeo", "geoserver", "GeoServer"),
    (r"roundcube", "roundcube", "webmail", "Roundcube Webmail"),
    (r"zimbra", "zimbra", "collaboration", "Zimbra Collaboration"),
]

_client = None
_sync_lock = threading.Lock()
router = APIRouter(prefix="/api/cti")


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def db():
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=4000, tz_aware=True)
    return _client[DB_NAME]


def ensure_indexes():
    d = db()
    d.botvrij_indicators.create_index("match_url")
    d.botvrij_indicators.create_index("match_host")
    d.botvrij_indicators.create_index("match_ip")
    d.botvrij_indicators.create_index("event_uuid")
    for field in ("match_url", "match_host", "match_ip", "imported_at"):
        d.threatfox_indicators.create_index(field)
    d.url_analyses.create_index([("analyzed_at", DESCENDING)])
    d.url_analyses.create_index("normalized_url")
    d.threat_findings.create_index([("kind", ASCENDING), ("last_seen", DESCENDING)])
    d.threat_findings.create_index("urls")


def http():
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def virustotal_key():
    return os.getenv("VT_API_KEY", "").strip()


def abusech_key():
    return os.getenv("ABUSECH_AUTH_KEY", "").strip()


# --------------------------------------------------------------------------- normalisation
def normalize(value):
    """Return dict(url, match_url, host, scheme, kind) for a URL, domain or IP; None if invalid."""
    value = str(value or "").strip().strip("\"'<>").replace("[.]", ".").replace("[:]", ":").replace("(.)", ".")
    # Undo common defanging of the scheme: hxxp://, hxxps://, ttp://, h**p://
    value = re.sub(r"^(?:hxxp|hxp|ttp|h\*\*p)(s?)(?=://|\[://\])", r"http\1", value, flags=re.I).replace("[://]", "://")
    if not value or any(c.isspace() for c in value) or len(value) > 2048:
        return None
    candidate = value if "://" in value else "http://" + value
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
        try:
            ascii_host = host.encode("idna").decode()
        except UnicodeError:
            return None
        if "." not in host or not re.fullmatch(r"[a-z0-9.-]+", ascii_host):
            return None
    scheme = (parts.scheme or "http").lower()
    netloc = host if not port or (scheme, port) in (("http", 80), ("https", 443)) else f"{host}:{port}"
    path = parts.path or "/"
    url = urlunsplit((scheme, netloc, path, parts.query, ""))
    match = (netloc + path.rstrip("/") + ("?" + parts.query if parts.query else "")).lower()
    kind = "url" if ("://" in value or path not in ("", "/") or parts.query) else ("ip" if is_ip else "domain")
    return {"input": value, "url": url, "match_url": match, "host": host, "scheme": scheme, "is_ip": is_ip, "kind": kind}


def parent_hosts(host):
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]


def resolve_ips(host, timeout=3.0):
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    with futures.ThreadPoolExecutor(1) as pool:
        try:
            infos = pool.submit(socket.getaddrinfo, host, None).result(timeout=timeout)
        except Exception:
            return []
    return sorted({i[4][0] for i in infos})[:8]


# --------------------------------------------------------------------------- Botvrij.eu sync
def _match_fields(attr_type, value):
    """Index keys used to match a MISP attribute against a URL/host/IP."""
    value = (value or "").strip()
    fields = {}
    first = value.split("|")[0]
    if attr_type in ("url", "uri", "link-malicious"):
        n = normalize(value)
        if n:
            fields["match_url"] = n["match_url"]
            fields["match_host"] = n["host"]
    elif attr_type in ("domain", "hostname", "domain|ip", "hostname|port"):
        fields["match_host"] = first.lower().rstrip(".")
        if attr_type == "domain|ip" and "|" in value:
            fields["match_ip"] = value.split("|")[1]
    elif attr_type in ("ip-dst", "ip-src", "ip-dst|port", "ip-src|port"):
        fields["match_ip"] = first
    return fields


def _event_documents(event_uuid, event):
    tags = [t.get("name") for t in event.get("Tag", []) if isinstance(t, dict)]
    attributes = list(event.get("Attribute", []))
    for obj in event.get("Object", []) or []:
        attributes += obj.get("Attribute", []) or []
    docs = []
    for a in attributes:
        if not isinstance(a, dict) or a.get("deleted"):
            continue
        value = str(a.get("value", "")).strip()
        if not value:
            continue
        doc = {"_id": f"{event_uuid}:{a.get('uuid') or value}", "source": "Botvrij.eu", "value": value,
               "type": a.get("type"), "category": a.get("category"), "comment": a.get("comment") or "",
               "to_ids": bool(a.get("to_ids")), "event_uuid": event_uuid, "event_info": event.get("info"),
               "event_date": event.get("date"), "threat_level_id": event.get("threat_level_id"), "event_tags": tags,
               "event_url": f"{BOTVRIJ}/{event_uuid}.json", "imported_at": utcnow()}
        doc.update(_match_fields(a.get("type"), value))
        docs.append(doc)
    return docs


def sync_botvrij(force=False):
    """Import the Botvrij.eu OSINT feed into MongoDB, re-downloading only changed events."""
    if not _sync_lock.acquire(blocking=False):
        return {"status": "already_running"}
    d = db()
    started = utcnow()
    try:
        d.feed_status.update_one({"_id": "botvrij"}, {"$set": {"state": "syncing", "started_at": started}}, upsert=True)
        with http() as client:
            manifest = client.get(f"{BOTVRIJ}/manifest.json").raise_for_status().json()
            known = {e["_id"]: e.get("timestamp") for e in d.botvrij_events.find({}, {"timestamp": 1})}
            todo = [k for k, meta in manifest.items() if force or known.get(k) != str(meta.get("timestamp"))]

            def fetch(event_uuid):
                r = client.get(f"{BOTVRIJ}/{event_uuid}.json")
                if r.status_code == 404:
                    return event_uuid, None
                r.raise_for_status()
                data = r.json()
                return event_uuid, data.get("Event", data)

            failed = 0
            with futures.ThreadPoolExecutor(8) as pool:
                for job in futures.as_completed([pool.submit(fetch, k) for k in todo]):
                    try:
                        event_uuid, event = job.result()
                    except Exception:
                        failed += 1
                        continue
                    if event is None:
                        continue
                    docs = _event_documents(event_uuid, event)
                    d.botvrij_indicators.delete_many({"event_uuid": event_uuid})
                    if docs:
                        d.botvrij_indicators.insert_many(docs, ordered=False)
                    meta = manifest[event_uuid]
                    d.botvrij_events.replace_one({"_id": event_uuid}, {
                        "_id": event_uuid, "info": event.get("info"), "date": event.get("date"),
                        "timestamp": str(meta.get("timestamp")), "threat_level_id": event.get("threat_level_id"),
                        "attribute_count": len(docs), "synced_at": utcnow()}, upsert=True)
            removed = [k for k in known if k not in manifest]
            if removed:
                d.botvrij_indicators.delete_many({"event_uuid": {"$in": removed}})
                d.botvrij_events.delete_many({"_id": {"$in": removed}})
        status = {"state": "ready", "last_sync": utcnow(), "events": d.botvrij_events.count_documents({}),
                  "indicators": d.botvrij_indicators.count_documents({}), "updated_events": len(todo) - failed,
                  "failed_events": failed, "error": None}
    except Exception as exc:
        status = {"state": "error", "error": f"{type(exc).__name__}: {exc}"[:300], "last_attempt": utcnow()}
    finally:
        _sync_lock.release()
    d.feed_status.update_one({"_id": "botvrij"}, {"$set": status}, upsert=True)
    return status


def _threatfox_match_fields(ioc_type, value):
    value = (value or "").strip()
    if ioc_type == "url":
        n = normalize(value)
        return {"match_url": n["match_url"], "match_host": n["host"]} if n else {}
    if ioc_type == "domain":
        return {"match_host": value.lower().rstrip(".")}
    if ioc_type == "ip:port":
        return {"match_ip": value.rsplit(":", 1)[0].strip("[]")}
    return {}


def sync_threatfox():
    """Import ThreatFox IOCs from the last 7 days. Its search API cannot look up full URLs, so URL
    IOCs are matched locally from MongoDB; domains and IPs are also searched live."""
    key = abusech_key()
    if not key:
        return {"state": "not_configured"}
    d = db()
    d.feed_status.update_one({"_id": "threatfox"}, {"$set": {"state": "syncing", "started_at": utcnow()}}, upsert=True)
    try:
        with http() as client:
            r = client.post(THREATFOX, json={"query": "get_iocs", "days": 7}, headers={"Auth-Key": key})
            r.raise_for_status()
            rows = r.json().get("data") or []
        now = utcnow()
        ops = []
        for ioc in rows if isinstance(rows, list) else []:
            doc = {"source": "ThreatFox", "value": ioc.get("ioc"), "ioc_type": ioc.get("ioc_type"),
                   "threat_type": ioc.get("threat_type_desc") or ioc.get("threat_type"), "malware": ioc.get("malware_printable"),
                   "confidence": ioc.get("confidence_level"), "first_seen": ioc.get("first_seen"), "last_seen": ioc.get("last_seen"),
                   "tags": ioc.get("tags") or [], "reference": f"https://threatfox.abuse.ch/ioc/{ioc.get('id')}/", "imported_at": now}
            doc.update(_threatfox_match_fields(ioc.get("ioc_type"), ioc.get("ioc")))
            ops.append(UpdateOne({"_id": f"tf:{ioc.get('id')}"}, {"$set": doc}, upsert=True))
        if ops:
            d.threatfox_indicators.bulk_write(ops, ordered=False)
        # Keep a rolling 30-day window so the collection does not grow without bound.
        d.threatfox_indicators.delete_many({"imported_at": {"$lt": now - dt.timedelta(days=30)}})
        status = {"state": "ready", "last_sync": now, "imported": len(ops),
                  "indicators": d.threatfox_indicators.count_documents({}), "error": None}
    except Exception as exc:
        status = {"state": "error", "error": f"{type(exc).__name__}: {exc}"[:300], "last_attempt": utcnow()}
    d.feed_status.update_one({"_id": "threatfox"}, {"$set": status}, upsert=True)
    return status


def sync_all(force=False):
    sync_botvrij(force)
    sync_threatfox()


def sync_if_stale():
    try:
        ensure_indexes()
        status = db().feed_status.find_one({"_id": "botvrij"}) or {}
        last = status.get("last_sync")
        if not last or utcnow() - last > BOTVRIJ_MAX_AGE or status.get("state") == "syncing":
            sync_botvrij()
        tf = db().feed_status.find_one({"_id": "threatfox"}) or {}
        if abusech_key() and (not tf.get("last_sync") or utcnow() - tf["last_sync"] > THREATFOX_MAX_AGE):
            sync_threatfox()
    except Exception:
        pass  # The page shows the feed state; analysis still runs against other sources.


# --------------------------------------------------------------------------- threat-feed analysis
def check_botvrij(target, ips):
    query = [{"match_url": target["match_url"]}, {"match_host": {"$in": parent_hosts(target["host"])}}]
    if ips:
        query.append({"match_ip": {"$in": ips}})
    hits = list(db().botvrij_indicators.find({"$or": query}, {"imported_at": 0}).limit(200))
    matches = []
    for h in hits:
        if h.get("match_url") == target["match_url"]:
            how = "exact URL"
        elif h.get("match_host") == target["host"]:
            how = "same host"
        elif h.get("match_host") in parent_hosts(target["host"]):
            how = "parent domain"
        else:
            how = "resolved IP"
        # A listed report link on a shared platform (e.g. a GitHub write-up) is not an IOC for that platform.
        if how != "exact URL" and (h.get("type") not in NETWORK_TYPES or target["host"] in SHARED_HOSTS):
            continue
        matches.append({"match": how, "value": h["value"], "type": h.get("type"), "category": h.get("category"),
                        "event": h.get("event_info"), "event_date": h.get("event_date"), "event_uuid": h.get("event_uuid"),
                        "event_url": h.get("event_url"), "comment": h.get("comment"), "to_ids": h.get("to_ids")})
    events = {m["event_uuid"] for m in matches}
    cves = sorted({v["value"].upper() for v in db().botvrij_indicators.find(
        {"event_uuid": {"$in": list(events)}, "type": "vulnerability"}, {"value": 1})}) if events else []
    status = (db().feed_status.find_one({"_id": "botvrij"}) or {})
    return {"source": "Botvrij.eu", "status": "hit" if matches else ("no_match" if status.get("indicators") else "not_synced"),
            "matches": matches, "related_cves": cves, "indicators_checked": status.get("indicators", 0)}


def check_urlhaus(target, client):
    key = abusech_key()
    if not key:
        return {"source": "URLhaus", "status": "not_configured",
                "message": "Set ABUSECH_AUTH_KEY (free at https://auth.abuse.ch/) to query URLhaus."}
    headers = {"Auth-Key": key}
    out = {"source": "URLhaus", "status": "no_match", "matches": []}
    try:
        if target["kind"] == "url":
            r = client.post(f"{URLHAUS}/url/", data={"url": target["url"]}, headers=headers).json()
            if r.get("query_status") == "ok":
                out["matches"].append({"match": "exact URL", "value": r.get("url"), "url_status": r.get("url_status"),
                                       "threat": r.get("threat"), "tags": r.get("tags") or [], "date_added": r.get("date_added"),
                                       "reference": r.get("urlhaus_reference"),
                                       "payloads": [p.get("signature") for p in r.get("payloads") or [] if p.get("signature")][:10]})
        r = client.post(f"{URLHAUS}/host/", data={"host": target["host"]}, headers=headers).json()
        if r.get("query_status") == "ok":
            urls = r.get("urls") or []
            out["host"] = {"url_count": r.get("url_count"), "blacklists": r.get("blacklists"),
                           "first_seen": r.get("firstseen"), "reference": r.get("urlhaus_reference"),
                           "online_urls": sum(1 for u in urls if u.get("url_status") == "online")}
            if target["host"] not in SHARED_HOSTS:
                for u in urls[:20]:
                    n = normalize(u.get("url"))
                    if n and n["match_url"] == target["match_url"] and out["matches"]:
                        continue  # already reported above as the exact URL
                    out["matches"].append({"match": "same host", "value": u.get("url"), "url_status": u.get("url_status"),
                                           "threat": u.get("threat"), "tags": u.get("tags") or [], "date_added": u.get("date_added"),
                                           "reference": u.get("urlhaus_reference")})
        elif r.get("query_status") not in ("no_results", "ok"):
            out.update(status="error", message=f"URLhaus answered: {r.get('query_status')}")
    except Exception as exc:
        out.update(status="error", message=f"URLhaus request failed: {type(exc).__name__}")
    if out["matches"]:
        out["status"] = "hit"
    return out


def check_virustotal(target, client):
    """Read VirusTotal's existing URL and domain/IP reports. The URL is never submitted for a new
    scan, because submitting would publish it to VirusTotal (free API: 4 requests/minute)."""
    import base64
    key = virustotal_key()
    if not key:
        return {"source": "VirusTotal", "status": "not_configured",
                "message": "Set VT_API_KEY (free at https://www.virustotal.com/gui/my-apikey) to query VirusTotal."}
    headers = {"x-apikey": key}
    out = {"source": "VirusTotal", "status": "no_match", "matches": [], "stats": {}}

    def flagged(attrs):
        stats = attrs.get("last_analysis_stats") or {}
        engines = sorted(f"{name}: {r.get('result') or r.get('category')}"
                         for name, r in (attrs.get("last_analysis_results") or {}).items()
                         if r.get("category") in ("malicious", "suspicious"))
        return stats, engines

    try:
        if target["kind"] == "url":
            url_id = base64.urlsafe_b64encode(target["url"].encode()).decode().rstrip("=")
            r = client.get(f"{VIRUSTOTAL}/urls/{url_id}", headers=headers)
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats, engines = flagged(attrs)
                out["stats"]["url"] = {**stats, "reputation": attrs.get("reputation"),
                                       "last_analysis": attrs.get("last_analysis_date"), "categories": attrs.get("categories")}
                if engines:
                    out["matches"].append({"match": "exact URL", "value": target["url"], "malicious": stats.get("malicious", 0),
                                           "threat": f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious of {sum(stats.values())} engines",
                                           "engines": engines[:15], "reference": f"https://www.virustotal.com/gui/url/{url_id}"})
            elif r.status_code == 404:
                out["stats"]["url"] = {"not_found": True}
            elif r.status_code in (401, 403):
                return {**out, "status": "error", "message": "VirusTotal rejected the API key."}
            elif r.status_code == 429:
                return {**out, "status": "error", "message": "VirusTotal rate limit reached (free key: 4 lookups per minute). Try again shortly."}
        kind = "ip_addresses" if target["is_ip"] else "domains"
        r = client.get(f"{VIRUSTOTAL}/{kind}/{target['host']}", headers=headers)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats, engines = flagged(attrs)
            out["stats"]["host"] = {**stats, "reputation": attrs.get("reputation")}
            if engines and target["host"] not in SHARED_HOSTS:
                out["matches"].append({"match": "same host", "value": target["host"], "malicious": stats.get("malicious", 0),
                                       "threat": f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious of {sum(stats.values())} engines (domain/IP)",
                                       "engines": engines[:15], "reference": f"https://www.virustotal.com/gui/{'ip-address' if target['is_ip'] else 'domain'}/{target['host']}"})
        elif r.status_code == 429:
            out["message"] = "Domain check skipped: VirusTotal rate limit (4/min on a free key)."
    except Exception as exc:
        out.update(status="error", message=f"VirusTotal request failed: {type(exc).__name__}")
        return out
    if out["matches"]:
        out["status"] = "hit"
        # One or two engines alone are often false positives; weigh by how many agree.
        top = max(m["malicious"] for m in out["matches"])
        exact = any(m["match"] == "exact URL" for m in out["matches"])
        out["score_points"] = (60 if exact else 35) if top >= 3 else 15 if top >= 1 else 5
        out["score_reason"] = f"VirusTotal: {top} engine{'s' if top != 1 else ''} flag this {'URL' if exact else 'domain/IP'}"
    elif "url" in out["stats"] and out["stats"]["url"].get("not_found"):
        out["message"] = "VirusTotal has no report for this exact URL (it was not submitted)."
    return out


def check_threatfox(target, client, ips=()):
    """Live search for the host/IP (ThreatFox's search cannot look up full URLs) plus a local match of
    the last 7 days of ThreatFox IOCs imported into MongoDB, which covers exact URLs and resolved IPs."""
    key = abusech_key()
    if not key:
        return {"source": "ThreatFox", "status": "not_configured",
                "message": "Set ABUSECH_AUTH_KEY (free at https://auth.abuse.ch/) to query ThreatFox."}
    out = {"source": "ThreatFox", "status": "no_match", "matches": []}
    seen = set()

    def add(match, ioc, reference):
        if reference in seen:
            return
        seen.add(reference)
        out["matches"].append({"match": match, "value": ioc.get("value") or ioc.get("ioc"), "ioc_type": ioc.get("ioc_type"),
                               "threat_type": ioc.get("threat_type") if "threat_type_desc" not in ioc else ioc.get("threat_type_desc"),
                               "malware": ioc.get("malware") or ioc.get("malware_printable"),
                               "confidence": ioc.get("confidence") or ioc.get("confidence_level"),
                               "first_seen": ioc.get("first_seen"), "last_seen": ioc.get("last_seen"),
                               "tags": ioc.get("tags") or [], "reference": reference})

    # 1) local: recent IOCs imported into MongoDB
    try:
        query = [{"match_url": target["match_url"]}, {"match_host": {"$in": parent_hosts(target["host"])}}]
        if ips:
            query.append({"match_ip": {"$in": list(ips)}})
        for doc in db().threatfox_indicators.find({"$or": query}).limit(100):
            if doc.get("match_url") == target["match_url"]:
                how = "exact URL"
            elif doc.get("match_host") == target["host"]:
                how = "same host"
            elif doc.get("match_host") in parent_hosts(target["host"]):
                how = "parent domain"
            else:
                how = "resolved IP"
            if how != "exact URL" and target["host"] in SHARED_HOSTS:
                continue
            add(how, doc, doc.get("reference"))
    except Exception:
        pass
    # 2) live: full ThreatFox history for the host or IP
    try:
        r = client.post(THREATFOX, json={"query": "search_ioc", "search_term": target["host"], "exact_match": True},
                        headers={"Auth-Key": key}).json()
        if r.get("query_status") == "ok":
            for ioc in r.get("data") or []:
                n = normalize(ioc.get("ioc", "").split("|")[0]) if ioc.get("ioc_type") == "url" else None
                how = "exact URL" if n and n["match_url"] == target["match_url"] else "same host"
                if how != "exact URL" and target["host"] in SHARED_HOSTS:
                    continue
                add(how, ioc, f"https://threatfox.abuse.ch/ioc/{ioc.get('id')}/")
        elif r.get("query_status") not in ("no_result", "no_results"):
            out.update(status="error", message=f"ThreatFox answered: {r.get('query_status')}")
    except Exception as exc:
        out.update(status="error", message=f"ThreatFox request failed: {type(exc).__name__}")
    tf = db().feed_status.find_one({"_id": "threatfox"}) or {}
    out["indicators_checked"] = tf.get("indicators", 0)
    if out["matches"]:
        out["status"] = "hit"
    return out


# --------------------------------------------------------------------------- GCVE analysis
def _english(items):
    for item in items or []:
        if isinstance(item, dict) and item.get("lang", "en").startswith("en") and item.get("value"):
            return item["value"]
    return ""


def _cvss_from_metrics(metrics):
    best = None
    if isinstance(metrics, dict):  # NVD style
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key) or []:
                data = m.get("cvssData", {})
                if data.get("baseScore") is not None:
                    return {"score": data["baseScore"], "severity": data.get("baseSeverity") or m.get("baseSeverity"), "version": data.get("version")}
    if isinstance(metrics, list):  # CVE 5 style
        for m in metrics:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                data = m.get(key) if isinstance(m, dict) else None
                if data and data.get("baseScore") is not None:
                    return {"score": data["baseScore"], "severity": data.get("baseSeverity"), "version": data.get("version")}
    return best


def vulnerability_summary(record):
    """Normalise CVE 5, NVD and OSV/GHSA records into one short summary."""
    if not isinstance(record, dict):
        return None
    meta = record.get("cveMetadata") or {}
    if meta.get("cveId"):
        cna = (record.get("containers") or {}).get("cna") or {}
        metrics = list(cna.get("metrics") or [])
        for adp in (record.get("containers") or {}).get("adp") or []:
            metrics += adp.get("metrics") or []
        return {"id": meta["cveId"].upper(), "title": cna.get("title") or "", "description": _english(cna.get("descriptions"))[:600],
                "published": meta.get("datePublished"), "cvss": _cvss_from_metrics(metrics), "aliases": [],
                "products": [f"{a.get('vendor')} {a.get('product')}" for a in cna.get("affected") or [] if isinstance(a, dict)][:5]}
    vid = record.get("id") or record.get("vulnerability_id")
    if not vid:
        return None
    description = _english(record.get("descriptions")) or record.get("summary") or record.get("details") or ""
    aliases = [a.upper() for a in record.get("aliases") or [] if isinstance(a, str)]
    cvss = _cvss_from_metrics(record.get("metrics"))
    if not cvss and isinstance(record.get("severity"), list) and record["severity"]:
        cvss = {"score": None, "severity": None, "vector": record["severity"][0].get("score")}
    return {"id": str(vid).upper(), "title": record.get("summary") or "", "description": str(description)[:600],
            "published": record.get("published"), "cvss": cvss, "aliases": aliases, "products": []}


def detect_products(target):
    text = (target["host"] + " " + target["match_url"]).lower()
    found, seen = [], set()
    for pattern, vendor, product, label in PRODUCT_SIGNATURES:
        if re.search(pattern, text) and (vendor, product) not in seen:
            seen.add((vendor, product))
            found.append({"vendor": vendor, "product": product, "label": label, "evidence": re.search(pattern, text).group(0)})
    return found


def _get_json(client, path, **params):
    r = client.get(GCVE + path, params=params or None)
    r.raise_for_status()
    return r.json()


def gcve_enrich(client, vuln_id):
    """GCVE record + EPSS + known-exploited status for one vulnerability id."""
    info = {"id": vuln_id}
    try:
        info.update({k: v for k, v in (vulnerability_summary(_get_json(client, f"/vulnerability/{quote(vuln_id)}")) or {}).items() if v not in (None, "", [])})
        info["found"] = True
    except Exception:
        info["found"] = False
    if vuln_id.upper().startswith("CVE-"):
        try:
            data = _get_json(client, f"/epss/{quote(vuln_id)}").get("data") or []
            if data:
                info["epss"] = float(data[0].get("epss"))
                info["epss_percentile"] = float(data[0].get("percentile"))
        except Exception:
            pass
    try:
        kev = _get_json(client, "/kev", vuln_id=vuln_id, per_page=1)
        rows = kev.get("data") or []
        info["known_exploited"] = bool(rows and (rows[0].get("status") or {}).get("exploited"))
    except Exception:
        pass
    info["link"] = f"https://db.gcve.eu/vuln/{quote(vuln_id.lower())}"
    return info


def analyse_gcve(target, extra_cves, client):
    out = {"source": "GCVE (db.gcve.eu)", "status": "ok", "products": [], "sightings": {}, "vendor": None,
           "vulnerabilities": [], "errors": []}
    candidate_ids = {c.upper(): "referenced by threat feed" for c in extra_cves}
    for c in CVE_RE.findall(target["input"]):
        candidate_ids.setdefault(c.upper(), "named in the URL")

    def product_job(p):
        data = _get_json(client, f"/vulnerability/search/{quote(p['vendor'])}/{quote(p['product'])}", per_page=5)
        recent = []
        for source_rows in (data.get("results") or {}).values():
            for row in source_rows:
                s = vulnerability_summary(row[1] if isinstance(row, list) and len(row) > 1 else row)
                if s and s["id"] not in {x["id"] for x in recent}:
                    recent.append(s)
        return {**p, "total_vulnerabilities": data.get("total_count"), "recent": recent[:5]}

    def sightings_job(term):
        data = _get_json(client, "/sighting", source=term, per_page=25)
        rows = data.get("data") or []
        return term, {"count": (data.get("metadata") or {}).get("count", len(rows)),
                      "items": [{"vulnerability": (r.get("vulnerability") or "").upper(), "type": r.get("type"),
                                 "source": r.get("source"), "date": r.get("creation_timestamp")} for r in rows]}

    def vendor_job(label):
        products = client.get(f"{GCVE}/browse/{quote(label)}").json()
        return {"vendor": label, "product_count": len(products), "sample_products": products[:8]} if products else None

    products = detect_products(target)
    label = target["host"].split(".")[-2] if not target["is_ip"] and target["host"].count(".") >= 1 else None
    sighting_terms = [target["host"]] + ([target["match_url"]] if target["kind"] == "url" and target["match_url"] != target["host"] else [])
    with futures.ThreadPoolExecutor(6) as pool:
        product_jobs = [pool.submit(product_job, p) for p in products]
        sighting_jobs = [pool.submit(sightings_job, t) for t in sighting_terms]
        vendor_future = pool.submit(vendor_job, label) if label and len(label) > 2 else None
        for job in product_jobs:
            try:
                out["products"].append(job.result())
            except Exception as exc:
                out["errors"].append(f"product search: {type(exc).__name__}")
        for job in sighting_jobs:
            try:
                term, data = job.result()
                out["sightings"]["url" if term == target["match_url"] else "host"] = data
            except Exception as exc:
                out["errors"].append(f"sightings: {type(exc).__name__}")
        if vendor_future:
            try:
                out["vendor"] = vendor_future.result()
            except Exception:
                pass

    # Sightings on this exact page are direct evidence. Host-level sightings count only for small
    # sites: big platforms (GitHub, NVD, news sites) mention thousands of CVEs and would be noise.
    # Recent product vulnerabilities stay as context only: whether they apply depends on the version.
    for scope in ("url", "host"):
        data = out["sightings"].get(scope) or {}
        if scope == "host" and (target["host"] in SHARED_HOSTS or (data.get("count") or 0) > HOST_SIGHTING_LIMIT):
            if data:
                data["ignored"] = "too many references on this host to attribute to the URL"
            continue
        for item in data.get("items", []):
            if item["vulnerability"]:
                candidate_ids.setdefault(item["vulnerability"], f"GCVE sighting ({item['type']}) on this {'page' if scope == 'url' else 'host'}")

    ids = list(candidate_ids)[:MAX_CVE_LOOKUPS]
    with futures.ThreadPoolExecutor(6) as pool:
        for vid, info in zip(ids, pool.map(lambda v: gcve_enrich(client, v), ids)):
            info["reason"] = candidate_ids[vid]
            out["vulnerabilities"].append(info)
    if out["errors"] and not (out["products"] or out["sightings"] or out["vulnerabilities"]):
        out["status"] = "error"
    return out


# --------------------------------------------------------------------------- merge, de-duplicate, score
def indicator_key(value):
    n = normalize(value)
    if not n:
        return "ioc:" + str(value).strip().lower()
    return ("ioc:url:" + n["match_url"]) if n["kind"] == "url" else ("ioc:host:" + n["host"])


def merge_findings(feeds, gcve):
    raw, merged = [], {}

    def add(key, kind, value, source, detail):
        raw.append(key)
        f = merged.setdefault(key, {"key": key, "kind": kind, "value": value, "sources": [], "evidence": []})
        if source not in f["sources"]:
            f["sources"].append(source)
        f["evidence"].append({"source": source, **detail})

    for feed in feeds:
        for m in feed.get("matches", []):
            add(indicator_key(m["value"]), "indicator", m["value"], feed["source"],
                {k: m.get(k) for k in ("match", "threat", "threat_type", "malware", "url_status", "event", "type", "reference", "event_url") if m.get(k)})
            for tag in m.get("tags") or []:
                for cve in CVE_RE.findall(str(tag)):
                    add("vuln:" + cve.upper(), "vulnerability", cve.upper(), feed["source"], {"via": "IOC tag"})
        for cve in feed.get("related_cves", []):
            add("vuln:" + cve, "vulnerability", cve, feed["source"], {"via": "same MISP event"})
    aliases = {}
    for v in gcve.get("vulnerabilities", []):
        for a in v.get("aliases") or []:
            aliases[a] = v["id"]
    for v in gcve.get("vulnerabilities", []):
        add("vuln:" + v["id"], "vulnerability", v["id"], "GCVE",
            {k: v.get(k) for k in ("reason", "title", "cvss", "epss", "known_exploited", "link") if v.get(k) not in (None, "")})
    # Fold aliases (e.g. GHSA ids) into their canonical CVE so one issue is reported once.
    for alias, canonical in aliases.items():
        a, c = "vuln:" + alias, "vuln:" + canonical
        if a in merged and c in merged and a != c:
            dup = merged.pop(a)
            merged[c]["sources"] += [s for s in dup["sources"] if s not in merged[c]["sources"]]
            merged[c]["evidence"] += dup["evidence"]
    findings = sorted(merged.values(), key=lambda f: (f["kind"] != "indicator", -len(f["sources"]), f["value"]))
    return findings, len(raw)


def score(feeds, gcve, findings):
    points, reasons = 0, []
    for feed in feeds:
        if feed.get("score_points") is not None:  # sources that weigh their own evidence (VirusTotal engine counts)
            points += feed["score_points"]; reasons.append(feed["score_reason"])
            continue
        exact = [m for m in feed.get("matches", []) if m["match"] == "exact URL"]
        host = [m for m in feed.get("matches", []) if m["match"] in ("same host", "parent domain")]
        ip = [m for m in feed.get("matches", []) if m["match"] == "resolved IP"]
        if exact:
            points += 60; reasons.append(f"{feed['source']} lists this exact URL")
        elif host:
            points += 35; reasons.append(f"{feed['source']} lists this host/domain ({len(host)} indicator{'s' if len(host) > 1 else ''})")
        elif ip:
            points += 15; reasons.append(f"{feed['source']} lists an IP this host resolves to")
    vulns = gcve.get("vulnerabilities", [])
    kev = [v for v in vulns if v.get("known_exploited")]
    hot = [v for v in vulns if (v.get("epss") or 0) >= 0.5]
    page_items = (gcve.get("sightings", {}).get("url") or {}).get("items", [])
    exploit_sightings = [s for s in page_items if s.get("type") in EXPLOIT_SIGHTINGS]
    if kev:
        points += min(20, 8 * len(kev)); reasons.append(f"{len(kev)} related vulnerabilit{'ies are' if len(kev) > 1 else 'y is'} known to be exploited")
    if hot:
        points += min(10, 5 * len(hot)); reasons.append(f"{len(hot)} related vulnerabilit{'ies have' if len(hot) > 1 else 'y has'} EPSS ≥ 0.5")
    if exploit_sightings:
        points += 15; reasons.append(f"GCVE records {len(exploit_sightings)} exploit/proof-of-concept sighting{'s' if len(exploit_sightings) > 1 else ''} on this page")
    elif page_items:
        reasons.append(f"GCVE records {len(page_items)} vulnerability mention{'s' if len(page_items) > 1 else ''} on this page (informational)")
    if gcve.get("products"):
        # Informational only: exposure of a product does not make the URL malicious.
        reasons.append("URL exposes " + ", ".join(p["label"] for p in gcve["products"]) + " — check the installed version against the GCVE list")
    multi = [f for f in findings if len(f["sources"]) > 1]
    if multi:
        points += 10; reasons.append(f"{len(multi)} finding{'s' if len(multi) > 1 else ''} confirmed by more than one source")
    points = min(points, 100)
    verdict = "Malicious" if points >= 60 else "Suspicious" if points >= 30 else "Low risk" if points > 0 else "No known threats"
    return points, verdict, reasons


def build_summary(target, verdict, points, reasons, feeds, gcve, unique, raw_count):
    hits = [f["source"] for f in feeds if f["status"] == "hit"]
    lines = [f"{target['url']} was assessed as **{verdict}** (risk score {points}/100)."]
    lines.append(f"Threat feeds with matches: {', '.join(hits) if hits else 'none'}.")
    lines.append(f"GCVE linked {len(gcve.get('vulnerabilities', []))} vulnerabilit{'y' if len(gcve.get('vulnerabilities', [])) == 1 else 'ies'}"
                 + (f" and recognised {', '.join(p['label'] for p in gcve['products'])}" if gcve.get("products") else "") + ".")
    lines.append(f"{raw_count} raw findings were merged into {unique} unique findings ({raw_count - unique} duplicates removed).")
    if not reasons:
        lines.append("No source reported this URL. That is not proof the URL is safe: feeds only contain what has been reported.")
    return " ".join(lines)


# --------------------------------------------------------------------------- orchestration + storage
def analyse(raw_url):
    target = normalize(raw_url)
    if not target:
        raise ValueError("Enter a valid URL, domain or IP address, for example http://example.com/path")
    started = utcnow()
    ips = resolve_ips(target["host"])
    with http() as client, futures.ThreadPoolExecutor(3) as pool:
        jobs = [pool.submit(check_urlhaus, target, client), pool.submit(check_threatfox, target, client, ips),
                pool.submit(check_virustotal, target, client)]
        botvrij = check_botvrij(target, ips)
        feeds = [j.result() for j in jobs] + [botvrij]
        feed_cves = set(botvrij.get("related_cves", []))
        for f in feeds:
            for m in f.get("matches", []):
                for tag in m.get("tags") or []:
                    feed_cves.update(c.upper() for c in CVE_RE.findall(str(tag)))
        try:
            gcve = analyse_gcve(target, sorted(feed_cves), client)
        except Exception as exc:
            gcve = {"source": "GCVE (db.gcve.eu)", "status": "error", "errors": [type(exc).__name__], "vulnerabilities": [], "products": [], "sightings": {}}
    findings, raw_count = merge_findings(feeds, gcve)
    points, verdict, reasons = score(feeds, gcve, findings)
    report = {
        "_id": str(uuid.uuid4()), "analyzed_at": started, "duration_seconds": round((utcnow() - started).total_seconds(), 2),
        "input": target["input"], "url": target["url"], "normalized_url": target["match_url"], "host": target["host"],
        "input_kind": target["kind"], "resolved_ips": ips, "verdict": verdict, "risk_score": points, "reasons": reasons,
        "feed_analysis": feeds, "gcve_analysis": gcve, "findings": findings,
        "dedup": {"raw_findings": raw_count, "unique_findings": len(findings), "duplicates_removed": raw_count - len(findings)},
        "sources_checked": {f["source"]: f["status"] for f in feeds} | {"GCVE": gcve.get("status")},
        "note": "The submitted URL was not opened; only threat-intelligence sources were queried.",
    }
    report["summary"] = build_summary(target, verdict, points, reasons, feeds, gcve, len(findings), raw_count)
    store(report)
    return report


def store(report):
    d = db()
    d.url_analyses.insert_one(report)
    now = report["analyzed_at"]
    ops = [UpdateOne({"_id": f["key"]}, {
        "$set": {"kind": f["kind"], "value": f["value"], "last_seen": now, "latest_evidence": f["evidence"][-5:]},
        "$setOnInsert": {"first_seen": now},
        "$addToSet": {"sources": {"$each": f["sources"]}, "urls": report["normalized_url"], "analysis_ids": report["_id"]},
        "$inc": {"times_reported": 1}}, upsert=True) for f in report["findings"]]
    if ops:
        d.threat_findings.bulk_write(ops, ordered=False)


# --------------------------------------------------------------------------- API
class AnalyseRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def _clean(doc):
    if isinstance(doc, dict):
        return {k: _clean(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_clean(v) for v in doc]
    if isinstance(doc, dt.datetime):
        return doc.isoformat()
    return doc


@router.post("/analyze")
def analyze_endpoint(request: AnalyseRequest):
    try:
        return _clean(analyse(request.url))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/analyses")
def analyses(limit: int = 20):
    rows = db().url_analyses.find({}, {"url": 1, "verdict": 1, "risk_score": 1, "analyzed_at": 1, "dedup": 1}).sort("analyzed_at", -1).limit(min(limit, 100))
    return _clean(list(rows))


@router.get("/analyses/{analysis_id}")
def analysis(analysis_id: str):
    doc = db().url_analyses.find_one({"_id": analysis_id})
    if not doc:
        raise HTTPException(404, "Analysis not found")
    return _clean(doc)


@router.get("/findings")
def findings(limit: int = 50):
    return _clean(list(db().threat_findings.find().sort("last_seen", -1).limit(min(limit, 200))))


@router.get("/status")
def status():
    d = db()
    bot = d.feed_status.find_one({"_id": "botvrij"}) or {"state": "not_synced"}
    sample = d.botvrij_indicators.find_one({"type": "url", "match_url": {"$exists": True}}, {"value": 1}, sort=[("event_date", -1)])
    return _clean({
        "database": DB_NAME,
        "compass_uri": "mongodb://localhost:27018/" + DB_NAME,
        "abusech_key_configured": bool(abusech_key()),
        "virustotal_key_configured": bool(virustotal_key()),
        "botvrij": {k: v for k, v in bot.items() if k != "_id"},
        "threatfox": {k: v for k, v in (d.feed_status.find_one({"_id": "threatfox"}) or {"state": "not_synced"}).items() if k != "_id"},
        "collections": {name: d[name].estimated_document_count() for name in
                        ("url_analyses", "threat_findings", "botvrij_indicators", "botvrij_events", "threatfox_indicators", "feed_status")},
        "sample_url": (normalize(sample["value"]) or {}).get("url") if sample else None,
    })


@router.post("/feeds/sync")
def feeds_sync(background: BackgroundTasks, force: bool = False):
    background.add_task(sync_all, force)
    return {"status": "started"}
