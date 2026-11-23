"""PC threat scan: receives a read-only scan from scripts/scan-pc.ps1, checks it, stores it in MongoDB.

Checks (each problem becomes a finding with an id the Threat Assistant can cite, e.g. [PC-DEF-RTP]):
  * Microsoft Defender: antivirus / real-time protection off, old signatures, no recent scan, detected threats
  * Windows Firewall profiles switched off
  * Windows release past end of support, no update installed for a long time
  * installed programs past end of life or behind the latest security release (endoflife.date),
    with recent vulnerabilities for that product from GCVE as context
  * network services that listen on every interface (databases, remote desktop, telnet ...)
  * connections from this PC to IP addresses listed in ThreatFox or Botvrij.eu (Experiment 7 feeds)

Collections: threat_lab.pc_scans (one document per scan) and threat_lab.eol_cache (endoflife.date, 24 h TTL).
"""
import datetime as dt
import json
import os
import re
import uuid
from concurrent import futures
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from pymongo import DESCENDING, MongoClient

router = APIRouter(prefix="/api/pc")
EOL_API = os.getenv("EOL_API", "https://endoflife.date/api")
MAX_BODY = 5 * 1024 * 1024
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
WEIGHT = {"critical": 40, "high": 20, "medium": 5, "low": 2}

_client = None


def tdb():
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=4000, tz_aware=True)
        d = _client.threat_lab
        d.pc_scans.create_index([("received_at", DESCENDING)])
        d.eol_cache.create_index("fetched_at", expireAfterSeconds=24 * 3600)
    return _client.threat_lab


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value):
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def days_since(value):
    t = parse_time(value)
    return (utcnow() - t).days if t else None


def vtuple(version):
    return tuple(int(x) for x in re.findall(r"\d+", str(version or ""))[:4])


# ------------------------------------------------------------------ programs checked against endoflife.date
# name pattern -> endoflife.date product, how to read the version, GCVE vendor/product, label
PRODUCTS = [
    (r"^Python (\d+\.\d+\.\d+)", "python", "name", ("python", "python"), "Python"),
    (r"^Node\.js$", "nodejs", "version", ("nodejs", "node.js"), "Node.js"),
    (r"^PostgreSQL \d+$", "postgresql", "version", ("postgresql", "postgresql"), "PostgreSQL"),
    (r"^MySQL Server", "mysql", "version", ("oracle", "mysql"), "MySQL Server"),
    (r"^MongoDB \d", "mongodb", "version", ("mongodb", "mongodb"), "MongoDB Server"),
    (r"^Google Chrome$", "chrome", "version", ("google", "chrome"), "Google Chrome"),
    (r"^Mozilla Firefox", "firefox", "version", ("mozilla", "firefox"), "Mozilla Firefox"),
    (r"^Git$", "git", "version", ("git-scm", "git"), "Git"),
    (r"^PowerShell 7", "powershell", "version", ("microsoft", "powershell"), "PowerShell 7"),
]


def eol_cycles(product, client):
    d = tdb()
    cached = d.eol_cache.find_one({"_id": product})
    if cached:
        return cached["cycles"]
    r = client.get(f"{EOL_API}/{quote(product)}.json")
    r.raise_for_status()
    cycles = r.json()
    d.eol_cache.replace_one({"_id": product}, {"_id": product, "cycles": cycles, "fetched_at": utcnow()}, upsert=True)
    return cycles


def match_cycle(version, cycles):
    best = None
    for c in cycles:
        cyc = str(c.get("cycle"))
        if (version == cyc or version.startswith(cyc + ".")) and (best is None or len(cyc) > len(str(best["cycle"]))):
            best = c
    return best


def is_past(value):
    if value is True:
        return True
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value) < utcnow().date()
        except ValueError:
            return False
    return False


def recent_cves(client, vendor, product):
    from app.cti import GCVE, vulnerability_summary
    r = client.get(f"{GCVE}/vulnerability/search/{quote(vendor)}/{quote(product)}", params={"per_page": 3})
    r.raise_for_status()
    data, out = r.json(), []
    for rows in (data.get("results") or {}).values():
        for row in rows:
            s = vulnerability_summary(row[1] if isinstance(row, list) and len(row) > 1 else row)
            if s and s["id"] not in [x["id"] for x in out]:
                out.append({"id": s["id"], "severity": (s.get("cvss") or {}).get("severity"),
                            "link": f"https://db.gcve.eu/vuln/{quote(s['id'].lower())}"})
    return {"total": data.get("total_count"), "recent": out[:3]}


def check_software(software, client):
    findings, checked = [], []
    for item in software:
        name = (item.get("name") or "").strip()
        for pattern, product, source, gcve, label in PRODUCTS:
            m = re.search(pattern, name)
            if not m:
                continue
            version = m.group(1) if source == "name" else re.sub(r"[-_ ].*$", "", item.get("version") or "")
            if not vtuple(version):
                break
            try:
                cycles = eol_cycles(product, client)
                cycle = match_cycle(version, cycles)
                current = next((c for c in cycles if not is_past(c.get("eol"))), cycles[0] if cycles else {})
                newest = str(current.get("latest") or current.get("cycle") or "")
            except Exception:
                checked.append({"program": name, "version": version, "status": "not checked (endoflife.date unreachable)"})
                break
            if not cycle:
                checked.append({"program": name, "version": version, "status": "release line not listed"})
                break
            latest, eol = cycle.get("latest"), cycle.get("eol")
            slug = re.sub(r"[^A-Z0-9]+", "-", f"{label} {version}".upper()).strip("-")
            source_url = f"https://endoflife.date/{product}"
            if is_past(eol):
                target = f"{label} {newest}" if newest else f"a supported {label} release"
                findings.append(finding(f"PC-SW-{slug}", "high", "Software", f"{label} {version} is past end of life — update to {target}",
                    f"The {cycle['cycle']} release line of {label} stopped receiving security fixes"
                    + (f" on {eol}." if isinstance(eol, str) else ".") + (f" The current release is {target}." if newest else ""),
                    (f"Update to {target}: open Menu → Help → About {label.split()[-1]} and restart the browser." if product in ("chrome", "firefox")
                     else f"Upgrade to {target}, or uninstall {label} if it is no longer needed."),
                    source_url, {"program": name, "version": version, "cycle": cycle["cycle"], "eol": eol, "latest": latest, "upgrade_to": newest},
                    gcve=gcve, label=label))
                checked.append({"program": name, "version": version, "status": "end of life"})
            elif latest and vtuple(version) < vtuple(latest):
                findings.append(finding(f"PC-SW-{slug}", "medium", "Software", f"{label} {version} is behind the latest security release — update to {label} {latest}",
                    f"{label} {latest} is the newest release of the {cycle['cycle']} line; newer releases usually include security fixes."
                    + (f" This line is supported until {eol}." if isinstance(eol, str) else ""),
                    f"Update {label} to {latest}.", source_url,
                    {"program": name, "version": version, "cycle": cycle["cycle"], "eol": eol, "latest": latest}, gcve=gcve, label=label))
                checked.append({"program": name, "version": version, "status": f"update available ({latest})"})
            else:
                checked.append({"program": name, "version": version, "status": "up to date"})
            break
    # Recent vulnerabilities for the flagged products, from GCVE (context: they may or may not affect the installed version).
    flagged = [f for f in findings if f.get("_gcve")]
    with futures.ThreadPoolExecutor(6) as pool:
        jobs = {pool.submit(recent_cves, client, *f["_gcve"]): f for f in flagged}
        for job, f in jobs.items():
            try:
                cves = job.result(timeout=30)
                if cves["recent"]:
                    f["evidence"]["gcve_recent_vulnerabilities"] = cves["recent"]
                    f["evidence"]["gcve_total_vulnerabilities"] = cves["total"]
                    f["summary"] += (" Known vulnerabilities in this product, for example (GCVE): "
                                     + ", ".join(c["id"] for c in cves["recent"]) + "; whether each one affects this exact version depends on the advisory.")
            except Exception:
                pass
    for f in findings:
        f.pop("_gcve", None)
    return findings, checked


def finding(fid, severity, category, title, summary, advice, source, evidence=None, gcve=None, label=None):
    f = {"_id": fid, "severity": severity, "category": category, "title": title, "summary": summary,
         "mitigation": advice, "source": source, "evidence": evidence or {}}
    if gcve:
        f["_gcve"] = gcve
    return f


# ------------------------------------------------------------------ Windows, Defender, firewall, network
def check_windows(system, client):
    out = []
    build = int(system.get("build") or 0)
    name = system.get("os_name") or "Windows"
    if build and build < 22000:
        out.append(finding("PC-OS-WIN10", "high", "Windows", f"{name} no longer receives regular security updates",
            "Windows 10 reached end of support on 14 October 2025; without Extended Security Updates it gets no more security fixes.",
            "Upgrade to Windows 11, or enrol in Extended Security Updates.", "https://endoflife.date/windows", {"build": build}))
    elif build:
        try:
            edition = "e" if re.search(r"Enterprise|Education", name) else "w"
            cycles = [c for c in eol_cycles("windows", client) if str(c.get("cycle", "")).endswith("-" + edition)
                      and str(c.get("latest", "")).endswith(f".{build}")]
            if cycles and is_past(cycles[0].get("eol")):
                out.append(finding("PC-OS-EOL", "high", "Windows", f"Windows release {cycles[0].get('releaseLabel')} is past end of support",
                    f"Support for this Windows release ended on {cycles[0].get('eol')}.", "Install the latest Windows 11 feature update.",
                    "https://endoflife.date/windows", {"build": build, "cycle": cycles[0].get("cycle")}))
        except Exception:
            pass
    newest = max((parse_time(h.get("installed_on")) for h in system.get("hotfixes") or [] if parse_time(h.get("installed_on"))), default=None)
    if newest and (utcnow() - newest).days > 45:
        out.append(finding("PC-OS-UPDATES", "medium", "Windows", f"No Windows update installed for {(utcnow() - newest).days} days",
            f"The newest installed update is from {newest.date()}. Microsoft releases security updates every month.",
            "Open Settings → Windows Update and install the pending updates.", "https://support.microsoft.com/windows/update-windows",
            {"newest_update": newest.isoformat()}))
    return out


DEFENDER_SEVERITY = {1: "Low", 2: "Moderate", 4: "High", 5: "Severe"}


def check_defender(d):
    out = []
    src = "https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows"
    if not d.get("available"):
        return [finding("PC-DEF-UNKNOWN", "low", "Antivirus", "Microsoft Defender status could not be read",
            "Defender may be replaced by another antivirus product, or its status is not available to this account.",
            "Make sure an antivirus product is installed, enabled and up to date.", src)]
    if d.get("antivirus_enabled") is False:
        out.append(finding("PC-DEF-AV", "critical", "Antivirus", "Microsoft Defender antivirus is turned off",
            "Defender reports that its antivirus engine is disabled.", "Turn Defender on (Windows Security → Virus & threat protection), unless another antivirus is active.", src))
    if d.get("real_time_protection") is False:
        out.append(finding("PC-DEF-RTP", "high", "Antivirus", "Real-time protection is off",
            "Files are not scanned when they are opened or downloaded.", "Turn on real-time protection in Windows Security.", src))
    age = days_since(d.get("signatures_updated"))
    if age is not None and age > 7:
        out.append(finding("PC-DEF-SIG", "medium", "Antivirus", f"Antivirus definitions are {age} days old",
            "Defender cannot recognise threats released after its last definition update.", "Run Windows Update or 'Check for updates' in Windows Security.", src))
    scans = [x for x in (days_since(d.get("quick_scan_end")), days_since(d.get("full_scan_end"))) if x is not None]
    if not scans or min(scans) > 14:
        out.append(finding("PC-DEF-SCAN", "low", "Antivirus", "No Defender scan in the last 14 days",
            "Real-time protection still runs, but no quick or full scan has completed recently.", "Run a quick scan in Windows Security.", src))
    if d.get("tamper_protection") is False:
        out.append(finding("PC-DEF-TAMPER", "low", "Antivirus", "Tamper protection is off",
            "Malware could change Defender settings.", "Turn on tamper protection in Windows Security.", src))
    for i, det in enumerate(d.get("detections") or []):
        sev_name = DEFENDER_SEVERITY.get(det.get("severity_id"), "Unknown")
        handled = not det.get("active") and det.get("action_success")
        name = det.get("name") or "Unknown threat"
        severity = "low" if handled else ("critical" if det.get("severity_id", 0) >= 4 else "high")
        kind = "potentially unwanted application" if name.startswith("PUA:") else "threat"
        out.append(finding(f"PC-DEF-THREAT-{i + 1}", severity, "Antivirus",
            f"Defender {'removed' if handled else 'detected'} {name}" + ("" if handled else " (still active)"),
            f"{name} is a {kind} with Defender severity {sev_name}, first detected {(det.get('detected') or '')[:10]}. "
            + ("Defender's action succeeded and it is no longer active." if handled else "Defender reports it as active or not fully removed."),
            "No action needed; check Protection history if it returns." if handled else "Open Windows Security → Protection history and remove or quarantine it, then run a full scan.",
            "https://www.microsoft.com/en-us/wdsi/threats", {k: det.get(k) for k in ("name", "severity_id", "active", "status_id", "action_success", "detected", "resources", "process")}))
    return out


def check_firewall(profiles):
    off = [p.get("profile") for p in profiles or [] if p.get("enabled") is False]
    if not off:
        return []
    return [finding("PC-FW-OFF", "high" if "Public" in off else "medium", "Firewall", f"Windows Firewall is off for: {', '.join(off)}",
        "Without the firewall, services on this PC can be reached by other devices on the network.",
        "Turn the firewall on in Windows Security → Firewall & network protection.",
        "https://support.microsoft.com/windows/turn-microsoft-defender-firewall-on-or-off", {"profiles_off": off})]


RISKY_PORTS = {
    23: ("Telnet", "high"), 21: ("FTP", "medium"), 3389: ("Remote Desktop", "medium"), 5900: ("VNC", "medium"),
    3306: ("MySQL", "db"), 33060: ("MySQL X protocol", "db"), 5432: ("PostgreSQL", "db"), 5433: ("PostgreSQL", "db"),
    1433: ("SQL Server", "db"), 27017: ("MongoDB", "db"), 6379: ("Redis", "db"), 9200: ("Elasticsearch", "db"),
    11434: ("Ollama", "db"), 9042: ("Cassandra", "db"), 7687: ("Neo4j", "db"),
}


def check_network(listening, connections, firewall_off):
    out, groups = [], {}
    for item in listening or []:
        port = item.get("port")
        if item.get("address") in ("0.0.0.0", "::") and port in RISKY_PORTS:
            groups.setdefault(item.get("process") or "unknown", []).append(port)
    for process, ports in sorted(groups.items()):
        services = sorted({RISKY_PORTS[p][0] for p in ports})
        kinds = {RISKY_PORTS[p][1] for p in ports}
        severity = "high" if "high" in kinds else ("medium" if "medium" in kinds or firewall_off else "low")
        slug = re.sub(r"[^A-Z0-9]+", "-", process.upper()).strip("-")
        out.append(finding(f"PC-NET-{slug}", severity, "Network",
            f"{' / '.join(services)} ({process}) listens on all network interfaces (port {', '.join(map(str, sorted(set(ports))))})",
            "The service accepts connections from other devices, not only from this PC"
            + (", and the firewall is off for at least one profile." if firewall_off else "; the Windows Firewall is the only thing restricting it."),
            "If only this PC uses it, bind it to 127.0.0.1 (localhost) in its configuration, or stop the service when not needed; keep strong passwords.",
            "https://attack.mitre.org/techniques/T1133/", {"process": process, "ports": sorted(set(ports))}))

    ips = sorted({c.get("remote_ip") for c in connections or [] if c.get("remote_ip")})
    if ips:
        from app.cti import db as cti_db
        d = cti_db()
        hits = list(d.threatfox_indicators.find({"match_ip": {"$in": ips}}, {"_id": 0, "value": 1, "match_ip": 1, "malware": 1, "threat_type": 1, "reference": 1}).limit(50))
        hits += [{"value": h.get("value"), "match_ip": h.get("match_ip"), "malware": h.get("event_info"), "threat_type": h.get("category"),
                  "reference": h.get("event_url"), "feed": "Botvrij.eu"}
                 for h in d.botvrij_indicators.find({"match_ip": {"$in": ips}}, {"_id": 0}).limit(50)]
        for ip in sorted({h["match_ip"] for h in hits}):
            ioc = [h for h in hits if h["match_ip"] == ip]
            procs = sorted({c.get("process") or "unknown" for c in connections if c.get("remote_ip") == ip})
            out.append(finding(f"PC-NET-IOC-{ip.replace('.', '-').replace(':', '-')}", "critical", "Network",
                f"Connection to {ip}, listed as malicious ({ioc[0].get('malware') or 'threat feed'})",
                f"{', '.join(procs)} is connected to {ip}, which appears in {ioc[0].get('feed', 'ThreatFox')} threat intelligence: {ioc[0].get('threat_type') or ''}.",
                "Disconnect from the network, end the process, run a full Defender scan and check what installed it.",
                ioc[0].get("reference") or "https://threatfox.abuse.ch/", {"ip": ip, "processes": procs, "indicators": ioc[:5]}))
    return out


# ------------------------------------------------------------------ scan pipeline
def analyse(scan):
    with httpx.Client(timeout=httpx.Timeout(20.0, connect=8.0), headers={"User-Agent": "threat-intelligence-lab/1.0"}) as client:
        software_findings, checked = check_software(scan.get("software") or [], client)
        windows = check_windows(scan.get("system") or {}, client)
    firewall = check_firewall(scan.get("firewall"))
    findings = (check_defender(scan.get("defender") or {}) + firewall + windows + software_findings
                + check_network(scan.get("listening"), scan.get("connections"), bool(firewall)))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["_id"]))
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
    # Many "update available" items must not add up to "high risk": medium and low findings are capped.
    score = min(100, WEIGHT["critical"] * counts["critical"] + WEIGHT["high"] * counts["high"]
                + min(30, WEIGHT["medium"] * counts["medium"]) + min(10, WEIGHT["low"] * counts["low"]))
    verdict = ("High risk" if counts["critical"] else "Needs attention" if counts["high"]
               else "Updates recommended" if counts["medium"] else "Low risk" if counts["low"] else "No threats found")
    return findings, checked, score, counts, verdict


@router.post("/scans")
async def upload_scan(request: Request):
    if os.getenv("CTI_PUBLIC") == "1":
        raise HTTPException(403, "PC scans are disabled on a public deployment.")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Scan too large")
    try:
        scan = json.loads(body)
    except ValueError:
        raise HTTPException(422, "Body must be the JSON produced by scripts/scan-pc.ps1")
    if not isinstance(scan, dict) or not isinstance(scan.get("system"), dict):
        raise HTTPException(422, "Body must be the JSON produced by scripts/scan-pc.ps1")
    for key in ("software", "listening", "connections", "firewall"):
        if not isinstance(scan.get(key) or [], list):
            raise HTTPException(422, f"'{key}' must be a list")
    findings, checked, score, counts, verdict = analyse(scan)
    doc = {"_id": str(uuid.uuid4()), "received_at": utcnow(), "scanned_at": parse_time(scan.get("scanned_at")) or utcnow(),
           "scanner": scan.get("scanner"), "system": scan.get("system"), "defender": scan.get("defender") or {},
           "firewall": scan.get("firewall") or [], "software": scan.get("software") or [], "software_checked": checked,
           "listening": scan.get("listening") or [], "connections": scan.get("connections") or [],
           "findings": findings, "counts": counts, "risk_score": score, "verdict": verdict}
    tdb().pc_scans.insert_one(doc)
    return clean(doc, full=False)


def clean(doc, full=True):
    if not doc:
        return None
    out = json.loads(json.dumps(doc, default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v)))
    if not full:
        for key in ("software", "listening", "connections"):
            out[key + "_count"] = len(out.pop(key, []) or [])
    return out


@router.get("/scans/latest")
def latest_scan():
    doc = tdb().pc_scans.find_one(sort=[("received_at", DESCENDING)])
    if not doc:
        raise HTTPException(404, "No PC scan yet. Run scripts/scan-pc.ps1 on Windows.")
    return clean(doc)


@router.get("/scans")
def list_scans(limit: int = 20):
    rows = tdb().pc_scans.find({}, {"received_at": 1, "verdict": 1, "risk_score": 1, "counts": 1, "system.computer": 1}).sort("received_at", DESCENDING).limit(min(limit, 100))
    return [clean(r) for r in rows]


# ------------------------------------------------------------------ Threat Assistant records
PC_INTENT = re.compile(r"\b(my|this)\s+(pc|computer|laptop|machine|system|device|windows)\b|\bon my\b|\binstalled\b|"
                       r"\bdefender\b|\bantivirus\b|\bfirewall\b|\bopen ports?\b|\bpc scan\b|\bscan\b", re.I)


TOPICS = {"Antivirus": r"defender|antivirus|anti-virus|virus|malware|trojan|infect|detect",
          "Firewall": r"firewall", "Network": r"port|network|connect|listen|ip\b|remote",
          "Software": r"update|software|program|app\b|apps|version|outdated|install",
          "Windows": r"\bwindows\b|\bos\b|patch"}


def pc_records(ids=None, limit=6, question=""):
    """Latest scan as Threat Assistant records: a summary record plus the most severe findings."""
    doc = tdb().pc_scans.find_one(sort=[("received_at", DESCENDING)])
    if not doc:
        return None
    d, s = doc.get("defender") or {}, doc.get("system") or {}
    summary = {
        "_id": "PC-SUMMARY", "title": f"Latest PC scan of {s.get('computer') or 'this PC'}", "source": "/#pc",
        "status": doc["verdict"],
        "summary": (f"Scan received {doc['received_at']:%Y-%m-%d %H:%M} UTC. Verdict: {doc['verdict']}, risk score {doc['risk_score']}/100. "
                    f"Findings: {doc['counts']['critical']} critical, {doc['counts']['high']} high, {doc['counts']['medium']} medium, {doc['counts']['low']} low. "
                    f"System: {s.get('os_name')} build {s.get('build')}. "
                    f"Defender antivirus {'on' if d.get('antivirus_enabled') else 'off or unknown'}, real-time protection {'on' if d.get('real_time_protection') else 'off or unknown'}, "
                    f"{len(d.get('detections') or [])} detection(s) on record"
                    + (": " + "; ".join(f"{x.get('name')} ({'removed' if not x.get('active') and x.get('action_success') else 'STILL ACTIVE'}, "
                                       f"detected {(x.get('detected') or '')[:10]})" for x in (d.get('detections') or [])[:5]) if d.get("detections") else "")
                    + ". "
                    + ("Windows Firewall is ON for all profiles (Domain, Private, Public). "
                       if all(p.get("enabled") for p in doc.get("firewall", [])) else
                       f"Windows Firewall is OFF for: {', '.join(p['profile'] for p in doc.get('firewall', []) if not p.get('enabled'))}. ")
                    + f"{len(doc.get('software') or [])} installed programs, {len(doc.get('software_checked') or [])} checked for end of life and updates."),
    }
    findings = doc.get("findings") or []
    if ids:  # follow-up on one finding: give the model its full detail
        picked = [{k: f[k] for k in ("_id", "severity", "category", "title", "summary", "mitigation", "source")} for f in findings if f["_id"] in ids]
        return [summary] + picked if "PC-SUMMARY" in ids else (picked or [summary])
    # A question about one area (e.g. "is Defender on?") gets that area's findings first, then the rest by severity.
    asked = {cat for cat, pattern in TOPICS.items() if re.search(pattern, question or "", re.I)}
    if asked:
        findings = sorted(findings, key=lambda f: f["category"] not in asked)  # stable: keeps severity order inside
    # Overview: short records (title + what to do), so a small model does not mix up the versions of different programs.
    return [summary] + [{"_id": f["_id"], "severity": f["severity"], "title": f["title"],
                         **({"detail": f["summary"]} if f["category"] in asked else {}),
                         "what_to_do": f["mitigation"], "source": f["source"]} for f in findings[:limit]]
