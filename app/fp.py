"""Chapter 18: false-positive review across MongoDB, Cassandra and Neo4j, and the indicator export.

Candidates come from this platform's own imported feeds (Botvrij.eu + ThreatFox in MongoDB) with
reasons: shared or benign infrastructure, one unrated source, or an indicator blamed on 4+ families.
For one value each database gives its own verdict from its own model of the data:
  MongoDB   — document rules (benign/shared infrastructure, private address);
  Cassandra — the indicator's single partition: how far it spreads across feeds and whether any rates it;
  Neo4j     — whether the families it is blamed on fall into different communities (label propagation).
A 2-of-3 vote gives the combined verdict. Moderator decisions are stored in fp_decisions and the
export honours them at once ("reviewed false positive").
"""
import csv
import datetime as dt
import io
import ipaddress
import os
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from app.cti import indicator_key, normalize
from app.platform import audit, clean, lab_access, pdb, port_open, require, start_command, utcnow

router = APIRouter(prefix="/api")
BENIGN = {"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "microsoft.com", "windows.net", "live.com", "office.com",
          "office365.com", "sharepoint.com", "onedrive.com", "1drv.ms", "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
          "cloudfront.net", "cloudflare.com", "workers.dev", "pages.dev", "akamai.net", "akamaized.net", "github.com", "github.io",
          "githubusercontent.com", "gitlab.com", "dropbox.com", "dropboxusercontent.com", "discord.com", "discordapp.com", "telegram.org",
          "t.me", "twitter.com", "x.com", "facebook.com", "youtube.com", "wikipedia.org", "mozilla.org", "adobe.com", "yahoo.com",
          "bing.com", "linkedin.com", "pastebin.com", "mediafire.com", "mega.nz", "bit.ly", "archive.org", "firebaseapp.com",
          "web.app", "azurewebsites.net", "blob.core.windows.net", "herokuapp.com", "vercel.app", "netlify.app", "ngrok.io"}
PUBLIC_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}
REASON_TEXT = {"shared_infrastructure": "Shared or benign infrastructure", "single_unrated_source": "One unrated source",
               "many_families": "Blamed on 4 or more families"}
_cache = {"at": 0, "universe": None}


def tidb():
    return pdb().client["threat_intelligence"]


def registered(host):
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def benign(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_reserved or host in PUBLIC_RESOLVERS
    except ValueError:
        return host in BENIGN or registered(host) in BENIGN or any(host.endswith("." + b) for b in BENIGN)


# --------------------------------------------------------------------------- indicator universe (MongoDB)
def _add(universe, value, kind, feed, family, rated, extra):
    n = normalize(value.split("|")[0] if kind != "url" else value)
    if not n:
        return
    key = indicator_key(n["url"] if n["kind"] == "url" else n["host"])
    item = universe.setdefault(key, {"key": key, "value": n["url"] if n["kind"] == "url" else n["host"], "kind": n["kind"],
                                     "host": n["host"], "feeds": set(), "families": set(), "rated": False, "rows": []})
    item["feeds"].add(feed)
    if family:
        item["families"].add(family.strip()[:120])
    item["rated"] = item["rated"] or bool(rated)
    if len(item["rows"]) < 12:
        item["rows"].append({"feed": feed, "family": family, "rated": bool(rated), **extra})


def universe():
    if _cache["universe"] is not None and time.time() - _cache["at"] < 300:
        return _cache["universe"]
    u = {}
    for a in tidb().botvrij_indicators.find({"$or": [{"match_url": {"$exists": True}}, {"match_host": {"$exists": True}}, {"match_ip": {"$exists": True}}]},
                                            {"value": 1, "type": 1, "event_info": 1, "to_ids": 1, "match_ip": 1}):
        value = a.get("match_ip") if a.get("type", "").startswith("ip") else a["value"]
        _add(u, value or a["value"], "url" if a.get("type") in ("url", "uri", "link-malicious") else "host", "Botvrij.eu",
             a.get("event_info"), a.get("to_ids"), {"type": a.get("type")})
    for t in tidb().threatfox_indicators.find({}, {"value": 1, "ioc_type": 1, "malware": 1, "confidence": 1, "match_ip": 1}):
        value = t.get("match_ip") if t.get("ioc_type") == "ip:port" else t.get("value")
        if value:
            _add(u, value, "url" if t.get("ioc_type") == "url" else "host", "ThreatFox", t.get("malware"),
                 (t.get("confidence") or 0) >= 75, {"type": t.get("ioc_type"), "confidence": t.get("confidence")})
    for item in u.values():
        reasons = []
        if benign(item["host"]):
            reasons.append("shared_infrastructure")
        if len(item["feeds"]) == 1 and not item["rated"] and len(item["families"]) <= 1:
            reasons.append("single_unrated_source")
        if len(item["families"]) >= 4:
            reasons.append("many_families")
        item["reasons"] = reasons
    _cache.update(universe=u, at=time.time())
    return u


def item_or_404(value):
    n = normalize(value)
    if not n:
        raise HTTPException(422, "Not a URL, domain or IP")
    key = indicator_key(n["url"] if n["kind"] == "url" else n["host"])
    item = universe().get(key) or universe().get(indicator_key(n["host"]))
    if not item:
        raise HTTPException(404, "This value is not in the imported feeds")
    return item


def decisions():
    return {d["_id"]: d for d in pdb().fp_decisions.find()}


def public_item(item, decision=None):
    return {"key": item["key"], "value": item["value"], "kind": item["kind"], "feeds": sorted(item["feeds"]),
            "families": sorted(item["families"])[:10], "family_count": len(item["families"]), "rated": item["rated"],
            "reasons": item["reasons"], "decision": (decision or {}).get("decision"), "decided_by": (decision or {}).get("by")}


def mongo_verdict(item):
    fp = "shared_infrastructure" in item["reasons"]
    return {"database": "MongoDB", "verdict": "false_positive" if fp else "keep",
            "rule": "Document rules: host on the shared/benign list or a private/resolver address" if fp else "No document rule matched",
            "raw": {"value": item["value"], "host": item["host"], "registered_domain": registered(item["host"]), "feeds": sorted(item["feeds"]),
                    "families": sorted(item["families"])[:10], "rated": item["rated"], "sample_rows": item["rows"][:5]}}


# --------------------------------------------------------------------------- Cassandra + Neo4j copies
def polyglot_ready():
    return port_open(9042) and port_open(7687)


def sync_polyglot(limit=50000):
    """Copy the candidates into Cassandra (one partition per indicator) and Neo4j (indicator→family graph)."""
    from app.polyglot import cassandra, cypher
    from cassandra.concurrent import execute_concurrent_with_args
    # Candidates, plus every indicator blamed on 2+ families: those are the edges that link families in Neo4j.
    cands = [i for i in universe().values() if i["reasons"] or len(i["families"]) >= 2][:limit]
    s = cassandra()
    s.execute("CREATE KEYSPACE IF NOT EXISTS cti_fp WITH replication = {'class':'SimpleStrategy','replication_factor':1}")
    s.execute("CREATE TABLE IF NOT EXISTS cti_fp.indicator_feeds (key text, feed text, family text, rated boolean, value text,"
              " PRIMARY KEY (key, feed, family))")
    s.execute("TRUNCATE cti_fp.indicator_feeds")
    rows = [(i["key"], r["feed"], (r.get("family") or "unknown")[:120], bool(r["rated"]), i["value"]) for i in cands for r in i["rows"]]
    stmt = s.prepare("INSERT INTO cti_fp.indicator_feeds (key, feed, family, rated, value) VALUES (?,?,?,?,?)")
    execute_concurrent_with_args(s, stmt, rows, concurrency=50)
    cypher("MATCH (n) WHERE n:FpIndicator OR n:FpFamily DETACH DELETE n")
    batch = [{"key": i["key"], "value": i["value"], "families": sorted(i["families"])[:20]} for i in cands]
    for start in range(0, len(batch), 500):
        cypher("UNWIND $rows AS r MERGE (i:FpIndicator {key:r.key}) SET i.value=r.value "
               "WITH i, r UNWIND r.families AS f MERGE (fam:FpFamily {name:f}) MERGE (i)-[:BLAMED_ON]->(fam)", rows=batch[start:start + 500])
    # Communities: label propagation over families linked by shared indicators (Neo4j Community has no GDS Louvain).
    edges = cypher("MATCH (a:FpFamily)<-[:BLAMED_ON]-(:FpIndicator)-[:BLAMED_ON]->(b:FpFamily) WHERE a.name < b.name RETURN a.name AS a, b.name AS b, count(*) AS w")
    neighbours = {}
    for e in edges:
        neighbours.setdefault(e["a"], {})[e["b"]] = e["w"]
        neighbours.setdefault(e["b"], {})[e["a"]] = e["w"]
    families = [r["name"] for r in cypher("MATCH (f:FpFamily) RETURN f.name AS name")]
    label = {f: f for f in families}
    for _ in range(10):
        changed = False
        for f in families:
            votes = {}
            for nb, w in neighbours.get(f, {}).items():
                votes[label[nb]] = votes.get(label[nb], 0) + w
            if votes:
                best = max(sorted(votes), key=lambda k: votes[k])
                if best != label[f]:
                    label[f], changed = best, True
        if not changed:
            break
    ids = {l: i for i, l in enumerate(sorted(set(label.values())))}
    cypher("UNWIND $rows AS r MATCH (f:FpFamily {name:r.name}) SET f.community=r.c", rows=[{"name": f, "c": ids[l]} for f, l in label.items()])
    state = {"_id": "fp_sync", "synced_at": utcnow(), "candidates": len(cands), "cassandra_rows": len(rows), "families": len(families),
             "communities": len(ids), "links": len(edges)}
    pdb().settings.replace_one({"_id": "fp_sync"}, state, upsert=True)
    return state


def cassandra_verdict(item):
    from app.polyglot import cassandra
    rows = list(cassandra().execute("SELECT feed, family, rated, value FROM cti_fp.indicator_feeds WHERE key=%s", (item["key"],)))
    if not rows:
        return {"database": "Cassandra", "verdict": "unknown", "rule": "Not in the synced partition table (not a candidate)", "raw": []}
    feeds = {r.feed for r in rows}
    rated = any(r.rated for r in rows)
    fp = len(feeds) == 1 and not rated
    return {"database": "Cassandra", "verdict": "false_positive" if fp else "keep",
            "rule": f"One partition: {len(feeds)} feed(s), {'rated' if rated else 'unrated'}" + (" → weak, single unrated source" if fp else ""),
            "raw": [{"feed": r.feed, "family": r.family, "rated": r.rated} for r in rows]}


def neo4j_verdict(item):
    from app.polyglot import cypher
    rows = cypher("MATCH (i:FpIndicator {key:$key})-[:BLAMED_ON]->(f:FpFamily) RETURN f.name AS family, f.community AS community", key=item["key"])
    if not rows:
        return {"database": "Neo4j", "verdict": "unknown", "rule": "Not in the synced graph (not a candidate)", "raw": []}
    if len(rows) < 2:
        return {"database": "Neo4j", "verdict": "keep", "rule": "Blamed on one family: no conflicting attribution", "raw": rows}
    # Are the families this indicator is blamed on tied together by any OTHER indicator?
    pairs = cypher("MATCH (i:FpIndicator {key:$key})-[:BLAMED_ON]->(a:FpFamily), (i)-[:BLAMED_ON]->(b:FpFamily) WHERE a.name < b.name "
                   "OPTIONAL MATCH (a)<-[:BLAMED_ON]-(o:FpIndicator)-[:BLAMED_ON]->(b) WHERE o.key <> $key "
                   "RETURN a.name AS a, b.name AS b, count(DISTINCT o) AS other_links", key=item["key"])
    unrelated = [p for p in pairs if p["other_links"] == 0]
    fp = bool(unrelated)
    rule = (f"Blamed on {len(rows)} families; {len(unrelated)} of {len(pairs)} family pair(s) share no other indicator"
            + (" → unrelated campaigns reuse it, likely shared infrastructure" if fp else " → the families are genuinely linked"))
    return {"database": "Neo4j", "verdict": "false_positive" if fp else "keep", "rule": rule, "raw": {"families": rows, "pairs": pairs}}


def all_verdicts(item):
    verdicts = [mongo_verdict(item)]
    if os.getenv("CTI_PUBLIC") == "1":
        verdicts += [{"database": db_, "verdict": "unavailable", "rule": "Lab databases are disabled on this public deployment (CTI_PUBLIC=1)", "raw": []}
                     for db_ in ("Cassandra", "Neo4j")]
    elif polyglot_ready():
        try:
            if not pdb().settings.find_one({"_id": "fp_sync"}):
                sync_polyglot()
            verdicts += [cassandra_verdict(item), neo4j_verdict(item)]
        except Exception as exc:
            from app.polyglot import reset_connections
            reset_connections()
            verdicts += [{"database": db_, "verdict": "unavailable", "rule": f"{type(exc).__name__}: databases still starting", "raw": []} for db_ in ("Cassandra", "Neo4j")]
    else:
        verdicts += [{"database": db_, "verdict": "unavailable", "rule": f"Polyglot topology stopped — start it with {start_command('polyglot')}", "raw": []}
                     for db_ in ("Cassandra", "Neo4j")]
    fp_votes = sum(v["verdict"] == "false_positive" for v in verdicts)
    keep_votes = sum(v["verdict"] == "keep" for v in verdicts)
    vote = "false_positive" if fp_votes >= 2 else "keep" if keep_votes >= 2 else "undecided"
    return verdicts, {"result": vote, "false_positive_votes": fp_votes, "keep_votes": keep_votes, "rule": "2 of 3 databases must agree"}


# --------------------------------------------------------------------------- moderation API
@router.get("/moderation/fp")
def fp_candidates(reason: str | None = Query(None, pattern="^(shared_infrastructure|single_unrated_source|many_families)$"),
                  kind: str | None = Query(None, pattern="^(url|domain|ip|host)$"), q: str | None = Query(None, max_length=200),
                  limit: int = Query(50, ge=1, le=200), skip: int = Query(0, ge=0), open_only: bool = True,
                  user=Depends(require("moderator", "admin"))):
    dec = decisions()
    rows = []
    for item in universe().values():
        if not item["reasons"] or (reason and reason not in item["reasons"]):
            continue
        if kind and item["kind"] != kind and not (kind == "host" and item["kind"] in ("domain", "ip")):
            continue
        if q and q.lower() not in item["value"].lower() and not any(q.lower() in f.lower() for f in item["families"]):
            continue
        if open_only and item["key"] in dec:
            continue
        rows.append(item)
    rows.sort(key=lambda i: (-len(i["reasons"]), -len(i["families"]), i["value"]))
    counts = {r: sum(r in i["reasons"] for i in universe().values()) for r in REASON_TEXT}
    return clean({"total": len(rows), "items": [public_item(i, dec.get(i["key"])) for i in rows[skip:skip + limit]],
                  "reason_counts": counts, "reasons": REASON_TEXT, "decided": len(dec)})


@router.get("/moderation/fp/value")
def fp_value(value: str = Query(min_length=3, max_length=2048), user=Depends(require("moderator", "admin"))):
    item = item_or_404(value)
    verdicts, vote = all_verdicts(item)
    pdb().fp_verdicts.replace_one({"_id": item["key"]}, {"_id": item["key"], "ts": utcnow(), "verdicts": {v["database"]: v["verdict"] for v in verdicts},
                                                         "vote": vote["result"]}, upsert=True)
    return clean({**public_item(item, decisions().get(item["key"])), "verdicts": verdicts, "vote": vote,
                  "sync": pdb().settings.find_one({"_id": "fp_sync"}, {"_id": 0})})


class Decision(BaseModel):
    value: str = Field(min_length=3, max_length=2048)
    kind: str | None = Field(default=None, max_length=20)
    decision: str = Field(pattern="^(false_positive|true_positive|clear)$")
    note: str | None = Field(default=None, max_length=500)


@router.post("/moderation/fp/decision")
def fp_decision(body: Decision, user=Depends(require("moderator", "admin"))):
    item = item_or_404(body.value)
    if body.decision == "clear":
        pdb().fp_decisions.delete_one({"_id": item["key"]})
    else:
        pdb().fp_decisions.replace_one({"_id": item["key"]}, {"_id": item["key"], "value": item["value"], "kind": item["kind"], "decision": body.decision,
                                                              "note": body.note, "by": user["_id"], "at": utcnow(), "reasons": item["reasons"]}, upsert=True)
    audit("fp.decision", user["_id"], value=item["value"], decision=body.decision)
    return {"key": item["key"], "value": item["value"], "decision": None if body.decision == "clear" else body.decision}


@router.post("/moderation/fp/sync", dependencies=[Depends(lab_access)])
def fp_sync(user=Depends(require("moderator", "admin"))):
    if not polyglot_ready():
        raise HTTPException(503, {"message": "The polyglot topology is not running.", "start_command": start_command("polyglot")})
    _cache["universe"] = None
    state = sync_polyglot()
    audit("fp.sync", user["_id"], candidates=state["candidates"])
    return clean(state)


# --------------------------------------------------------------------------- export (honours decisions)
def export_rows():
    dec = decisions()
    kept, excluded = [], []
    for item in sorted(universe().values(), key=lambda i: i["value"]):
        d = dec.get(item["key"])
        if d and d["decision"] == "false_positive":
            excluded.append({"value": item["value"], "kind": item["kind"], "reason": "reviewed false positive", "by": d["by"], "at": d["at"]})
            continue
        kept.append({"value": item["value"], "kind": item["kind"], "feeds": "+".join(sorted(item["feeds"])), "families": len(item["families"]),
                     "status": "reviewed true positive" if d else ("candidate: " + ", ".join(item["reasons"]) if item["reasons"] else "active")})
    return kept, excluded


@router.get("/cti/export")
def export_json():
    kept, excluded = export_rows()
    return clean({"generated_at": utcnow(), "indicators": len(kept), "excluded": excluded, "sample": kept[:50],
                  "csv": "/api/cti/export.csv"})


@router.get("/cti/export.csv")
def export_csv():
    kept, excluded = export_rows()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["value", "kind", "feeds", "families", "status"])
    w.writeheader()
    w.writerows(kept)
    buf.write(f"# {len(excluded)} indicator(s) excluded as reviewed false positives\n")
    return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=indicators.csv"})


# --------------------------------------------------------------------------- sources, scoring and report
def scoring():
    dec = decisions()
    labelled = [(k, d["decision"] == "false_positive") for k, d in dec.items() if d["decision"] in ("false_positive", "true_positive")]
    cache = {v["_id"]: v for v in pdb().fp_verdicts.find({"_id": {"$in": [k for k, _ in labelled]}})}
    table = []
    for database in ("MongoDB", "Cassandra", "Neo4j", "Vote (2 of 3)"):
        tp = fp = fn = tn = scored = 0
        for key, is_fp in labelled:
            v = cache.get(key)
            if not v:
                continue
            verdict = v["vote"] if database.startswith("Vote") else v["verdicts"].get(database)
            if verdict not in ("false_positive", "keep"):
                continue
            scored += 1
            said_fp = verdict == "false_positive"
            tp += said_fp and is_fp
            fp += said_fp and not is_fp
            fn += (not said_fp) and is_fp
            tn += (not said_fp) and not is_fp
        table.append({"database": database, "scored": scored, "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                      "recall": round(tp / (tp + fn), 3) if tp + fn else None, "real_threats_wrongly_dropped": fp})
    return {"labelled": len(labelled), "table": table,
            "note": "Known answers are the moderators' decisions; a database is scored on values whose verdicts were looked up."}


@router.get("/ops/sources")
def sources(user=Depends(require("admin"))):
    u, dec = universe(), decisions()
    feeds = {}
    for item in u.values():
        for f in item["feeds"]:
            s = feeds.setdefault(f, {"feed": f, "indicators": 0, "candidates": 0, "confirmed_fp": 0})
            s["indicators"] += 1
            s["candidates"] += bool(item["reasons"])
            s["confirmed_fp"] += dec.get(item["key"], {}).get("decision") == "false_positive"
    for s in feeds.values():
        s["candidate_rate"] = round(s["candidates"] / s["indicators"], 4) if s["indicators"] else 0
        s["fp_rate"] = round(s["confirmed_fp"] / s["indicators"], 5) if s["indicators"] else 0
    # Family pairs blamed for the same indicator. One shared indicator is a weak tie (SUSPICIOUS: possibly shared
    # infrastructure misattributed to both); two or more shared indicators suggest a real link (LINKED).
    pairs = {}
    for item in u.values():
        if len(item["families"]) >= 2:
            fams = sorted(item["families"])[:6]
            for i, a in enumerate(fams):
                for b in fams[i + 1:]:
                    pairs.setdefault((a, b), []).append(item["value"])
    suspicious = [{"a": a, "b": b, "shared_candidates": len(vals), "label": "LINKED" if len(vals) >= 2 else "SUSPICIOUS", "example": vals[0]}
                  for (a, b), vals in sorted(pairs.items(), key=lambda x: (len(x[1]) >= 2, x[0]))][:40]
    return clean({"feeds": sorted(feeds.values(), key=lambda s: s["feed"]), "suspicious_pairs": suspicious, "scoring": scoring(),
                  "sync": pdb().settings.find_one({"_id": "fp_sync"}, {"_id": 0})})


@router.get("/ops/report", response_class=HTMLResponse)
def report(user=Depends(require("admin"))):
    s = sources(user)
    esc = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    feed_rows = "".join(f"<tr><td>{esc(f['feed'])}</td><td>{f['indicators']:,}</td><td>{f['candidates']:,}</td><td>{f['candidate_rate']:.2%}</td>"
                        f"<td>{f['confirmed_fp']}</td><td>{f['fp_rate']:.3%}</td></tr>" for f in s["feeds"])
    score_rows = "".join(f"<tr><td>{esc(r['database'])}</td><td>{r['scored']}</td><td>{r['precision'] if r['precision'] is not None else '—'}</td>"
                         f"<td>{r['recall'] if r['recall'] is not None else '—'}</td><td>{r['real_threats_wrongly_dropped']}</td></tr>" for r in s["scoring"]["table"])
    pair_rows = "".join(f"<tr><td>{esc(p['a'])}</td><td>{esc(p['b'])}</td><td>{p['shared_candidates']}</td></tr>" for p in s["suspicious_pairs"][:15])
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Comparative report</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 16px;color:#111}}table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}
th,td{{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left}}th{{color:#555;font-weight:500}}h1{{font-size:22px}}h2{{font-size:16px;margin-top:28px}}
.muted{{color:#666}}@media print{{.noprint{{display:none}}}}</style></head><body>
<p class="noprint"><button onclick="print()">Print / Save as PDF</button></p>
<h1>Comparative threat-intelligence report</h1><p class="muted">Generated {utcnow():%Y-%m-%d %H:%M} UTC from the platform's MongoDB, Cassandra and Neo4j copies.</p>
<h2>False-positive rate per feed</h2><table><tr><th>Feed</th><th>Indicators</th><th>Candidates</th><th>Candidate rate</th><th>Confirmed FP</th><th>FP rate</th></tr>{feed_rows}</table>
<h2>FP test: each database against moderator decisions ({s['scoring']['labelled']} labelled)</h2>
<table><tr><th>Database</th><th>Scored</th><th>Precision</th><th>Recall</th><th>Real threats wrongly dropped</th></tr>{score_rows}</table>
<h2>Family pairs sharing indicators (1 = SUSPICIOUS, 2+ = LINKED)</h2><table><tr><th>Family A</th><th>Family B</th><th>Shared indicators</th></tr>{pair_rows or '<tr><td colspan=3>None</td></tr>'}</table>
<h2>Method</h2><p>MongoDB applies document rules; Cassandra reads one partition per indicator; Neo4j checks whether the indicator's families fall into
different label-propagation communities. A 2-of-3 vote gives the combined verdict. Candidates are leads for review, not proof.</p></body></html>"""
    audit("ops.report", user["_id"])
    return HTMLResponse(html)


@router.get("/labs/lab18", dependencies=[Depends(lab_access)])
def lab18(user=Depends(require("moderator", "admin"))):
    out = {"running": polyglot_ready(), "start_command": start_command("polyglot"), "neo4j_browser": "http://localhost:7474"}
    if polyglot_ready():
        try:
            from app.polyglot import cassandra, cypher
            out["neo4j"] = cypher("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC")
            out["neo4j_links"] = cypher("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n")
            out["communities"] = cypher("MATCH (f:FpFamily) WHERE f.community IS NOT NULL RETURN f.community AS community, count(*) AS families, "
                                        "collect(f.name)[0..6] AS sample ORDER BY families DESC LIMIT 12")
            out["cassandra_rows"] = cassandra().execute("SELECT count(*) FROM cti_fp.indicator_feeds").one()[0]
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: databases still starting"
    out["mongodb"] = {"botvrij_indicators": tidb().botvrij_indicators.estimated_document_count(),
                      "threatfox_indicators": tidb().threatfox_indicators.estimated_document_count(),
                      "fp_decisions": pdb().fp_decisions.estimated_document_count()}
    out["scoring"] = scoring()
    return clean(out)
