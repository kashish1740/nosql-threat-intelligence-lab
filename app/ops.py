"""Chapters 13 and 14: deployment metrics, failover, monitoring, alerts, backups and verified restores.

A background sampler reads both replica sets every SAMPLE_SECONDS (the secure set needs the TLS CA
and admin password mounted from .secrets) and stores one document per member in a MongoDB
time-series collection. Prometheus/Grafana are replaced by this sampler and the dashboard charts.
"""
import datetime as dt
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from pymongo.errors import CollectionInvalid, PyMongoError

from app.platform import (LAB_HOST, TOPOLOGIES, audit, clean, lab_access, lab_client, pdb, require, require_lab,
                          start_command, stop_command, topology_up, utcnow)

SAMPLE_SECONDS = int(os.getenv("OPS_SAMPLE_SECONDS", "10"))
HIT_RATIO_MIN = 0.80
LAG_MAX_SECONDS = 10
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/work/backups")) / "ch14"
BACKUP_RETENTION = dt.timedelta(days=7)
SAMPLED = {"replica": False, "secure": True}  # topology -> needs TLS + auth

router = APIRouter(prefix="/api", dependencies=[Depends(lab_access)])
_clients, _previous, _primary = {}, {}, {}


def ensure_collections():
    d = pdb()
    try:
        d.create_collection("metrics", timeseries={"timeField": "ts", "metaField": "meta", "granularity": "seconds"},
                            expireAfterSeconds=2 * 24 * 3600)
    except CollectionInvalid:
        pass
    d.elections.create_index([("topology", 1), ("ts", -1)])
    d.alerts.create_index([("status", 1), ("last_seen", -1)])
    d.backups.create_index("ts")


def _member_client(topology, port):
    key = (topology, port)
    if key not in _clients:
        _clients[key] = lab_client(port, tls=SAMPLED[topology], serverSelectionTimeoutMS=1500, connectTimeoutMS=1500)
    return _clients[key]


def sample_topology(topology):
    """One reading of every reachable member; returns the per-member documents written."""
    now = utcnow()
    ports = TOPOLOGIES[topology]["ports"]
    status, members_by_name, docs, last_write = None, {}, [], {}
    for port in ports:
        try:
            c = _member_client(topology, port)
            hello = c.admin.command("hello")
            me = hello.get("me")
            members_by_name[me] = port
            # Each member's own last applied write; the primary's view of secondaries (heartbeats) lags by seconds.
            if (hello.get("lastWrite") or {}).get("lastWriteDate"):
                last_write[me] = hello["lastWrite"]["lastWriteDate"]
            if status is None:
                status = c.admin.command("replSetGetStatus")
        except PyMongoError:
            continue
    if not status:
        return []
    primary = next((m for m in status["members"] if m.get("stateStr") == "PRIMARY"), None)
    primary_write = last_write.get(primary["name"]) if primary else None
    valid = lambda d: d is not None and d.year >= 2020  # an unknown optime is reported as 1970
    for m in status["members"]:
        port = members_by_name.get(m["name"])
        if valid(primary_write) and valid(last_write.get(m["name"])):
            lag = max(0.0, (primary_write - last_write[m["name"]]).total_seconds())
        elif primary and valid(primary.get("optimeDate")) and valid(m.get("optimeDate")):
            # Member unreachable from the app: use the primary's last known position for it (grows during a partition).
            lag = max(0.0, (primary["optimeDate"] - m["optimeDate"]).total_seconds())
        else:
            lag = None
        doc = {"ts": now, "meta": {"topology": topology, "member": m["name"]}, "state": m.get("stateStr"),
               "health": m.get("health"), "ping_ms": m.get("pingMs", 0 if m.get("self") else None), "lag_s": lag}
        if port:
            try:
                ss = _member_client(topology, port).admin.command("serverStatus")
                ops = sum(ss.get("opcounters", {}).values())
                cache = ss.get("wiredTiger", {}).get("cache", {})
                requested, read = cache.get("pages requested from the cache", 0), cache.get("pages read into cache", 0)
                prev = _previous.get((topology, m["name"]))
                if prev:
                    seconds = max(0.001, (now - prev["ts"]).total_seconds())
                    doc["ops_per_s"] = round(max(0, ops - prev["ops"]) / seconds, 2)
                    d_req, d_read = requested - prev["requested"], read - prev["read"]
                    doc["hit_ratio"] = round(max(0.0, 1 - d_read / d_req), 4) if d_req >= 50 else None
                _previous[(topology, m["name"])] = {"ts": now, "ops": ops, "requested": requested, "read": read}
                doc["connections"] = ss.get("connections", {}).get("current")
            except PyMongoError:
                pass
        docs.append(doc)
    if docs:
        pdb().metrics.insert_many([dict(d) for d in docs])
    new_primary = primary["name"] if primary else None
    old = _primary.get(topology)
    if old is not None and new_primary and old != new_primary:
        pdb().elections.insert_one({"topology": topology, "ts": now, "old_primary": old, "new_primary": new_primary, "source": "observed"})
    if new_primary:
        _primary[topology] = new_primary
    check_alerts(topology, docs)
    return docs


def check_alerts(topology, docs):
    d = pdb()
    for doc in docs:
        member = doc["meta"]["member"]
        for kind, bad, value, message in (
                ("cache", doc.get("hit_ratio") is not None and doc["hit_ratio"] < HIT_RATIO_MIN, doc.get("hit_ratio"),
                 f"Cache hit ratio below {int(HIT_RATIO_MIN * 100)} %"),
                ("lag", (doc.get("lag_s") or 0) > LAG_MAX_SECONDS, doc.get("lag_s"), f"Replication lag above {LAG_MAX_SECONDS} s")):
            key = f"{topology}:{member}:{kind}"
            if bad:
                d.alerts.update_one({"_id": key}, {"$set": {"status": "open", "last_seen": doc["ts"], "value": value, "level": "WARNING",
                                                            "message": message, "topology": topology, "member": member, "kind": kind},
                                                   "$setOnInsert": {"first_seen": doc["ts"]}, "$unset": {"resolved_at": ""}}, upsert=True)
            else:
                d.alerts.update_one({"_id": key, "status": "open"}, {"$set": {"status": "resolved", "resolved_at": doc["ts"]}})


def sampler_loop():
    ensure_collections()
    while True:
        for topology in SAMPLED:
            try:
                if topology_up(topology):
                    sample_topology(topology)
                else:
                    _primary.pop(topology, None)
            except Exception:
                pass
        time.sleep(SAMPLE_SECONDS)


def start_sampler():
    threading.Thread(target=sampler_loop, daemon=True, name="ops-sampler").start()


def series(topology, minutes):
    since = utcnow() - dt.timedelta(minutes=minutes)
    rows = list(pdb().metrics.find({"meta.topology": topology, "ts": {"$gte": since}}, {"_id": 0}).sort("ts", 1).limit(20000))
    by_member = {}
    for r in rows:
        by_member.setdefault(r["meta"]["member"], []).append({k: v for k, v in r.items() if k != "meta"})
    return by_member


def current_members(topology):
    latest = {}
    for r in pdb().metrics.find({"meta.topology": topology, "ts": {"$gte": utcnow() - dt.timedelta(seconds=SAMPLE_SECONDS * 4)}}).sort("ts", -1):
        latest.setdefault(r["meta"]["member"], {k: v for k, v in r.items() if k not in ("_id", "meta")} | {"name": r["meta"]["member"]})
    return sorted(latest.values(), key=lambda m: m["name"])


def lab_state(topology):
    return {"topology": topology, "label": TOPOLOGIES[topology]["label"], "running": topology_up(topology),
            "start_command": start_command(topology), "stop_command": stop_command(topology),
            "compass": {"replica": "mongodb://localhost:27031/?directConnection=true",
                        "secure": "mongodb://admin:<password>@localhost:27036/?tls=true&authSource=admin&directConnection=true"}.get(topology)}


# --------------------------------------------------------------------------- Chapter 13
@router.get("/ops/metrics/deployment")
def deployment_metrics(minutes: int = Query(30, ge=5, le=720), topology: str = Query("secure", pattern="^(secure|replica)$"),
                       user=Depends(require("admin"))):
    since = utcnow() - dt.timedelta(minutes=minutes)
    return clean({**lab_state(topology), "minutes": minutes, "members": current_members(topology), "series": series(topology, minutes),
                  "elections": list(pdb().elections.find({"topology": topology, "ts": {"$gte": since}}, {"_id": 0}).sort("ts", 1)),
                  "kubernetes": {"state": "not_configured", "command": "./scripts/kubernetes.sh",
                                 "note": "Needs a local Kubernetes cluster (Docker Desktop → Kubernetes). The script creates a 3-pod StatefulSet."},
                  "atlas": {"state": "needs_key", "note": "Needs an Atlas organisation API key with the Organization Project Creator role. Not configured."}})


@router.post("/ops/lab13/failover")
def failover(topology: str = Query("secure", pattern="^(secure|replica)$"), user=Depends(require("admin"))):
    require_lab(topology)
    started = time.monotonic()
    ports = TOPOLOGIES[topology]["ports"]
    old = None
    for port in ports:
        try:
            c = _member_client(topology, port)
            hello = c.admin.command("hello")
            if hello.get("isWritablePrimary"):
                old = hello.get("me")
                try:
                    c.admin.command("replSetStepDown", 30, secondaryCatchUpPeriodSecs=10)
                except PyMongoError:
                    pass  # the primary closes connections while stepping down
                break
        except PyMongoError:
            continue
    if not old:
        audit("ops.failover", user["_id"], outcome="no_primary", topology=topology)
        raise HTTPException(409, "No primary found to step down; the set may be electing already.")
    new = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not new:
        for port in ports:
            try:
                hello = _member_client(topology, port).admin.command("hello")
                if hello.get("primary") and hello["primary"] != old:
                    new = hello["primary"]
                    break
            except PyMongoError:
                pass
        time.sleep(0.5)
    seconds = round(time.monotonic() - started, 2)
    pdb().elections.insert_one({"topology": topology, "ts": utcnow(), "old_primary": old, "new_primary": new, "source": "failover",
                                "actor": user["_id"], "seconds": seconds})
    if new:
        _primary[topology] = new
    audit("ops.failover", user["_id"], outcome="ok" if new else "timeout", topology=topology, old=old, new=new, seconds=seconds)
    return {"topology": topology, "old_primary": old, "new_primary": new, "seconds": seconds,
            "message": "New primary elected" if new else "No new primary within 30 s"}


@router.get("/ops/overview")
def overview(user=Depends(require("admin"))):
    return clean({"topologies": [lab_state(t) for t in ("replica", "secure")] +
                  [{"topology": t, "label": TOPOLOGIES[t]["label"], "running": topology_up(t), "start_command": start_command(t)}
                   for t in ("basic", "shards", "auth", "polyglot")],
                  "lab13": {"members": current_members("secure"), "kubernetes": "not_configured", "atlas": "needs_key"}})


# --------------------------------------------------------------------------- Chapter 14
def latest_backups(limit=20):
    return list(pdb().backups.find({}, {"_id": 0}).sort("ts", -1).limit(limit))


@router.get("/ops/metrics/monitoring")
def monitoring(minutes: int = Query(60, ge=5, le=720), user=Depends(require("admin"))):
    alerts = list(pdb().alerts.find({"status": "open"}, {"_id": 1, "message": 1, "member": 1, "value": 1, "acknowledged_by": 1}))
    backups = latest_backups()
    newest = backups[0] if backups else None
    return clean({**lab_state("replica"), "minutes": minutes, "members": current_members("replica"), "series": series("replica", minutes),
                  "thresholds": {"hit_ratio": HIT_RATIO_MIN, "lag_s": LAG_MAX_SECONDS}, "open_alerts": alerts,
                  "backups": backups, "newest_backup": newest,
                  "last_rto_s": next((b["verify"]["rto_s"] for b in backups if b.get("verify")), None)})


def _primary_port(topology):
    for port in TOPOLOGIES[topology]["ports"]:
        try:
            if _member_client(topology, port).admin.command("hello").get("isWritablePrimary"):
                return port
        except PyMongoError:
            continue
    raise HTTPException(409, "No primary is available right now; try again in a few seconds.")


def _uri(port):
    return f"mongodb://{LAB_HOST}:{port}/?directConnection=true"


@router.post("/ops/lab14/backup")
def backup_now(user=Depends(require("admin"))):
    require_lab("replica")
    port = _primary_port("replica")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    now = utcnow()
    archive = BACKUP_DIR / f"app-{now.strftime('%Y%m%dT%H%M%SZ')}.archive.gz"
    started = time.monotonic()
    proc = subprocess.run(["mongodump", "--uri", _uri(port), "--oplog", "--gzip", f"--archive={archive}"], capture_output=True, text=True, timeout=600)
    seconds = round(time.monotonic() - started, 2)
    if proc.returncode != 0:
        audit("ops.backup", user["_id"], outcome="failed")
        raise HTTPException(500, "mongodump failed: " + proc.stderr.strip()[-400:])
    removed = []
    for old in BACKUP_DIR.glob("app-*.archive.gz"):
        if dt.datetime.fromtimestamp(old.stat().st_mtime, dt.timezone.utc) < now - BACKUP_RETENTION:
            old.unlink()
            removed.append(old.name)
    pdb().backups.delete_many({"file": {"$in": removed}})
    doc = {"file": archive.name, "ts": now, "bytes": archive.stat().st_size, "seconds": seconds, "oplog": True, "by": user["_id"],
           "path": f"backups/ch14/{archive.name}"}
    pdb().backups.insert_one(dict(doc))
    audit("ops.backup", user["_id"], file=archive.name, bytes=doc["bytes"], seconds=seconds, removed=len(removed))
    return clean({**doc, "retention_removed": removed})


def _doc_hashes(collection):
    return {str(d["_id"]): hashlib.sha256(json.dumps(d, default=str, sort_keys=True).encode()).hexdigest() for d in collection.find()}


@router.post("/ops/lab14/verify")
def verify_restore(user=Depends(require("admin"))):
    require_lab("replica")
    newest = pdb().backups.find_one(sort=[("ts", -1)])
    if not newest:
        raise HTTPException(409, "No backup yet. Press Back up now first.")
    archive = BACKUP_DIR / newest["file"]
    if not archive.exists():
        raise HTTPException(409, f"Backup file {newest['file']} is missing.")
    port = _primary_port("replica")
    client = _member_client("replica", port)
    source_db, target_db = "college_ch14", "college_ch14_verify"
    client.drop_database(target_db)
    started = time.monotonic()
    proc = subprocess.run(["mongorestore", "--uri", _uri(port), "--gzip", f"--archive={archive}", f"--nsInclude={source_db}.*",
                           f"--nsFrom={source_db}.*", f"--nsTo={target_db}.*", "--drop"], capture_output=True, text=True, timeout=900)
    rto = round(time.monotonic() - started, 2)
    if proc.returncode != 0:
        audit("ops.verify", user["_id"], outcome="failed")
        raise HTTPException(500, "mongorestore failed: " + proc.stderr.strip()[-400:])
    collections = []
    for name in sorted(client[source_db].list_collection_names()):
        src, dst = _doc_hashes(client[source_db][name]), _doc_hashes(client[target_db][name])
        differing = [k for k in src if k in dst and src[k] != dst[k]]
        collections.append({"collection": name, "source_count": len(src), "restored_count": len(dst),
                            "missing": len(set(src) - set(dst)), "extra": len(set(dst) - set(src)), "differing": len(differing)})
    client.drop_database(target_db)
    passed = bool(collections) and all(c["missing"] == 0 and c["extra"] == 0 and c["differing"] == 0 for c in collections)
    result = {"passed": passed, "rto_s": rto, "rpo_s": round((utcnow() - newest["ts"]).total_seconds(), 1), "collections": collections,
              "backup": newest["file"], "verified_at": utcnow(), "note": "Differences mean the data changed after the backup was taken (that gap is the RPO)."}
    pdb().backups.update_one({"file": newest["file"]}, {"$set": {"verify": result}})
    audit("ops.verify", user["_id"], outcome="passed" if passed else "differences", backup=newest["file"], rto_s=rto)
    return clean(result)


class AlertAck(BaseModel):
    key: str = Field(min_length=3, max_length=200)


@router.get("/moderation/alerts")
def alerts(user=Depends(require("moderator", "admin"))):
    """Open WARNINGs plus those that resolved in the last 24 h but nobody has acknowledged yet."""
    since = utcnow() - dt.timedelta(hours=24)
    return clean(list(pdb().alerts.find({"$or": [{"status": "open"}, {"resolved_at": {"$gte": since}, "acknowledged_by": {"$exists": False}}]})
                      .sort("last_seen", -1).limit(200)))


@router.post("/moderation/alerts/ack")
def ack_alert(body: AlertAck, user=Depends(require("moderator", "admin"))):
    res = pdb().alerts.update_one({"_id": body.key}, {"$set": {"acknowledged_by": user["_id"], "acknowledged_at": utcnow()}})
    if not res.matched_count:
        raise HTTPException(404, "Unknown alert")
    audit("alert.ack", user["_id"], key=body.key)
    return {"acknowledged": body.key}
