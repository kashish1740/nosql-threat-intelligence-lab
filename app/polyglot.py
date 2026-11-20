"""Chapter 16: the audit log in Cassandra and fraud review across MongoDB, Cassandra and Neo4j.

Audit delivery is exactly-once: events wait in the MongoDB audit_outbox while the polyglot topology
is down; the flusher writes each one to Cassandra with its event id in the primary key (so a retry
overwrites the same row instead of duplicating it) and deletes it from the outbox only after
Cassandra has accepted all three writes.
"""
import datetime as dt
import socket
import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query

from app.platform import (LAB_HOST, audit, clean, lab_access, lab_client, pdb, port_open, require, require_lab,
                          start_command, stop_command, utcnow)
from labs.ch16.service import CircuitOpen, FraudQueryService

CASSANDRA_PORT, NEO4J_PORT, MONGO_PORT = 9042, 7687, 27039
router = APIRouter(prefix="/api", dependencies=[Depends(lab_access)])
_lock = threading.Lock()
_state = {"cassandra": None, "cluster": None, "graph": None, "service": None, "delivered": 0, "last_error": None}


# --------------------------------------------------------------------------- connections
def cassandra():
    if _state["cassandra"] is not None:
        return _state["cassandra"]
    from cassandra.cluster import Cluster
    from cassandra.policies import WhiteListRoundRobinPolicy
    address = socket.gethostbyname(LAB_HOST)
    cluster = Cluster([address], port=CASSANDRA_PORT, connect_timeout=5, protocol_version=5,
                      load_balancing_policy=WhiteListRoundRobinPolicy([address]))
    session = cluster.connect()
    session.default_timeout = 15
    session.execute("CREATE KEYSPACE IF NOT EXISTS cti_audit WITH replication = {'class':'SimpleStrategy','replication_factor':1}")
    for ddl in (
            "CREATE TABLE IF NOT EXISTS cti_audit.events_by_day (day text, ts timestamp, id uuid, actor text, action text, outcome text,"
            " details map<text,text>, PRIMARY KEY (day, ts, id)) WITH CLUSTERING ORDER BY (ts DESC, id ASC)",
            "CREATE TABLE IF NOT EXISTS cti_audit.events_by_actor (actor text, ts timestamp, id uuid, day text, action text, outcome text,"
            " details map<text,text>, PRIMARY KEY (actor, ts, id)) WITH CLUSTERING ORDER BY (ts DESC, id ASC)",
            "CREATE TABLE IF NOT EXISTS cti_audit.action_counts (day text, action text, id uuid, PRIMARY KEY (day, action, id))"):
        session.execute(ddl)
    _state.update(cassandra=session, cluster=cluster)
    return session


def reset_connections():
    for key in ("cluster",):
        try:
            if _state[key]:
                _state[key].shutdown()
        except Exception:
            pass
    try:
        if _state["graph"]:
            _state["graph"].close()
    except Exception:
        pass
    _state.update(cassandra=None, cluster=None, graph=None, service=None)


def graph():
    if _state["graph"] is None:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(f"bolt://{LAB_HOST}:{NEO4J_PORT}", auth=None, connection_timeout=5)
        driver.verify_connectivity()
        _state["graph"] = driver
    return _state["graph"]


def cypher(query, **params):
    from neo4j import Query as NQuery
    with graph().session() as session:
        return [r.data() for r in session.run(NQuery(query, timeout=20), **params)]


def polyglot_up():
    return port_open(CASSANDRA_PORT) and port_open(NEO4J_PORT) and port_open(MONGO_PORT)


# --------------------------------------------------------------------------- audit outbox flusher
def flush_once(limit=200):
    if not port_open(CASSANDRA_PORT):
        return 0
    with _lock:
        session = cassandra()
        ins_day = session.prepare("INSERT INTO cti_audit.events_by_day (day, ts, id, actor, action, outcome, details) VALUES (?,?,?,?,?,?,?)")
        ins_actor = session.prepare("INSERT INTO cti_audit.events_by_actor (actor, ts, id, day, action, outcome, details) VALUES (?,?,?,?,?,?,?)")
        ins_count = session.prepare("INSERT INTO cti_audit.action_counts (day, action, id) VALUES (?,?,?)")
        delivered = 0
        for ev in pdb().audit_outbox.find().sort("ts", 1).limit(limit):
            event_id = uuid.UUID(ev["_id"])
            ts = ev["ts"].replace(tzinfo=None)
            details = {str(k): str(v) for k, v in (ev.get("details") or {}).items()}
            session.execute(ins_day, (ev["day"], ts, event_id, ev["actor"], ev["action"], ev.get("outcome", "ok"), details))
            session.execute(ins_actor, (ev["actor"], ts, event_id, ev["day"], ev["action"], ev.get("outcome", "ok"), details))
            session.execute(ins_count, (ev["day"], ev["action"], event_id))
            pdb().audit_outbox.delete_one({"_id": ev["_id"]})  # only after Cassandra acknowledged all three writes
            delivered += 1
        _state["delivered"] += delivered
        return delivered


def flusher_loop():
    while True:
        try:
            flush_once()
            _state["last_error"] = None
        except Exception as exc:
            _state["last_error"] = type(exc).__name__
            reset_connections()
        time.sleep(3)


def start_flusher():
    threading.Thread(target=flusher_loop, daemon=True, name="audit-flusher").start()


def lab16_state():
    return {"running": polyglot_up(), "start_command": start_command("polyglot"), "stop_command": stop_command("polyglot"),
            "waiting": pdb().audit_outbox.count_documents({}), "delivered_this_process": _state["delivered"],
            "neo4j_browser": "http://localhost:7474"}


# --------------------------------------------------------------------------- audit log API
@router.get("/ops/audit")
def audit_log(day: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"), actor: str | None = Query(None, max_length=64),
              limit: int = Query(100, ge=1, le=500), user=Depends(require("admin"))):
    state = lab16_state()
    if not port_open(CASSANDRA_PORT):
        return {**state, "available": False, "events": []}
    try:
        flush_once()
        s = cassandra()
        if actor:
            rows = s.execute("SELECT * FROM cti_audit.events_by_actor WHERE actor=%s LIMIT %s", (actor, limit))
        else:
            rows = s.execute("SELECT * FROM cti_audit.events_by_day WHERE day=%s LIMIT %s", (day or utcnow().strftime("%Y-%m-%d"), limit))
        events = [{"id": str(r.id), "ts": r.ts.replace(tzinfo=dt.timezone.utc).isoformat(), "actor": r.actor, "action": r.action,
                   "outcome": r.outcome, "details": dict(r.details or {})} for r in rows if not day or not actor or getattr(r, "day", day) == day]
    except Exception as exc:
        reset_connections()
        raise HTTPException(503, {"message": f"Cassandra is starting or unavailable ({type(exc).__name__}).", **state})
    return {**lab16_state(), "available": True, "events": events}


@router.get("/ops/audit/summary")
def audit_summary(days: int = Query(7, ge=1, le=31), user=Depends(require("admin"))):
    state = lab16_state()
    if not port_open(CASSANDRA_PORT):
        return {**state, "available": False}
    try:
        flush_once()
        s = cassandra()
        per_day = []
        for i in range(days - 1, -1, -1):
            day = (utcnow() - dt.timedelta(days=i)).strftime("%Y-%m-%d")
            counts = {r.action: r.count for r in s.execute("SELECT action, count(*) AS count FROM cti_audit.action_counts WHERE day=%s GROUP BY action", (day,))}
            per_day.append({"day": day, "counts": counts, "total": sum(counts.values())})
    except Exception as exc:
        reset_connections()
        raise HTTPException(503, {"message": f"Cassandra is starting or unavailable ({type(exc).__name__}).", **state})
    totals = {}
    for d in per_day:
        for k, v in d["counts"].items():
            totals[k] = totals.get(k, 0) + v
    kinds = {}
    for k, v in totals.items():
        kinds[k.split(".")[0]] = kinds.get(k.split(".")[0], 0) + v
    return {**lab16_state(), "available": True, "days": per_day, "totals": totals, "by_kind": kinds,
            "events_7d": sum(d["total"] for d in per_day), "actors_today": None}


# --------------------------------------------------------------------------- fraud review
def service():
    if _state["service"] is None:
        mongo = lab_client(MONGO_PORT).college_ch16
        session = cassandra()
        session.set_keyspace("college")
        _state["service"] = FraudQueryService(mongo, session, cypher)
    return _state["service"]


def breaker_states(svc):
    out = {}
    for name, b in svc.breakers.items():
        cooling = b.failures >= b.threshold and time.monotonic() - b.opened < b.cooldown
        out[name] = {"state": "open" if cooling else ("half-open" if b.failures >= b.threshold else "closed"), "failures": b.failures}
    return out


@router.get("/moderation/fraud")
def fraud_accounts(user=Depends(require("moderator", "admin"))):
    require_lab("polyglot")
    try:
        rings = cypher("MATCH p=(u:LabUser)-[:SHARES_DEVICE*2..4]-(u) WITH u, collect(DISTINCT [n IN nodes(p) | n.id]) AS paths "
                       "RETURN u.id AS account, size(paths) AS ring_paths ORDER BY account LIMIT 100")
        txns = {}
        for t in lab_client(MONGO_PORT).college_ch16.transactions.find({}, {"user_id": 1, "amount": 1}).limit(500):
            txns.setdefault(t["user_id"], []).append({"id": t["_id"], "amount": t.get("amount")})
    except Exception as exc:
        reset_connections()
        raise HTTPException(503, {"message": f"Polyglot databases are starting ({type(exc).__name__}). Try again shortly.",
                                  "start_command": start_command("polyglot")})
    for r in rings:
        r["transactions"] = txns.get(r["account"], [])
    return clean({"accounts": rings, "note": "Run ./scripts/lab.sh ch16 --mode quick to (re)load the sample transaction, profile and device-sharing ring."})


@router.get("/moderation/fraud/{account}")
def fraud_review(account: str, txn_id: str | None = Query(None, max_length=64), max_hops: int = Query(3, ge=2, le=4),
                 user=Depends(require("moderator", "admin"))):
    require_lab("polyglot")
    svc = service()
    result, errors = {"account": account}, {}
    try:
        tx = svc.get_transaction(txn_id) if txn_id else svc.breakers["mongo"].call(
            lambda: svc.mongo.transactions.find_one({"user_id": account}))
        result["transaction"] = tx
    except (CircuitOpen, Exception) as exc:
        errors["mongo"] = type(exc).__name__
    try:
        row = svc.get_user_profile(account)
        result["profile"] = dict(row._asdict()) if row else None
    except (CircuitOpen, Exception) as exc:
        errors["cassandra"] = type(exc).__name__
    try:
        result["rings"] = svc.detect_fraud_rings(account, max_depth=max_hops)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except (CircuitOpen, Exception) as exc:
        errors["neo4j"] = type(exc).__name__
    result.update(errors=errors, breakers=breaker_states(svc),
                  classification="Candidates need analyst verification; this is not confirmed fraud.")
    audit("fraud.review", user["_id"], account=account, hops=max_hops, errors=",".join(errors) or "none")
    return clean(result)


@router.post("/services/lab16/{action}")
def lab16_service(action: str, user=Depends(require("moderator", "admin"))):
    if action not in ("start", "stop"):
        raise HTTPException(404, "Use start or stop")
    audit(f"lab.{action}", user["_id"], lab="lab16")
    return {"lab": "lab16", "action": action, "running": polyglot_up(),
            "command": start_command("polyglot") if action == "start" else stop_command("polyglot"),
            "note": "The dashboard does not control Docker (that would need the Docker socket inside the app). Run this command in Ubuntu."}
