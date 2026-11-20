"""Shared platform services for Chapters 13–18 inside this dashboard.

* Demo sign-in with roles (analyst / moderator / admin) and organisations. There are no passwords:
  this is a classroom demo. The server signs a session token and always looks the role up in
  MongoDB, so a role cannot be forged from the browser.
* An audit trail: every audited action is written to the MongoDB ``audit_outbox`` and delivered to
  Cassandra (Chapter 16) by ``app.polyglot`` once that topology is running.
* Connections to the lab topologies, published on the Docker host (see infra/*.yaml). A stopped lab
  answers 503 with the command that starts it, never a stack trace.
* ``CTI_PUBLIC=1`` turns every lab endpoint off with a 403 and an explanation.
"""
import datetime as dt
import hashlib
import hmac
import os
import secrets
import socket
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from pymongo import MongoClient

LAB_HOST = os.getenv("LAB_HOST", "host.docker.internal")
SECRETS = Path(os.getenv("LAB_SECRETS_DIR", "/secrets"))
ROLES = ("analyst", "moderator", "admin")

_client = None
router = APIRouter(prefix="/api")


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def pdb():
    """The platform database (users, cases, audit outbox, metrics, alerts, decisions…)."""
    global _client
    if _client is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=4000, tz_aware=True)
    return _client["cti_platform"]


def clean(doc):
    if isinstance(doc, dict):
        return {k: clean(v) for k, v in doc.items()}
    if isinstance(doc, (list, tuple)):
        return [clean(v) for v in doc]
    if isinstance(doc, dt.datetime):
        return doc.isoformat()
    return doc


# --------------------------------------------------------------------------- lab topologies
TOPOLOGIES = {
    "basic": {"label": "Standalone server", "chapters": ["ch07", "ch15", "ch17"], "ports": [27019], "compose": "college-basic", "file": "standalone"},
    "replica": {"label": "Replica set rs0", "chapters": ["ch08", "ch09", "ch10", "ch14"], "ports": [27031, 27032, 27033], "compose": "college-replica", "file": "replica"},
    "shards": {"label": "Sharded cluster", "chapters": ["ch11"], "ports": [27034], "compose": "college-shards", "file": "shards"},
    "auth": {"label": "Auth + TLS", "chapters": ["ch12"], "ports": [27035], "compose": "college-auth", "file": "auth"},
    "secure": {"label": "Secure replica set (keyfile + TLS)", "chapters": ["ch13"], "ports": [27036, 27037, 27038], "compose": "college-secure", "file": "secure"},
    "polyglot": {"label": "MongoDB + Cassandra + Neo4j", "chapters": ["ch16", "ch18"], "ports": [27039, 9042, 7687], "compose": "college-polyglot", "file": "polyglot"},
}
START_CHAPTER = {"basic": "ch07", "replica": "ch14", "shards": "ch11", "auth": "ch12", "secure": "ch13", "polyglot": "ch16"}


def port_open(port, host=None, timeout=0.6):
    try:
        with socket.create_connection((host or LAB_HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def topology_up(name):
    return any(port_open(p) for p in TOPOLOGIES[name]["ports"][:1])


def start_command(name):
    t = TOPOLOGIES[name]
    return f"./scripts/lab.sh {START_CHAPTER[name]} --mode quick"


def stop_command(name):
    t = TOPOLOGIES[name]
    return f"docker compose -p {t['compose']} -f infra/{t['file']}.yaml down"


class LabStopped(HTTPException):
    def __init__(self, name):
        super().__init__(503, {"message": f"{TOPOLOGIES[name]['label']} is not running.",
                               "start_command": start_command(name), "topology": name})


def require_lab(name):
    if not topology_up(name):
        raise LabStopped(name)


def lab_access():
    if os.getenv("CTI_PUBLIC") == "1":
        raise HTTPException(403, "Lab features are disabled on this public deployment (CTI_PUBLIC=1). "
                                 "Run the project locally to use them.")


def secure_password():
    try:
        return (SECRETS / "password").read_text().strip()
    except OSError:
        return None


def lab_client(port, tls=False, **kwargs):
    """Direct connection to one lab mongod (replica-set hostnames are not resolvable from the app)."""
    opts = dict(directConnection=True, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000, tz_aware=True)
    if tls:
        # The lab certificate is issued for localhost and the container names (mongo, mongo1-3), not for
        # host.docker.internal, which is how the app reaches the lab. The chain is still verified against
        # the lab CA; only the hostname check is relaxed for this internal hop.
        opts.update(tls=True, tlsCAFile=str(SECRETS / "ca.crt"), tlsAllowInvalidHostnames=True,
                    username="admin", password=secure_password() or "", authSource="admin")
    opts.update(kwargs)
    return MongoClient(LAB_HOST, port, **opts)


# --------------------------------------------------------------------------- demo identities
DEMO_USERS = [
    {"_id": "demo-admin", "name": "Demo Admin", "role": "admin", "org": None, "org_role": None},
    {"_id": "demo-moderator", "name": "Demo Moderator", "role": "moderator", "org": None, "org_role": None},
    {"_id": "aurora-admin", "name": "Aurora Admin", "role": "analyst", "org": "aurora", "org_role": "admin"},
    {"_id": "aurora-analyst", "name": "Aurora Analyst", "role": "analyst", "org": "aurora", "org_role": "member"},
    {"_id": "borealis-analyst", "name": "Borealis Analyst", "role": "analyst", "org": "borealis", "org_role": "member"},
]
ORGS = {"aurora": "Aurora Security", "borealis": "Borealis Labs"}


def _secret():
    d = pdb()
    doc = d.settings.find_one({"_id": "session_secret"})
    if not doc:
        d.settings.update_one({"_id": "session_secret"}, {"$setOnInsert": {"value": secrets.token_hex(32)}}, upsert=True)
        doc = d.settings.find_one({"_id": "session_secret"})
    return doc["value"].encode()


def sign(username):
    return username + "." + hmac.new(_secret(), username.encode(), hashlib.sha256).hexdigest()[:32]


def seed_platform():
    d = pdb()
    for u in DEMO_USERS:
        d.users.update_one({"_id": u["_id"]}, {"$setOnInsert": {**u, "created_at": utcnow()}}, upsert=True)
    for key, name in ORGS.items():
        d.organisations.update_one({"_id": key}, {"$setOnInsert": {"name": name}}, upsert=True)
    d.audit_outbox.create_index("ts")
    d.cases.create_index([("tenant_id", 1), ("created_at", -1)])
    d.rate_limits.create_index("expires_at", expireAfterSeconds=0)


def current_user(x_session: str = Header(default="")):
    if "." not in x_session:
        return None
    username, _ = x_session.rsplit(".", 1)
    if not hmac.compare_digest(sign(username), x_session):
        return None
    return pdb().users.find_one({"_id": username})


def signed_in(user=Depends(current_user)):
    if not user:
        raise HTTPException(401, "Sign in first (choose a demo identity in the sidebar).")
    return user


def require(*roles):
    def dependency(user=Depends(signed_in)):
        if user["role"] not in roles:
            raise HTTPException(403, f"This needs the {' or '.join(roles)} role; you are signed in as {user['role']}.")
        return user
    return dependency


# --------------------------------------------------------------------------- audit trail
def audit(action, actor, outcome="ok", **details):
    """Queue an audit event; app.polyglot delivers it to Cassandra exactly once."""
    now = utcnow()
    pdb().audit_outbox.insert_one({"_id": str(uuid.uuid4()), "ts": now, "day": now.strftime("%Y-%m-%d"),
                                   "actor": actor or "anonymous", "action": action, "outcome": outcome,
                                   "details": {k: str(v)[:300] for k, v in details.items()}})


# --------------------------------------------------------------------------- API
class SignIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)


@router.get("/auth/users")
def demo_users():
    return clean(list(pdb().users.find({}, {"name": 1, "role": 1, "org": 1, "org_role": 1}).sort("_id", 1)))


@router.post("/auth/signin")
def signin(body: SignIn):
    user = pdb().users.find_one({"_id": body.username})
    if not user:
        raise HTTPException(404, "Unknown demo user")
    audit("auth.signin", user["_id"])
    return {"token": sign(user["_id"]), "user": clean(user)}


@router.get("/auth/me")
def me(user=Depends(current_user)):
    return {"user": clean(user) if user else None}


class UserUpdate(BaseModel):
    org: str | None = Field(default=None, max_length=40)
    org_role: str | None = Field(default=None, pattern="^(admin|member)$")
    role: str | None = Field(default=None, pattern="^(analyst|moderator|admin)$")


@router.get("/admin/users")
def list_users(user=Depends(require("admin"))):
    return clean({"users": list(pdb().users.find().sort("_id", 1)), "organisations": list(pdb().organisations.find())})


@router.patch("/admin/users/{username}")
def update_user(username: str, body: UserUpdate, user=Depends(require("admin"))):
    changes = {k: v for k, v in body.model_dump().items() if k in body.model_fields_set}
    if "org" in changes and changes["org"] and not pdb().organisations.find_one({"_id": changes["org"]}):
        raise HTTPException(422, "Unknown organisation")
    if changes.get("org") is None and "org" in changes:
        changes["org_role"] = None
    if not pdb().users.update_one({"_id": username}, {"$set": changes}).matched_count:
        raise HTTPException(404, "Unknown user")
    audit("user.update", user["_id"], target=username, changes=changes)
    return clean(pdb().users.find_one({"_id": username}))


CHAPTER_TOUR = [
    ("ch07", "URL threat analysis: URLhaus, ThreatFox, Botvrij.eu, VirusTotal and GCVE, merged and stored in MongoDB", "app", "#analysis"),
    ("ch08", "Replica set rs0: the Deployment charts show its members", "replica", "#lab/ch08"),
    ("ch09", "Write concerns and partitions on rs0", "replica", "#lab/ch09"),
    ("ch10", "Transactions on rs0", "replica", "#lab/ch10"),
    ("ch11", "Sharded cluster through mongos", "shards", "#lab/ch11"),
    ("ch12", "Users, roles and TLS", "auth", "#lab/ch12"),
    ("ch13", "Secure replica set: live member state, failover with an election marker", "secure", "#ops/deployment"),
    ("ch14", "Monitoring every 10 s, alerts, back up now and verified restore with RTO", "replica", "#ops/monitoring"),
    ("ch15", "Multi-tenant cases per organisation with a MongoDB rate limit", "app", "#cases"),
    ("ch16", "Audit log in Cassandra and fraud review across MongoDB, Cassandra and Neo4j", "polyglot", "#moderation/fraud"),
    ("ch17", "Ask: vector retrieval over threat reports with cited answers and memory", "app", "#ask"),
    ("ch18", "False-positive review: three databases vote; decisions change the export", "polyglot", "#moderation/fp"),
]


@router.get("/tour")
def tour():
    up = {name: topology_up(name) for name in TOPOLOGIES}
    rows = []
    for ch, what, where, link in CHAPTER_TOUR:
        if where == "app":
            status, image = "app", "nosql-projects-main-app (FastAPI) + mongo:7.0"
        else:
            status = "running" if up[where] else "stopped"
            image = "mongo:7.0" + (" + cassandra:4.1 + neo4j:5.26-community" if where == "polyglot" else "") + f" · lab image {TOPOLOGIES[where]['compose']}-lab"
        rows.append({"chapter": ch, "what": what, "status": status, "topology": where, "image": image, "link": link,
                     "lab_page": f"#lab/{ch}", "start_command": None if where == "app" else start_command(where),
                     "stop_command": None if where == "app" else stop_command(where)})
    return {"chapters": rows, "public": os.getenv("CTI_PUBLIC") == "1"}
