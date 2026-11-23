import json
import os
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pymongo import MongoClient, TEXT

client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=3000)
db = client.threat_lab
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
STATUSES = ["Anticipated", "Active", "Evolving", "Resolved"]


def seed():
    records = json.loads(Path("data/threats.json").read_text())
    for record in records:
        db.threats.replace_one({"_id": record["_id"]}, record, upsert=True)
    db.threats.create_index([("summary", TEXT), ("package", TEXT), ("title", TEXT)])
    db.threats.create_index("status")
    return db.threats.count_documents({})


@asynccontextmanager
async def lifespan(app):
    seed()
    # Experiment 7: refresh the Botvrij.eu feed in the background (only changed events are downloaded).
    import threading
    from app.cti import sync_if_stale
    threading.Thread(target=sync_if_stale, daemon=True).start()
    # Chapters 13–18: demo identities, the metrics sampler (Ch 13/14) and the Cassandra audit flusher (Ch 16).
    from app.platform import seed_platform, pdb
    from app.ops import start_sampler
    from app.polyglot import start_flusher
    seed_platform()
    pdb().ask_budget.create_index("expires_at", expireAfterSeconds=0)
    start_sampler()
    start_flusher()
    yield
    client.close()


app = FastAPI(title="Linux Threat Intelligence Assistant", lifespan=lifespan)

from fastapi.staticfiles import StaticFiles  # noqa: E402
from app.experiments import router as experiments_router  # noqa: E402
from app.cti import router as cti_router  # noqa: E402
from app import platform, ops, cases, polyglot, ask, fp, pcscan  # noqa: E402

app.include_router(experiments_router)
app.include_router(cti_router)
for module in (platform, ops, cases, polyglot, ask, fp, pcscan):
    app.include_router(module.router)
app.add_exception_handler(cases.RateLimited, cases.rate_limited_handler)


@app.middleware("http")
async def revalidate_static(request, call_next):
    # The page and its scripts change with every update: browsers must re-check them (cheap ETag 304s)
    # instead of showing a cached old version after a rebuild.
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
def home():
    return FileResponse("app/static/index.html")


@app.get("/api/health")
def health():
    state = {"database": "unavailable", "model": "unavailable", "model_tag": MODEL}
    try:
        client.admin.command("ping")
        state["database"] = "available"
    except Exception:
        pass
    try:
        response = httpx.get(OLLAMA + "/api/tags", timeout=3)
        response.raise_for_status()
        state["model"] = "available" if MODEL in [m["name"] for m in response.json()["models"]] else "not downloaded"
    except Exception:
        pass
    return state


@app.get("/api/threats")
def threats(q: str = "", status: str = ""):
    query = {}
    if status:
        if status not in STATUSES:
            raise HTTPException(422, "Unknown lifecycle status")
        query["status"] = status
    if q.strip():
        query["$text"] = {"$search": q[:500]}
    return list(db.threats.find(query).sort("_id", 1).limit(50))


@app.get("/api/threats/{record_id}")
def detail(record_id: str):
    record = db.threats.find_one({"_id": record_id})
    if not record:
        raise HTTPException(404, "Record not found")
    return record


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = Field(default=None, max_length=64)


NO_PC_SCAN = ("No scan of this PC has been received yet, so there is no evidence about it. Run the read-only scanner in "
              "Windows PowerShell from the project folder: powershell -ExecutionPolicy Bypass -File .\\scripts\\scan-pc.ps1 "
              "— then ask again, or open the My PC page.")


def retrieve(message, exchanges):
    lower = message.lower()
    from app.pcscan import PC_INTENT, pc_records
    if re.search(r"\b(first|that one|it)\b", lower) and exchanges:
        ids = exchanges[-1].get("record_ids", [])
        if ids and str(ids[0]).startswith("PC-"):
            # Follow-up on a PC answer: "the first one" = the first finding cited after the summary.
            findings = [i for i in ids if i != "PC-SUMMARY"]
            return pc_records(ids=findings[:1] or ids[:1]) or []
        return [detail(ids[0])] if ids else []
    if PC_INTENT.search(message):
        return pc_records(question=message)  # None = no scan yet
    status = next((s for s in STATUSES if re.search(r"\b" + s.lower() + r"\b", lower)), "")
    if status and any(w in lower for w in ("linux", "threat", "dataset")):
        return threats(status=status)[:3]
    return threats(q=message, status=status)[:3]


@app.post("/api/chat")
def chat(request: ChatRequest):
    cid = request.conversation_id or str(uuid.uuid4())
    conversation = db.conversations.find_one({"_id": cid}) or {}
    exchanges = conversation.get("exchanges", [])[-5:]
    records = retrieve(request.message, exchanges)
    answer = "The records in this dataset provide insufficient evidence to answer that question."
    if records is None:
        records, answer = [], NO_PC_SCAN
    sources = [{"id": r["_id"], "url": r["source"], "title": r["title"]} for r in records]
    generated = False
    if records:
        from app.rag import generate_and_store
        try:
            result = generate_and_store(db, cid, request.message, records)
            return {"conversation_id": cid, "answer": result["answer"], "retrieved_sources": sources,
                    "model_generated": True, "history_exchanges_used": result["history_exchanges_used"]}
        except Exception:
            raise HTTPException(503, "Model unavailable, timed out, or returned unsupported citations. Search remains available.")
    db.conversations.update_one({"_id": cid}, {"$push": {"exchanges": {"$each": [{"question": request.message, "answer": answer, "record_ids": [r["_id"] for r in records]}], "$slice": -5}}}, upsert=True)
    return {"conversation_id": cid, "answer": answer, "retrieved_sources": sources, "model_generated": generated}
