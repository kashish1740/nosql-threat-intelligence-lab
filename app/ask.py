"""Chapter 17: Ask — retrieval-augmented answers over threat reports, with citations and memory.

Corpus: the Botvrij.eu OSINT reports already in MongoDB (event title, date, tags, analyst comments and
indicators), split into numbered "pages", plus the 12 classroom advisories. Each page is embedded with
all-MiniLM (384 dimensions) served by the local Ollama, stored in MongoDB ``report_chunks``, and
searched by cosine similarity combined with keyword matching. Answers come from the local LLM with
numbered citations; if the model is unavailable the answer is extractive and says so. Memory keeps
the last 5 exchanges per user. The question text is never written to the audit log.
"""
import datetime as dt
import math
import os
import re
import threading

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pymongo import UpdateOne

from app.platform import audit, clean, pdb, require, signed_in, utcnow

OLLAMA = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434").rstrip("/")
CHAT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-minilm")
ASK_BUDGET = int(os.getenv("ASK_BUDGET", "40"))
PAGE_ATTRS = 25
TOP_K = 6
STOP = set("the a an and or of in on for to with which what who when where how does did do is are was were reports report mention mentions "
           "about from by this that these those any all there their them it its as at be been".split())

router = APIRouter(prefix="/api")
_cache = {"chunks": None}
_index_lock = threading.Lock()


def tidb():
    return pdb().client["threat_intelligence"]


# --------------------------------------------------------------------------- corpus
def build_chunks():
    chunks = []
    attrs_by_event = {}
    for a in tidb().botvrij_indicators.find({}, {"event_uuid": 1, "type": 1, "value": 1, "comment": 1, "category": 1}):
        attrs_by_event.setdefault(a["event_uuid"], []).append(a)
    for ev in tidb().botvrij_events.find():
        attrs = attrs_by_event.get(ev["_id"], [])
        tags = []
        sample = next(iter(attrs), None)
        if sample:
            full = tidb().botvrij_indicators.find_one({"event_uuid": ev["_id"]}, {"event_tags": 1})
            tags = [t for t in (full or {}).get("event_tags") or [] if t and not t.startswith("tlp:")]
        base = {"report": ev.get("info") or ev["_id"], "date": ev.get("date"), "source": "Botvrij.eu",
                "url": f"https://www.botvrij.eu/data/feed-osint/{ev['_id']}.json", "event_uuid": ev["_id"]}
        types = {}
        for a in attrs:
            types[a.get("type")] = types.get(a.get("type"), 0) + 1
        overview = (f"Report: {base['report']}. Published {base['date']} in the Botvrij.eu OSINT feed. "
                    f"Tags: {', '.join(tags[:15]) or 'none'}. Indicators: " + ", ".join(f"{n} {t}" for t, n in sorted(types.items(), key=lambda x: -x[1])[:8]) + ".")
        chunks.append({**base, "page": 1, "text": overview})
        comments = [a for a in attrs if a.get("comment") or a.get("type") in ("text", "comment", "vulnerability", "link")]
        rest = [a for a in attrs if a not in comments]
        page = 2
        for start in range(0, len(comments) + len(rest), PAGE_ATTRS):
            group = (comments + rest)[start:start + PAGE_ATTRS]
            lines = [f"{a.get('type')}: {a.get('value')}" + (f" — {a['comment']}" if a.get("comment") else "") for a in group]
            chunks.append({**base, "page": page, "text": f"Report: {base['report']} (page {page}). " + " | ".join(lines)[:1800]})
            page += 1
            if page > 8:
                break
    for r in pdb().client["threat_lab"].threats.find():
        chunks.append({"report": f"{r['title']} ({r['_id']})", "date": r.get("source_date"), "source": "Ubuntu advisory (classroom)",
                       "url": r.get("source"), "page": 1, "text": f"{r['title']}. Package {r.get('package')}. {r.get('summary', '')} Mitigation: {r.get('mitigation', '')}"})
    return chunks


def ollama_models(client):
    return [m["name"] for m in client.get(f"{OLLAMA}/api/tags").json().get("models", [])]


def ensure_embed_model(client):
    if not any(n.split(":")[0] == EMBED_MODEL for n in ollama_models(client)):
        client.post(f"{OLLAMA}/api/pull", json={"model": EMBED_MODEL, "stream": False}, timeout=600).raise_for_status()


def embed(client, texts):
    r = client.post(f"{OLLAMA}/api/embed", json={"model": EMBED_MODEL, "input": texts}, timeout=300)
    r.raise_for_status()
    return r.json()["embeddings"]


def run_index(actor):
    d = pdb()
    d.settings.update_one({"_id": "ask_index"}, {"$set": {"state": "indexing", "started_at": utcnow(), "error": None, "done": 0}}, upsert=True)
    try:
        chunks = build_chunks()
        d.settings.update_one({"_id": "ask_index"}, {"$set": {"total": len(chunks)}})
        with httpx.Client(timeout=120) as client:
            ensure_embed_model(client)
            ops = []
            for start in range(0, len(chunks), 64):
                batch = chunks[start:start + 64]
                vectors = embed(client, [c["text"] for c in batch])
                for c, v in zip(batch, vectors):
                    key = f"{c.get('event_uuid') or c['report']}:{c['page']}"
                    ops.append(UpdateOne({"_id": key}, {"$set": {**c, "embedding": v, "dims": len(v), "indexed_at": utcnow()}}, upsert=True))
                d.settings.update_one({"_id": "ask_index"}, {"$set": {"done": start + len(batch)}})
            d.report_chunks.delete_many({})
            if ops:
                d.report_chunks.bulk_write(ops, ordered=False)
        _cache["chunks"] = None
        d.settings.update_one({"_id": "ask_index"}, {"$set": {"state": "ready", "finished_at": utcnow(), "chunks": len(chunks),
                                                              "model": EMBED_MODEL, "dims": len(ops and vectors[0] or [])}})
        audit("ask.index", actor, chunks=len(chunks), model=EMBED_MODEL)
    except Exception as exc:
        d.settings.update_one({"_id": "ask_index"}, {"$set": {"state": "error", "error": f"{type(exc).__name__}: {exc}"[:300]}})
        audit("ask.index", actor, outcome="failed", error=type(exc).__name__)
    finally:
        _index_lock.release()


# --------------------------------------------------------------------------- retrieval
def chunks_cache():
    if _cache["chunks"] is None:
        rows = list(pdb().report_chunks.find({}, {"report": 1, "page": 1, "date": 1, "url": 1, "source": 1, "text": 1, "embedding": 1}))
        for r in rows:
            v = r["embedding"]
            norm = math.sqrt(sum(x * x for x in v)) or 1.0
            r["unit"] = [x / norm for x in v]
            r["lower"] = r["text"].lower()
        _cache["chunks"] = rows
    return _cache["chunks"]


def keywords(text):
    phrases = [p.strip().lower() for p in re.findall(r'"([^"]+)"', text)]
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9\-\.]{2,}", text.lower()) if w not in STOP and not re.fullmatch(r"(19|20)\d\d", w)]
    caps = [m.lower() for m in re.findall(r"\b([A-Z][\w\-]+(?:\s+[A-Z][\w\-]+)+)\b", text)]
    return phrases + caps, words


def search(question, years, k=TOP_K):
    rows = chunks_cache()
    if not rows:
        return []
    with httpx.Client(timeout=60) as client:
        q = embed(client, [question])[0]
    norm = math.sqrt(sum(x * x for x in q)) or 1.0
    q = [x / norm for x in q]
    phrases, words = keywords(question)
    scored = []
    for r in rows:
        if years and not any(str(r.get("date") or "").startswith(y) for y in years):
            continue
        cosine = sum(a * b for a, b in zip(q, r["unit"]))
        lexical = sum(2.0 for p in phrases if p in r["lower"]) + sum(0.35 for w in set(words) if w in r["lower"])
        scored.append((cosine + lexical, cosine, lexical, r))
    scored.sort(key=lambda x: -x[0])
    out, seen = [], set()
    for score, cosine, lexical, r in scored:
        key = (r["report"], r["page"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"report": r["report"], "page": r["page"], "date": r.get("date"), "url": r.get("url"), "source": r.get("source"),
                    "text": r["text"], "score": round(score, 3), "cosine": round(cosine, 3), "keyword": round(lexical, 2)})
        if len(out) >= k:
            break
    return out


# --------------------------------------------------------------------------- API
class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=500)


def history_doc(user_id):
    return pdb().ask_history.find_one({"_id": user_id}) or {"exchanges": []}


def extractive(question, hits):
    if not hits:
        return "No indexed report matches this question."
    lines = ["These reports are the closest matches (extractive answer — the language model was not used):"]
    pages = {}
    for i, h in enumerate(hits, 1):
        pages.setdefault((h["report"], h.get("date")), []).append(i)
    for (report, date), numbers in pages.items():
        lines.append(f"- {report} ({date or 'undated'}) " + "".join(f"[{n}]" for n in numbers))
    return "\n".join(lines)


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]{3,}", text.lower()) if w not in STOP}


def ground(text, hits):
    """Keep the model honest: drop citation numbers that do not exist, and when a listed item names a
    report that does not match the source it cites, replace the name with the cited source's title."""
    fixed = []
    for raw in text.splitlines():
        line = re.sub(r"\[(\d+)\]", lambda m: m.group(0) if 1 <= int(m.group(1)) <= len(hits) else "", raw)
        if re.search(r"\[\d+\]", raw) and not re.search(r"\[\d+\]", line) and re.match(r"\s*([-*•]|\d+[.)])\s", raw):
            continue  # a listed item whose only citations point at sources that do not exist
        cited = [int(n) for n in re.findall(r"\[(\d+)\]", line)]
        if cited and re.match(r"\s*([-*•]|\d+[.)])\s", line):
            source = hits[cited[0] - 1]
            claimed = re.sub(r"\[(\d+)\]", "", re.sub(r"^\s*([-*•]|\d+[.)])\s*", "", line))
            if len(_words(claimed) & _words(source["report"])) < min(2, len(_words(source["report"]))):
                marker = re.match(r"\s*([-*•]|\d+[.)])", line).group(0)
                line = f"{marker} {source['report']} ({source.get('date') or 'undated'}) " + "".join(f"[{n}]" for n in cited)
        fixed.append(line)
    return "\n".join(fixed).strip()


@router.post("/ask")
def ask(body: AskIn, user=Depends(signed_in)):
    d = pdb()
    if not d.report_chunks.estimated_document_count():
        raise HTTPException(409, "The report index is empty. An admin must press Index the reports (Operations → Ask index).")
    day = utcnow().strftime("%Y-%m-%d")
    used = d.ask_budget.find_one_and_update({"_id": f"{user['_id']}:{day}"}, {"$inc": {"n": 1}, "$setOnInsert": {"expires_at": utcnow() + dt.timedelta(days=2)}},
                                           upsert=True, return_document=True)
    if used["n"] > ASK_BUDGET:
        raise HTTPException(429, f"Daily question budget reached ({ASK_BUDGET}). Try again tomorrow.")
    history = history_doc(user["_id"])["exchanges"][-5:]
    question = body.question.strip()
    years = re.findall(r"\b((?:19|20)\d\d)\b", question)
    retrieval_q = question
    # A follow-up ("and in 2023?", "what about 2022?") has no subject of its own: it then reuses the previous question's.
    own_subject = keywords(re.sub(r"^\s*(and|also|what about|how about)\b", "", question, flags=re.I))[1]
    follow_up = bool(re.match(r"\s*(and|also|what about|how about)\b", question, re.I)) or not own_subject
    if history and follow_up:
        retrieval_q = history[-1]["question"] + " " + question
        if not years:
            years = history[-1].get("years") or []
    hits = search(retrieval_q, years)
    mode, model, answer = "extractive", None, None
    if hits:
        context = "\n\n".join(f"[{i}] {h['report']} — page {h['page']} ({h.get('date') or 'undated'})\n{h['text'][:900]}" for i, h in enumerate(hits, 1))
        # Memory gives the model the earlier questions (to understand follow-ups) but not its earlier
        # answers, so it cannot repeat reports that are not in the current sources.
        earlier = "; ".join(x["question"] for x in history[-3:])
        prompt = ("You answer questions about cyber threat reports using ONLY the numbered sources below. "
                  "When listing reports, write one line per report as '- <report title> [n]' using the title exactly as given in the source. "
                  "Cite every claim with its source number in square brackets. If the sources do not answer the question, say so. Keep it short.\n\n"
                  f"Earlier questions in this conversation: {earlier or 'none'}\n\nSources:\n{context}\n\nQuestion: {question}\nAnswer:")
        try:
            # keep_alive holds the model in memory between questions; the first one may wait for it to load.
            r = httpx.post(f"{OLLAMA}/api/generate", json={"model": CHAT_MODEL, "prompt": prompt, "stream": False, "keep_alive": "30m",
                                                           "options": {"temperature": 0.1, "num_predict": 400}}, timeout=240)
            r.raise_for_status()
            text = ground(r.json().get("response", "").strip(), hits)
            if text and re.search(r"\[\d+\]", text):
                answer, mode, model = text, "llm", CHAT_MODEL
        except Exception:
            pass
    if answer is None:
        answer = extractive(question, hits)
    citations = [{"n": i, "report": h["report"], "page": h["page"], "date": h.get("date"), "url": h.get("url"), "source": h.get("source"),
                  "score": h["score"]} for i, h in enumerate(hits, 1)]
    d.ask_history.update_one({"_id": user["_id"]}, {"$push": {"exchanges": {"$each": [{
        "question": question, "answer": answer, "mode": mode, "years": years, "ts": utcnow()}], "$slice": -5}}}, upsert=True)
    audit("ask.question", user["_id"], length=len(question), mode=mode, model=model or "none")
    return {"answer": answer, "citations": citations, "mode": mode, "model": model, "memory_used": len(history),
            "retrieval": "cosine similarity over all-MiniLM embeddings + keyword match" + (f", filtered to {', '.join(years)}" if years else ""),
            "budget_left": max(0, ASK_BUDGET - used["n"])}


@router.get("/ask/history")
def get_history(user=Depends(signed_in)):
    return clean(history_doc(user["_id"])["exchanges"])


@router.delete("/ask/history")
def forget(user=Depends(signed_in)):
    pdb().ask_history.delete_one({"_id": user["_id"]})
    audit("ask.forget", user["_id"])
    return {"forgotten": True}


@router.get("/ops/ask-index")
def index_status(user=Depends(require("admin"))):
    d = pdb()
    status = d.settings.find_one({"_id": "ask_index"}) or {"state": "empty"}
    return clean({**{k: v for k, v in status.items() if k != "_id"}, "chunks_indexed": d.report_chunks.estimated_document_count(),
                  "embedding_model": EMBED_MODEL, "chat_model": CHAT_MODEL, "questions_asked": sum(x.get("n", 0) for x in d.ask_budget.find()),
                  "vector_search": "Exact cosine kNN in the app (MongoDB 7 Community has no $vectorSearch; Atlas would add an HNSW index)."})


@router.post("/ops/ask-index")
def start_index(user=Depends(require("admin"))):
    if not _index_lock.acquire(blocking=False):
        raise HTTPException(409, "Indexing is already running.")
    threading.Thread(target=run_index, args=(user["_id"],), daemon=True).start()
    return {"state": "indexing"}
