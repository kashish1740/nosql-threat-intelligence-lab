"""Read-only browser for the chapter labs: their source code and saved run evidence.

Only files under labs/chNN and results/chNN are ever served. Secrets, backups and
other repository folders are never reachable through these routes.
"""
import json
import os
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

LABS = Path(os.getenv("LABS_DIR", "labs")).resolve()
RESULTS = Path(os.getenv("RESULTS_DIR", "results")).resolve()

CHAPTER_RE = re.compile(r"^ch(0[1-9]|1[0-8])$")
RUN_RE = re.compile(r"^\d{8}T\d{6,12}Z$")
TEXT_SUFFIXES = {".py", ".md", ".json", ".js", ".txt", ".yaml", ".yml", ".sh", ".log", ".csv"}
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml"}
MAX_TEXT = 400_000

# Mirrors scripts/lab.sh so the page can show where each chapter runs.
TOPOLOGY = {
    **{c: ("standalone", "college-basic") for c in ("ch01", "ch02", "ch03", "ch04", "ch05", "ch06", "ch07", "ch15", "ch17")},
    **{c: ("replica", "college-replica") for c in ("ch08", "ch09", "ch10", "ch14")},
    "ch11": ("shards", "college-shards"),
    "ch12": ("auth", "college-auth"),
    "ch13": ("secure", "college-secure"),
    "ch16": ("polyglot", "college-polyglot"),
    "ch18": ("polyglot", "college-polyglot"),
}

# How to open each topology's MongoDB in MongoDB Compass (ports published on 127.0.0.1 in infra/*.yaml).
TLS_STEPS = ("In Compass: Advanced Connection Options → TLS/SSL → On, Certificate Authority = "
             r"\\wsl.localhost\Ubuntu\home\<you>\projects\NoSQL-Projects-main\.secrets\ca.crt ; "
             "the admin password is printed by: cat ~/projects/NoSQL-Projects-main/.secrets/password")
COMPASS = {
    "standalone": {"uri": "mongodb://localhost:27019", "note": "Single server."},
    "replica": {"uri": "mongodb://localhost:27031/?directConnection=true",
                "note": "Three members on ports 27031, 27032 and 27033 (direct connection to one member each). "
                        "27031 is normally the primary; on a secondary add &readPreference=secondaryPreferred to browse."},
    "shards": {"uri": "mongodb://localhost:27034", "note": "Connects through the mongos router, so Compass sees the whole sharded cluster."},
    "auth": {"uri": "mongodb://admin:<password>@localhost:27035/?tls=true&authSource=admin", "note": TLS_STEPS},
    "secure": {"uri": "mongodb://admin:<password>@localhost:27036/?tls=true&authSource=admin&directConnection=true",
               "note": "Members on 27036, 27037 and 27038. " + TLS_STEPS},
    "polyglot": {"uri": "mongodb://localhost:27039", "note": "MongoDB part only; Cassandra and Neo4j stay inside Docker."},
}

router = APIRouter(prefix="/api/experiments")


def _chapter(chapter: str) -> str:
    if not CHAPTER_RE.match(chapter):
        raise HTTPException(404, "Unknown chapter")
    return chapter


def _inside(base: Path, relative: str) -> Path:
    target = (base / relative).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        raise HTTPException(404, "File not found")
    return target


def _title(chapter: str) -> str:
    readme = LABS / chapter / "README.md"
    if readme.is_file():
        for line in readme.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    return chapter


def _runs(chapter: str) -> list[dict]:
    folder = RESULTS / chapter
    runs = []
    if not folder.is_dir():
        return runs
    for run_dir in folder.iterdir():
        result = run_dir / "result.json"
        if not (run_dir.is_dir() and RUN_RE.match(run_dir.name) and result.is_file()):
            continue
        try:
            data = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {"status": "unreadable"}
        runs.append({"id": run_dir.name, "status": data.get("status"), "mode": data.get("mode"),
                     "activity": data.get("activity"), "elapsed_seconds": data.get("elapsed_seconds"),
                     "events": len(data.get("events", []))})
    return sorted(runs, key=lambda r: r["id"], reverse=True)


def _files(folder: Path, base: Path) -> list[str]:
    return sorted(str(p.relative_to(base)).replace("\\", "/") for p in folder.rglob("*")
                  if p.is_file() and p.suffix in TEXT_SUFFIXES and "__pycache__" not in p.parts)


@router.get("")
def list_experiments():
    chapters = []
    for i in range(1, 19):
        chapter = f"ch{i:02}"
        runs = _runs(chapter)
        topology, project = TOPOLOGY[chapter]
        chapters.append({"id": chapter, "title": _title(chapter), "topology": topology, "project": project,
                         "latest": runs[0] if runs else None, "run_count": len(runs)})
    return chapters


@router.get("/{chapter}")
def experiment(chapter: str):
    chapter = _chapter(chapter)
    base = LABS / chapter
    if not base.is_dir():
        raise HTTPException(404, "Chapter source not found")
    activities = []
    for folder in sorted(p for p in base.iterdir() if p.is_dir() and p.name.startswith("activity_")):
        readme = folder / "README.md"
        activities.append({"name": folder.name,
                           "readme": readme.read_text(encoding="utf-8", errors="replace") if readme.is_file() else "",
                           "files": _files(folder, base)})
    chapter_files = sorted(p.name for p in base.iterdir() if p.is_file() and p.suffix in TEXT_SUFFIXES)
    logs = sorted((p.name for p in (RESULTS / chapter).glob("*.log")), reverse=True) if (RESULTS / chapter).is_dir() else []
    topology, project = TOPOLOGY[chapter]
    readme = base / "README.md"
    return {"id": chapter, "title": _title(chapter), "topology": topology, "project": project,
            "command": f"./scripts/lab.sh {chapter} --mode quick",
            "stop_command": f"docker compose -p {project} -f infra/{topology}.yaml down",
            # Chapter 13 keeps no lab collections: it tests secure logins and failover, so show its users instead.
            "compass": {**COMPASS[topology], "database": "admin (system.users) — run rs.status() in the shell" if chapter == "ch13" else f"college_{chapter}"},
            "readme": readme.read_text(encoding="utf-8", errors="replace") if readme.is_file() else "",
            "files": chapter_files, "activities": activities, "runs": _runs(chapter), "logs": logs}


@router.get("/{chapter}/source")
def source(chapter: str, path: str):
    target = _inside(LABS / _chapter(chapter), path)
    if target.suffix not in TEXT_SUFFIXES:
        raise HTTPException(415, "Not a text source file")
    return {"path": path, "content": target.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT],
            "truncated": target.stat().st_size > MAX_TEXT}


@router.get("/{chapter}/runs/{run_id}")
def run(chapter: str, run_id: str):
    chapter = _chapter(chapter)
    if not RUN_RE.match(run_id):
        raise HTTPException(404, "Unknown run")
    run_dir = RESULTS / chapter / run_id
    result = _inside(RESULTS, f"{chapter}/{run_id}/result.json")
    artifacts = sorted(p.name for p in run_dir.iterdir() if p.is_file() and p.name != "result.json")
    return {"result": json.loads(result.read_text(encoding="utf-8")), "artifacts": artifacts}


@router.get("/{chapter}/runs/{run_id}/artifacts/{name}")
def artifact(chapter: str, run_id: str, name: str):
    chapter = _chapter(chapter)
    if not RUN_RE.match(run_id) or "/" in name or "\\" in name:
        raise HTTPException(404, "Unknown artifact")
    target = _inside(RESULTS, f"{chapter}/{run_id}/{name}")
    if target.suffix in IMAGE_TYPES:
        return FileResponse(target, media_type=IMAGE_TYPES[target.suffix])
    if target.suffix in TEXT_SUFFIXES:
        return {"name": name, "content": target.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT]}
    raise HTTPException(415, "Unsupported artifact type")


@router.get("/{chapter}/logs/{name}")
def log(chapter: str, name: str):
    chapter = _chapter(chapter)
    if not name.endswith(".log") or "/" in name or "\\" in name:
        raise HTTPException(404, "Unknown log")
    target = _inside(RESULTS, f"{chapter}/{name}")
    text = target.read_text(encoding="utf-8", errors="replace")
    # Strip terminal colour/cursor codes written by docker build output.
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    return {"name": name, "content": text[-MAX_TEXT:], "truncated": len(text) > MAX_TEXT}
