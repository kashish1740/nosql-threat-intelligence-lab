#!/usr/bin/env bash
# One command to bring the presentation back up after a restart.
#   cd ~/projects/NoSQL-Projects-main && ./scripts/start-demo.sh
# Starts MongoDB, the web app and the local AI model (data, model and keys are kept between runs),
# waits until everything answers, prints a status summary and opens the dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not reachable. Start Docker Desktop on Windows, wait until it says 'Engine running', then rerun this script." >&2
  exit 1
fi

echo "Starting MongoDB, the web app and the AI model..."
docker compose --profile model up -d >/dev/null

printf 'Waiting for the dashboard'
for i in $(seq 1 60); do
  if curl -sf http://localhost:8000/api/health >/dev/null; then break; fi
  printf '.'; sleep 2
done
echo
if ! curl -sf http://localhost:8000/api/health >/dev/null; then
  echo "The app did not answer. Check: docker compose logs --tail=50 app" >&2
  exit 1
fi

if ! docker compose exec -T ollama ollama list 2>/dev/null | grep -q 'qwen2.5:1.5b'; then
  echo "AI model missing; downloading qwen2.5:1.5b (about 1 GB, needs internet)..."
  docker compose exec -T ollama ollama pull qwen2.5:1.5b
fi

python3 - <<'EOF'
import json, urllib.request
def get(path):
    with urllib.request.urlopen("http://localhost:8000" + path, timeout=20) as r:
        return json.load(r)
health, cti, labs = get("/api/health"), get("/api/cti/status"), get("/api/experiments")
counts = {}
for c in labs:
    s = (c.get("latest") or {}).get("status", "not run"); counts[s] = counts.get(s, 0) + 1
ok = lambda b: "OK " if b else "-- "
print()
print("  Status")
print(f"  {ok(health['database'] == 'available')} MongoDB            {health['database']}")
print(f"  {ok(health['model'] == 'available')} AI model           {health['model_tag']} ({health['model']})")
print(f"  {ok(cti['virustotal_key_configured'])} VirusTotal key     {'configured' if cti['virustotal_key_configured'] else 'missing: ./scripts/set-api-key.sh virustotal'}")
print(f"  {ok(cti['abusech_key_configured'])} abuse.ch key       {'configured (URLhaus + ThreatFox)' if cti['abusech_key_configured'] else 'missing: ./scripts/set-api-key.sh abusech'}")
c = cti["collections"]
print(f"  {ok(c.get('botvrij_indicators', 0) > 0)} Threat data        {c.get('botvrij_indicators', 0):,} Botvrij + {c.get('threatfox_indicators', 0):,} ThreatFox indicators, {c.get('url_analyses', 0)} saved analyses")
print(f"  OK  Experiments        " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
tour = get("/api/tour")["chapters"]
running = [c["chapter"] for c in tour if c["status"] == "running"]
print(f"  OK  Demo identities    demo-admin, demo-moderator, aurora-admin, aurora-analyst, borealis-analyst (sidebar sign-in)")
print(f"  --  Labs running       " + (", ".join(running) if running else "none — start one per chapter, e.g. ./scripts/lab.sh ch14 --mode quick"))
EOF

cat <<'EOF'

  Dashboard        http://localhost:8000
  MongoDB Compass  mongodb://localhost:27018   (web app + URL analysis)
  Run a lab        ./scripts/lab.sh ch10 --mode quick   (its Compass string is on the chapter page)
  Stop everything  docker compose --profile model down   (keeps all data)
EOF

# Open the dashboard in the Windows browser when running under WSL.
if command -v cmd.exe >/dev/null 2>&1; then cmd.exe /c start "" "http://localhost:8000" >/dev/null 2>&1 || true; fi
