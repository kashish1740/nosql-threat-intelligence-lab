#!/bin/sh
# Starts MongoDB, Ollama and the dashboard inside the all-in-one image (Dockerfile.full).
set -e
mkdir -p /data/db
mongod --dbpath /data/db --bind_ip 127.0.0.1 --fork --logpath /var/log/mongod.log >/dev/null
echo "MongoDB started"
ollama serve >/var/log/ollama.log 2>&1 &
OLLAMA_PID=$!
i=0; until ollama list >/dev/null 2>&1 || [ $i -ge 60 ]; do i=$((i+1)); sleep 1; done
echo "Ollama started (models: $(ollama list | tail -n +2 | awk '{print $1}' | tr '\n' ' '))"

stop() {
  kill "$APP_PID" 2>/dev/null || true
  mongod --dbpath /data/db --shutdown >/dev/null 2>&1 || true
  kill "$OLLAMA_PID" 2>/dev/null || true
  exit 0
}
trap stop TERM INT

echo "Dashboard on http://localhost:8000"
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
APP_PID=$!
wait "$APP_PID"
