#!/usr/bin/env bash
# Save an API key for Experiment 7 without showing it on screen, check it, then restart the app.
#   ./scripts/set-api-key.sh virustotal   # key from https://www.virustotal.com/gui/my-apikey
#   ./scripts/set-api-key.sh abusech      # key from https://auth.abuse.ch/ (URLhaus + ThreatFox)
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  virustotal|vt) name=VirusTotal; var=VT_API_KEY; flag=virustotal_key_configured ;;
  abusech|abuse.ch) name=abuse.ch; var=ABUSECH_AUTH_KEY; flag=abusech_key_configured ;;
  *) echo "Usage: $0 virustotal|abusech" >&2; exit 2 ;;
esac

for attempt in 1 2 3; do
  read -rsp "Paste your $name API key with RIGHT-CLICK (input hidden), then press Enter: " key
  printf '\n'
  # Terminals may wrap a paste in bracketed-paste markers (ESC[200~ ... ESC[201~) or pass a raw Ctrl+V;
  # drop those, then keep only characters that can appear in a key.
  key=${key//$'\e[200~'/}; key=${key//$'\e[201~'/}
  key=$(printf '%s' "$key" | tr -cd 'A-Za-z0-9_-')
  if [ ${#key} -ge 20 ]; then break; fi
  echo "That paste did not arrive (received ${#key} usable characters). Right-click inside this window to paste, then press Enter." >&2
  key=''
done
if [ -z "$key" ]; then echo 'No key received; nothing changed.' >&2; exit 1; fi
echo "Received a ${#key}-character key: ${key:0:4}…${key: -4}"

echo "Checking the key with $name..."
if [ "$var" = VT_API_KEY ]; then
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -H "x-apikey: $key" https://www.virustotal.com/api/v3/domains/example.com || true)
else
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 30 -X POST -H "Auth-Key: $key" -d 'url=http://example.com/' https://urlhaus-api.abuse.ch/v1/url/ || true)
fi
case "$code" in
  200) ;;
  429) echo "$name says the key works but its rate limit is reached right now; saving it anyway." ;;
  000) echo "Could not reach $name (no network?). Nothing changed; try again." >&2; exit 1 ;;
  *) echo "$name rejected the key (HTTP $code). Copy the whole key again from the $name website (copy icon) and rerun; nothing changed." >&2; exit 1 ;;
esac

touch .env
chmod 600 .env
tmp=$(mktemp)
grep -v "^$var=" .env > "$tmp" || true
printf '%s=%s\n' "$var" "$key" >> "$tmp"
cat "$tmp" > .env && rm -f "$tmp"
unset key
echo "Key saved to .env as $var (readable only by you; .env is ignored by Git and Docker builds)."

echo 'Restarting the app so it picks up the key...'
docker compose --profile model up -d app >/dev/null
for i in $(seq 1 30); do curl -sf http://localhost:8000/api/cti/status >/dev/null && break; sleep 2; done
if curl -s http://localhost:8000/api/cti/status | grep -q "\"$flag\":true"; then
  echo "Done: $name is now enabled in Lab Experiments -> CH07 -> Threat Analysis."
else
  echo 'The app did not report the key as configured; check: docker compose logs --tail=50 app' >&2
  exit 1
fi
