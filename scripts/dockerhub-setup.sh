#!/usr/bin/env bash
# One-time setup for automatic Docker Hub publishing.
# Asks for your Docker Hub username and an access token (hidden), checks them with Docker Hub, and stores
# them in the GitHub repository: DOCKERHUB_USERNAME as a variable, DOCKERHUB_TOKEN as an encrypted secret.
# The token is never printed or written to disk.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Your Docker Hub USERNAME is shown at the top right of hub.docker.com (not your email, not your GitHub name)."
read -rp "Docker Hub username: " user
user=$(printf '%s' "$user" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
[ -n "$user" ] || { echo "No username entered; nothing changed." >&2; exit 1; }
case "$user" in *@*) echo "That looks like an email address. Use the Docker Hub username instead; nothing changed." >&2; exit 1 ;; esac

for attempt in 1 2 3; do
  read -rsp "Paste your Docker Hub access token with RIGHT-CLICK (input hidden), then press Enter: " token
  printf '\n'
  token=${token//$'\e[200~'/}; token=${token//$'\e[201~'/}
  token=$(printf '%s' "$token" | tr -cd 'A-Za-z0-9_-')
  [ ${#token} -ge 20 ] && break
  echo "That paste did not arrive (${#token} characters). Right-click inside this window to paste, then press Enter." >&2
  token=''
done
[ -n "$token" ] || { echo "No token received; nothing changed." >&2; exit 1; }

echo "Received username '$user' and a ${#token}-character token (${token:0:4}…${token: -4})."
echo "Checking them with the Docker Hub registry (the same check docker push uses)..."
# Credentials go to curl on stdin (-K -), so they never appear in the process list.
code=$(printf 'user = "%s:%s"\n' "$user" "$token" | curl -s -K - -o /dev/null -w '%{http_code}' -m 30 \
  "https://auth.docker.io/token?service=registry.docker.io&account=$user&scope=repository:$user/threat-intelligence-lab:push,pull" || true)
if [ "$code" != "200" ]; then
  echo "Docker Hub rejected the username/token (HTTP $code). Check that '$user' is your Docker Hub username and that the token" >&2
  echo "was copied whole (tokens start with dckr_pat_), then run this script again. Nothing changed." >&2
  exit 1
fi

gh variable set DOCKERHUB_USERNAME --body "$user" >/dev/null
printf '%s' "$token" | gh secret set DOCKERHUB_TOKEN >/dev/null
unset token
echo "Saved in GitHub: variable DOCKERHUB_USERNAME=$user and secret DOCKERHUB_TOKEN (encrypted)."
echo "Done: Docker Hub publishing is set up."
