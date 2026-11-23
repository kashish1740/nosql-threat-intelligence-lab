# Presentation day: start-up checklist

**Submission links** (both always show the latest version):
- GitHub: https://github.com/kashish1740/nosql-threat-intelligence-lab
- Docker Hub: https://hub.docker.com/r/kashish1740/threat-intelligence-lab

To publish a change: `git add . && git commit -m "what changed" && git push` in Ubuntu. GitHub updates at once;
the Action (repo → Actions tab) tests, rebuilds and pushes the Docker Hub image within about 3 minutes
(`latest`, about 80 MB), then the all-in-one `full` image (about 2–3 GB) within about 15 minutes more.
Anyone can run the whole project with one command: `docker run -p 8000:8000 kashish1740/threat-intelligence-lab:full`.

Everything is already installed and saved: code, MongoDB data, the AI model, imported threat feeds and
your API keys (`.env`). Docker keeps the data between restarts, so start-up takes about a minute.

## Start (2 steps)

1. **Windows:** open **Docker Desktop** and wait until it shows *Engine running*.
2. **Ubuntu** (Start menu → Ubuntu), then run:

   ```bash
   cd ~/projects/NoSQL-Projects-main
   ./scripts/start-demo.sh
   ```

   It starts MongoDB, the web app and the AI model, waits until they answer, prints a status summary
   (everything should say `OK`) and opens **http://localhost:8000** in your browser.

## MongoDB Compass

| Connect to | For |
|---|---|
| `mongodb://localhost:27018` | Web app data: `threat_lab` (Threat Assistant, PC scans in `pc_scans`) and `threat_intelligence` (URL Threat Analysis) |
| Chapter page → *Inspect in MongoDB Compass* | Lab data `college_chNN` — run that chapter first, e.g. `./scripts/lab.sh ch10 --mode quick` |

Lab ports: standalone 27019 · replica set 27031–27033 · sharded 27034 · auth/TLS 27035 · secure 27036–27038 · polyglot 27039.
Ch 12–13 need TLS: CA file `\\wsl.localhost\Ubuntu\home\lenovo\projects\NoSQL-Projects-main\.secrets\ca.crt`,
password from `cat ~/projects/NoSQL-Projects-main/.secrets/password` (keep it off screen).

## Demo order (about 15 minutes)

1. **Overview** page — the project at a glance: 18 experiments, threat indicators, services.
2. **URL Threat Analysis** — analyse `https://morkovka.cn/qqkb/` (ThreatFox + VirusTotal), then
   `https://waterforvoiceless.org/invite.php` (Botvrij + VirusTotal, duplicates removed), then
   `https://www.wikipedia.org/` (no known threats). Download the report. Show `url_analyses` and
   `threat_findings` in Compass. VirusTotal's free key allows about 2 analyses per minute.
3. **Threat Assistant** — search `openssh`; ask “Which active Linux threats in this dataset need attention?”,
   then “What should I do about the first one?”, then “What is the weather in Tokyo?”.
   **Scan this PC:** in Windows PowerShell, in the project folder, run
   `powershell -ExecutionPolicy Bypass -File .\scripts\scan-pc.ps1` (read-only: Defender, firewall, Windows updates,
   installed programs, network). Open **My PC**, then ask the assistant “What threats are on my PC right now?”,
   “How do I fix the first one?” and “Is Defender protecting my PC and is my firewall on?”. In Compass: `threat_lab.pc_scans`.
4. **Experiments** — open chapters and use their *Overview*, *Implementation* and *Results* tabs.
   Optionally run one live (e.g. Ch 10 or Ch 11) and show its database in Compass.
   Run one lab topology at a time and stop it with the command shown on its page.

## Chapters 13–18 (platform features)

**Demo sign-in** (bottom of the sidebar, no passwords): `demo-admin` (Operations), `demo-moderator` (Moderation),
`aurora-admin` and `aurora-analyst` (organisation *Aurora Security*), `borealis-analyst` (*Borealis Labs*).
The sidebar only shows what the signed-in role may use; the server checks every request again (wrong role → 403).
**Course tour** (sidebar) lists chapters 7–18 with their live status and links.

These pages need their lab running. **Run one lab topology at a time** (RAM) and stop it with the command on its page:

| Chapter | Start in Ubuntu first | Where | What to show (about 2 min each) |
|---|---|---|---|
| 13 Secure deployment | `./scripts/lab.sh ch13 --mode quick` | Operations → Deployment | As **demo-admin** press **Test failover**: a new PRIMARY within ~1 s and an "elected" marker on the state chart within 10 s. Kubernetes and Atlas cards explain what they need. |
| 14 Monitoring & backup | `./scripts/lab.sh ch14 --mode quick` | Operations → Monitoring & backups | Tiles and charts with the 80 % / 10 s threshold lines. **Back up now**, then **Verify restore** (every document compared, RTO and RPO). Optional: `./scripts/partition.sh` raises lag WARNINGs → as **demo-moderator** acknowledge them in Moderation → Alerts. |
| 15 Cases | nothing (built into the app) | Cases | As **aurora-analyst**: Threat Assistant → open an advisory → **Open case**. As **aurora-admin**: the case is in *All cases*, change status/assignee. As **borealis-analyst**: it does not exist. Rapid requests → 429 with the retry time (30/min). |
| 16 Cassandra & Neo4j | `./scripts/lab.sh ch16 --mode quick` | Operations → Audit log; Moderation → Fraud review | Audit log from Cassandra with a 7-day chart. Exactly-once: stop Cassandra, sign in twice (the page shows "2 events waiting"), start it, both appear once. Fraud review: click **U1** → MongoDB transaction, Cassandra profile, Neo4j ring, breaker states. |
| 17 Ask | nothing (index already built: 1,372 pages) | Ask the reports | As **aurora-analyst** ask “Which reports mention Cobalt Strike?” then “and in 2022?” (memory + year filter). Every [n] links to its report and page; Forget history. |
| 18 False positives | `./scripts/lab.sh ch16 --mode quick` (same topology) | Moderation → False positives; Operations → Sources / Lab 18 | As **demo-moderator** press **Sync to Cassandra & Neo4j**, open a candidate (or look up `163.com`): three verdicts + 2-of-3 vote → **Confirm false positive**; it leaves **Export CSV** as "reviewed false positive"; **Clear decision** brings it back. Sources: FP rate per feed, family pairs, precision/recall per database, printable report. |

Lab databases are reached through their published ports (no Docker socket in the app), so pages show the start
command instead of a Start button. Re-index Ask after new Botvrij data: Operations → Ask index → **Index the reports**.

## Before you go on stage

- Run the three demo URLs once beforehand (warms up the sources; past reports stay in MongoDB).
- Keep the laptop plugged in and stop it from sleeping; keep Docker Desktop open.
- Take screenshots as a fallback in case the internet fails (Botvrij data and saved reports still work offline).

## If something goes wrong

| Problem | Fix |
|---|---|
| `Docker is not reachable` | Start Docker Desktop, wait for *Engine running*, rerun the script |
| Page does not load | `docker compose logs --tail=50 app`, then rerun `./scripts/start-demo.sh` |
| Model shows unavailable | `docker compose exec ollama ollama pull qwen2.5:1.5b` |
| VirusTotal “rate limit” | Wait one minute (free key: 4 lookups/minute) |
| A key shows missing | `./scripts/set-api-key.sh virustotal` or `./scripts/set-api-key.sh abusech` |
| Out of memory during a lab | Stop other lab topologies (command on each chapter page) |
| A Ch 13–18 page says the lab is stopped | Run the start command it shows; Cassandra needs about a minute after start |
| Ask answers “extractive” | The model was loading; ask again (it stays loaded for 30 min after a question) |
| Audit log shows “events waiting” | Lab 16 (Cassandra) is stopped; events are delivered exactly once when it starts |
| “Sign in first” | Choose a demo identity at the bottom of the sidebar and press Sign in |

## Stop after the presentation

```bash
cd ~/projects/NoSQL-Projects-main
docker compose --profile model down     # keeps all data; never add -v (that deletes it)
```

The copy that runs is the Ubuntu one, `~/projects/NoSQL-Projects-main`. The Windows folder
`Downloads\NoSQL-Projects-main\NoSQL-Projects-main` holds the same code.
