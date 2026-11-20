# Threat Intelligence Lab — NoSQL / MongoDB final project

A FastAPI dashboard backed by MongoDB for a NoSQL course: 18 MongoDB lab chapters, a threat-advisory assistant
with a local LLM, URL threat analysis (URLhaus, ThreatFox, Botvrij.eu, VirusTotal, GCVE) and Chapter 13–18
platform features — replica-set deployment and failover, monitoring and verified backups, multi-tenant cases,
a Cassandra audit log, fraud review across MongoDB/Cassandra/Neo4j, cited "Ask the reports" answers and
three-database false-positive review.

**Source code:** https://github.com/kashish1740/nosql-threat-intelligence-lab
This image is rebuilt and published automatically on every push to that repository's `main` branch.

## Run it

```bash
curl -O https://raw.githubusercontent.com/kashish1740/nosql-threat-intelligence-lab/main/compose.hub.yaml
docker compose -f compose.hub.yaml --profile model up -d
docker compose -f compose.hub.yaml exec ollama ollama pull qwen2.5:1.5b   # once, about 1 GB
```

Open **http://localhost:8000**. MongoDB Compass: `mongodb://localhost:27018`.
Sign in with a demo identity at the bottom of the sidebar (`demo-admin`, `demo-moderator`, `aurora-analyst`, …).

The lab chapters themselves (replica sets, sharding, TLS, Cassandra, Neo4j) run from the source repository with
`./scripts/lab.sh chNN --mode quick`; their pages in the dashboard explain how.

## Tags

- `latest` — newest build of `main`
- `sha-<commit>` — one tag per commit, to run an exact version

Optional API keys for URL analysis (`VT_API_KEY`, `ABUSECH_AUTH_KEY`) go in a local `.env` file; none are in the image.
