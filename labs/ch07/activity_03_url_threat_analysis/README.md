# URL Threat Analysis

Analyse any URL for cyber threats and produce a report. Open the dashboard at
http://localhost:8000, go to **Lab Experiments → CH07 → Threat Analysis**, paste a URL and press **Analyse**.

## Two analyses, one report

1. **Threat-feed analysis**
   - **URLhaus** (urlhaus.abuse.ch): live API lookup of the exact URL and of its host.
   - **ThreatFox** (threatfox.abuse.ch): its search API cannot look up full URLs, so the last 7 days of
     IOCs are imported into MongoDB (`threatfox_indicators`, refreshed every 6 h) and matched locally by
     exact URL, host and resolved IP; the host/IP is also searched live across ThreatFox's full history.
   - **VirusTotal** (optional `VT_API_KEY`): reads existing URL and domain/IP reports and weighs them by how
     many engines agree. URLs are never submitted, so nothing you analyse is published.
   - **Botvrij.eu OSINT feed** (botvrij.eu/data/feed-osint): every MISP event is imported into MongoDB
     (`botvrij_indicators`, `botvrij_events`) and matched locally by exact URL, host, parent domain and
     the IPs the host resolves to. Only changed events are re-downloaded (every 24 h or with *Refresh feed*).
2. **Vulnerability analysis with GCVE** (db.gcve.eu)
   - products recognised from the URL (WordPress, Exchange, FortiOS, Confluence, …) with their known
     vulnerabilities as version-dependent context;
   - GCVE *sightings* whose source is this page or host (exploits, proofs of concept, mentions);
   - every CVE found by either analysis is enriched with title, CVSS, EPSS and known-exploited (KEV) status.

## Duplicate removal

Findings from both analyses get a canonical key: `ioc:url:<normalised url>`, `ioc:host:<host>` or
`vuln:<CVE id>`; GHSA/OSV aliases fold into their CVE. A URL listed by URLhaus *and* Botvrij, or a CVE
tagged in ThreatFox *and* found in GCVE, becomes one finding that lists every source. The report shows
raw findings, unique findings and the number of duplicates removed.

## MongoDB storage (open in Compass: `mongodb://localhost:27018`)

| Collection (database `threat_intelligence`) | Contents |
|---|---|
| `url_analyses` | one full report per analysis (verdict, score, both analyses, merged findings) |
| `threat_findings` | one document per unique finding across all analyses; sources and URLs are `$addToSet`, so repeats never duplicate |
| `botvrij_indicators`, `botvrij_events` | imported Botvrij.eu OSINT feed |
| `feed_status` | last sync state of each feed |

## Keys

URLhaus and ThreatFox require a free abuse.ch Auth-Key since 2025 (their old public downloads return
HTTP 410). Create one at https://auth.abuse.ch/, put `ABUSECH_AUTH_KEY=<key>` in the project `.env`,
then restart the app with `docker compose --profile model up -d`. Without it those two sources are
reported as *Not configured*; Botvrij.eu and GCVE still run.

## Safety and limits

The submitted URL is never fetched; only intelligence sources are queried (plus a DNS lookup of the host).
"No known threats" means no source has reported the URL, not that it is safe.

## Lab run

```bash
./scripts/lab.sh ch07 --activity 3 --mode quick
```

The lab run analyses a sample URL against the lab MongoDB and records the verdict, sources checked and the
de-duplication counts in `results/ch07/<run>/result.json`. Set `CTI_SAMPLE_URL` to choose the URL.
