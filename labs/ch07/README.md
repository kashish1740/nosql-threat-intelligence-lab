# Chapter 7: Cyber threat analysis, threat schema and working set

**Activity 3 — URL threat analysis:** submit any URL on the dashboard (Lab Experiments → CH07 → Threat Analysis). It is checked against URLhaus, ThreatFox and the Botvrij.eu OSINT feed, and analysed for vulnerabilities with GCVE (db.gcve.eu). Both analyses are merged with duplicate findings removed, shown as a report, and stored in MongoDB `threat_intelligence` (Compass: `mongodb://localhost:27018`). See `activity_03_url_threat_analysis/README.md`.

Activities 1–2: shared threat application, BSON sizes, alternative references, random reads and ten-second cache samples; report archive and optional newer-link check.

```bash
./scripts/lab.sh ch07 --mode quick
./scripts/lab.sh ch07 --mode full
./scripts/lab.sh ch07 --activity 3 --mode quick   # URL threat analysis only
```

Expected observable behavior: labeled JSON events containing actual database results, counts and measurements. Failed assertions produce a failed result. Missing optional credentials are reported as partial, never successful external verification. Evidence: `results/ch07/<UTC-run-id>/result.json`, plus chapter-specific plots/explains/logs when applicable.

See [lab instructions](../README.md) for topology stop commands and supplementary activities. See `activity_*` folders for Python entrypoints. Full mode is required for the rubric's graded dataset sizes. This implementation has not yet been executed against live database services in the restricted development session.
