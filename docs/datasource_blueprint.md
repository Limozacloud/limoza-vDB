# Datasource documentation blueprint

This page defines the conventions every `docs/datasources/<source>.md` page should
follow. Red Hat ([redhat.md](datasources/redhat.md)) is the reference implementation
— match its structure and level of detail when documenting a new source.

## What a source can write

A source maps its format onto the shared [data model](ingest/schema.md). Everything
is keyed by CVE id; a source writes into some subset of these tables:

```
cve                     the spine — every CVE id (ON CONFLICT DO NOTHING)
cve_record              CVE List baseline (one writer: cvelistv5)

per-CVE enrichment      (cve_id, origin, source, …) — many sources side by side
├── cve_cvss            version, base_score, severity, vector
├── cve_cwe             cwe_id  → cwe dictionary
├── cve_desc            lang, value
├── cve_ref             url, type
├── cve_solution        lang, value
├── cve_workaround      lang, value
├── cve_impact          capec_id, description
└── cve_alias           alias

advisories
├── advisory            (source, advisory_id) url, title, severity, dates, vendor_data
├── advisory_cve        advisory ↔ CVE links
└── cve_vendor          (cve_id, source) per-CVE assessment blob (data JSONB)

risk scoring            epss · kev · ssvc          (one row / CVE)
exploit intel           exploits                   (source, url, metadata)
dictionaries            cna · adp · cpe · cwe
```

> **`origin` vs `source`.** Enrichment rows carry `origin` (the importer — the unit
> of delete-and-replace on re-import) and `source` (who authored the data, for
> display). See the [pipeline overview](ingest/index.md#origin-vs-source).

## Page structure

Each `docs/datasources/<source>.md` should contain:

1. **Per-feed section** — `URL`, `Official`, `Format`, `Local path`, `Sync`,
   `Content` bullets (one block per feed if the source has several).
2. **Field-mapping tree** — a fenced ASCII tree of the source format, annotating each
   field with the table it lands in. Legend: `✅ imported`, `✗ not imported`, plus
   source-specific markers (e.g. `⊃ covered by another feed`).
3. **PURL** — the package URL format this source produces, where it emits package
   data (affected/fixed versions are a later phase, but the purl shape is worth
   documenting).
4. **Notes** — caveats, gaps, cross-source relationships (e.g. how this source feeds
   an [advisory tier](advisory-tiers.md)).
5. **Schema Coverage** — a checklist of the tables above with `✅ / ❌`, showing
   exactly which parts of the model this source writes.

Enrichment-only sources (EPSS, KEV, SSVC) and exploit-intel sources (Nuclei,
Metasploit, PoC-in-GitHub, Exploit-DB) write only a slice; their pages may omit the
PURL section where it does not apply, but should still include Schema Coverage so the
populated slice is explicit.

## Advisory sources & URLs

A source that issues bulletins should note its entry in
`ingest/advisories/source_urls.json` (the `cve_url` / `advisory_url` /
`when_id_prefix` templates), since those drive how the source appears in the
[advisory tiers](advisory-tiers.md).
