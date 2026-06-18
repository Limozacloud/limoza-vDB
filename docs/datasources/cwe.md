# CWE Dictionary

The CWE (Common Weakness Enumeration) dictionary is a **reference source**, not a
per-CVE source. It produces a local CWE-id → weakness-name lookup that the pipeline uses
to enrich `lve_cwes` rows when a source supplies a CWE id but no human-readable name. It
does **not** produce LVE records of its own.

## CWE-CAPEC REST-API-wg (json_repo/W)
- **URL:** `https://github.com/CWE-CAPEC/REST-API-wg`
- **Official:** Yes — MITRE CWE/CAPEC working-group repository
- **Format:** one JSON file per weakness under `json_repo/W/` (`*.json`)
- **Local path:** `cwe-db/json_repo/W/*.json`
- **Sync:** sparse `git` clone (`--depth=1 --filter=blob:none --sparse`) restricted to the
  `json_repo/W` directory; on subsequent runs the sparse-checkout set is re-applied and
  the repo is updated with `git pull --ff-only`. After sync it prints the number of
  weakness definitions found.
- **Content:** each file holds a weakness definition; only the `ID` and `Name` fields are
  used by the pipeline.

## Lookup format

`ingest.cwe._load()` reads every `json_repo/W/*.json` file once and builds an in-memory
map (cached for the process):

```
json_repo/W/<n>.json
├── ID    ✅ → key   "CWE-<ID>"
├── Name  ✅ → value weakness name
└── (all other fields)  ✗ not read

Legend: ✅ used  ✗ not used
```

Files that fail to parse are silently skipped. If `json_repo/W` does not exist, the
lookup is an empty map.

## What it produces and how it is consumed

`ingest.cwe.lookup("CWE-NNN", dirs)` returns the weakness name for a given CWE id, or
`None` if it is not in the dictionary.

The sole consumer is the database writer (`ingest/db.py`): when inserting `lve_cwes`
rows, the name written is `c.get("name") or _cwe_name(c["id"])` — i.e. the source-supplied
name is used if present, otherwise the CWE dictionary is consulted as a fallback. The
lookup directory comes from the `CWE_DB_DIR` environment variable. This only fills the
`name` column of `lve_cwes`; the CWE id and the row itself originate from the per-CVE
source (Red Hat, NVD, etc.), not from this module.

## Notes
- This is enrichment-only: it never creates `lve_cwes` rows, it only supplies the `name`
  for rows other sources already emit (and only when that source left the name blank).
- Only `json_repo/W/` (Weaknesses) is synced — Categories, Views, and CAPEC data in the
  upstream repo are not fetched.
- The lookup map is cached on first use for the lifetime of the ingest process.

## Schema Coverage

Schema Coverage: none — reference data only. The CWE module owns no LVE record fields; it
only provides the fallback `name` value for `lve_cwes` rows whose id and source come from
other datasources.
