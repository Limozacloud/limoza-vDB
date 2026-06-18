# CPE Dictionary

The NVD CPE (Common Platform Enumeration) dictionary is a **reference source**, not a
per-CVE source. It produces a local catalogue of all known CPE names which the pipeline
uses to (a) populate the standalone `cpe` table and (b) validate the CPEs that other
ingesters derive from product names. It does **not** write any `lve_*` record.

## NVD CPE API
- **URL:** `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- **Official:** Yes — NIST/NVD-maintained
- **Format:** NVD API 2.0 JSON, paged (`resultsPerPage=10000`, `startIndex` cursor)
- **Local path:** `cpe/cpe_raw.json` (full API dump), `cpe/cpe_dict.json` (compact index)
- **Sync:** two steps —
  - `sync cpe` downloads all ~1.7M CPE products page by page into `cpe_raw.json`.
    Keyed by `cpeNameId`. A `checkpoint.txt` records the current `startIndex` so an
    interrupted download resumes; it is deleted on completion. Rate is throttled to the
    NVD limit (5 req/30s without an API key, 50 req/30s when `NVD_API_KEY` is set);
    HTTP 403 triggers a 30s back-off and retry.
  - `sync cpe_index` (no download) reads `cpe_raw.json` and writes the compact
    `cpe_dict.json`. This is the file the rest of the pipeline reads.
- **Content:** one entry per CPE name: CPE 2.3 URI, type, vendor, product, version,
  English title, deprecation flag, created/last-modified timestamps.

## Index format

`sync_index()` keeps only CPE 2.3 URIs (`cpe:2.3:...`) with a non-empty vendor; entries
with a missing URI or an unrecognised format are skipped. Each surviving entry is stored
in `cpe_dict.json` as a positional array keyed by `cpeNameId`:

```
cpe_raw.json (cpeNameId → cpe object from NVD API)
├── cpeName            ✅ → cpe_dict[*][0]  cpe_uri      (must start with "cpe:2.3:")
├── (URI part 2)       ✅ → cpe_dict[*][1]  type
├── (URI part 3)       ✅ → cpe_dict[*][2]  vendor       (entry skipped if empty)
├── (URI part 4)       ✅ → cpe_dict[*][3]  product
├── (URI part 5)       ✅ → cpe_dict[*][4]  version
├── titles[lang=en]    ✅ → cpe_dict[*][5]  title_en
├── deprecated         ✅ → cpe_dict[*][6]  deprecated
├── created            ✅ → cpe_dict[*][7]  created
└── lastModified       ✅ → cpe_dict[*][8]  modified
                       ✗   refs / deprecatedBy / other API fields not retained

Legend: ✅ retained in index  ✗ not retained
```

## What it produces and how it is consumed

1. **`cpe` table** — `ingest.cpe.ingest()` loads every `cpe_dict.json` entry into the
   standalone `cpe` table (`cpe_name_id`, `cpe_uri`, `type`, `vendor`, `product`,
   `version`, `title_en`, `deprecated`, `created_at`, `modified_at`), upserting on
   `cpe_name_id`. This is an independent lookup table; it is **not** linked to LVE records.

2. **CPE validation** — `ingest.cpe.validate` builds an in-memory set of
   `(vendor, product)` pairs from `cpe_dict.json`. `validate.load()` is called once at
   ingest startup; `validate.is_valid(cpe)` then returns whether the `(vendor, product)`
   of a given CPE 2.3 URI exists in the dictionary. If the dictionary has not been loaded
   (no `cpe_dict.json` present), `is_valid()` returns `True` unconditionally so imports
   still run without CPE data.

   The only consumer of `is_valid()` is the **Microsoft** ingester
   (`ingest/microsoft/transform.py`): when a CPE derived from a Microsoft product name is
   not found in the dictionary, it is dropped (set to `None`) and a `cpe_not_found` notice
   is recorded. Other CSAF-based sources carry their CPE through unchanged and do not call
   the validator.

## Notes
- Two-phase sync: `sync cpe` (download) must run before `sync cpe_index` (build index).
  The ingest precondition checks for `{cpe}/cpe_dict.json`.
- The validator only checks the `(vendor, product)` pair — not the version or other CPE
  fields — so it confirms a product is known to NVD, not that a specific version exists.
- Deprecated CPEs are retained (the `deprecated` flag is preserved); validation does not
  exclude them.

## Schema Coverage

Schema Coverage: none — reference data only. The CPE module populates the standalone
`cpe` table and an in-memory `(vendor, product)` validator; it writes no fields of the
LVE record.
