# Ingest

The ingest pipeline fetches vulnerability data from many upstream sources and
writes it into the shared [data model](schema.md). Every source keeps its own
rows — there is no merge step and no record that one source owns.

## Pipeline architecture

| Stage | Description |
|-------|-------------|
| **Sync** | Fetch raw data from a source's API/feed/git and store it under `/data/<source>` |
| **Transform** | `parse()` + `transform()` in each source module map the raw format to rows |
| **Write** | `ingest.run` writes the rows; the `cve` spine is filled with `ON CONFLICT DO NOTHING` |

Run the CLI with a **target** — either a single source key or a group:

```
vdb sync                 # all sources
vdb sync redhat epss     # specific sources
vdb sync advisories      # a whole group
vdb ingest all           # write everything that was synced
```

| Group | Members |
|-------|---------|
| `reference` | `cna`, `cpe`, `cwe`, `source_urls` |
| `records` | `cvelistv5` |
| `scoring` | `epss`, `kev`, `ssvc` |
| `advisories` | `redhat`, `suse`, `ubuntu`, `debian`, `oracle`, `almalinux`, `rocky`, `microsoft`, `ghsa`, `osv` |
| `exploits` | `exploitdb`, `metasploit`, `nuclei`, `poc_github` |

See the [Ingest CLI](../running/cli.md) reference and the
[data source pages](../datasources/index.md) for the full list.

## Source module structure

Each source is a module directory under `ingest/` exposing two entry points:

| Function | Signature | Role |
|----------|-----------|------|
| `sync.run(dirs)` | → `int` \| `None` \| `{"status": "no_new_data", ...}` | download raw data; return item count, or a gate result if the source is unchanged |
| `ingest.run(conn, dirs)` | → `int` | parse the downloaded data and write rows |

Most sources also have a `transform.py` that turns one raw document into row
tuples. Source modules never log or count themselves — `ingest/run.py` wraps every
phase: it times it, records a `sync_log` row, and isolates failures so one source
erroring never aborts the rest.

## `origin` vs `source`

The per-CVE enrichment tables (`cve_cvss`, `cve_cwe`, `cve_ref`, …) carry two
provenance columns:

| Column | Meaning |
|--------|---------|
| `origin` | the **importer** that wrote the row — used to delete-and-replace that importer's slice on re-import |
| `source` | who **authored** the data, for display — `cna`, an ADP short name, a distro name, … |

`origin` is the unit of idempotency; `source` is provenance for the reader.

## Import order

Sources can be imported in **any order** — the model is order-independent. The
`cve` spine is a shared registry filled with `INSERT … ON CONFLICT DO NOTHING`, so
whoever sees a CVE id first creates the spine row and everyone else is a no-op. No
source writes another source's rows, so there is nothing to overwrite.

## Identity & normalization

The join key is the **CVE id**, validated by a `CHECK` constraint
(`^CVE-[0-9]{4}-[0-9]+$`). Importers pass every id through `core.cveid.normalize`
at the boundary, so casing and Unicode hyphen variants can never split a CVE into
two rows.

## Idempotent re-imports

Re-running a source is safe and leaves the database matching the upstream feed:

- **Advisory sources** delete their own slice (`delete_scope`) — their `cve_*` rows
  by `origin`, plus their `advisory` / `advisory_cve` / `cve_vendor` rows by
  `source` — then reinsert. The swap holds a row-level lock only, so the API stays
  readable throughout.
- **Snapshot sources** (KEV, SSVC, exploits) rebuild with `DELETE + INSERT` so
  withdrawn upstream entries disappear.
- **Append-only sources** (EPSS, CPE, CWE, CNA) `UPSERT` — entries are re-scored or
  deprecated, never deleted.

Every run's outcome — `success`, `no_new_data`, or `failed`, with row deltas and a
human-readable message — lands in `sync_log`, which powers the freshness and error
views.
