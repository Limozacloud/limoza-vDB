# Limoza Schema

All vendor data is normalized to a single JSON schema defined in `limoza_schema.json` (repository root; embedded in full below).

One record per vulnerability. The `lve_id` is the stable vendor-neutral identifier; all other fields are populated by one or more vendor sources.

The canonical, machine-readable definition is `limoza_schema.json` (JSON Schema draft 2020-12) at the repository root. The relational layout it maps to lives in `schema.sql`. The sections below are the human-readable reference — when in doubt, the JSON Schema file is authoritative.

??? note "Full JSON Schema (`limoza_schema.json`)"

    ```json
    --8<-- "limoza_schema.json"
    ```

---

## Top-level Fields

### `lve_id`

```
Type: string  Pattern: ^LVDB-[0-9]{8}$
```

Auto-generated sequential identifier. Never derived from CVE or vendor IDs. Assigned by PostgreSQL trigger on first insert.

Examples: `LVDB-00000001`, `LVDB-00012345`

---

### `aliases`

```
Type: string[]
```

All known identifiers for this vulnerability — CVE IDs, vendor advisory IDs, GHSA IDs, etc. Always uppercase. Accumulated across all sources; no source discriminator.

Examples: `["CVE-2023-27533", "GHSA-JFH8-C2JP-HDPQ", "RHSA-2023:1234", "ADV240001"]`

Used for lookup: `_get_or_create_lve()` matches incoming records against existing LVEs via `aliases && %s::text[]`.

---

### `has_exploit`

```
Type: boolean  Default: false
```

True when `exploits[]` is non-empty. Maintained as a derived flag for fast filtering without joining `lve_exploits`.

---

### `cve`

```
Type: object | null
```

CVE data from MITRE/NVD. `null` for vulnerabilities without a CVE (vendor-only advisories like Microsoft ADV, BSI WID). **Only NVD writes this object.**

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier, e.g. `CVE-2023-27533` |
| `status` | enum | `cve_assigned` · `cve_reserved` · `cve_pending` · `cve_rejected` |
| `published` | datetime | CVE publication date from MITRE |
| `updated` | datetime | Last-updated timestamp from MITRE |
| `epss` | object\|null | FIRST EPSS score (`score`, `percentile`, `date`) |
| `kev` | object\|null | CISA KEV entry (`date_added`, `due_date`, `known_ransomware`, `required_action`) |
| `ssvc` | object\|null | CISA SSVC triage (`exploitation`, `automatable`, `technical_impact`) |

Stored in the separate `lve_cve` table (1:1 with `lve`). All fields use `COALESCE(EXCLUDED.x, lve_cve.x)` on conflict so the last non-null write wins.

---

### `titles`

```
Type: array  Unique by: (source)
```

| Field | Type | Description |
|-------|------|-------------|
| `value` | string | The title text |
| `source` | string | Who provided it: `nvd`, `microsoft`, `redhat`, … |
| `advisory` | ref\|null | `{"@id": "..."}` linking to `advisories[]` |

---

### `descriptions`

```
Type: array  Unique by: (source)
```

Same structure as `titles`. HTML is stripped during transform.

---

### `cvss`

```
Type: array  Unique by: (vector, source)
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | enum | `2.0` · `3.0` · `3.1` · `4.0` |
| `score` | number | 0–10 |
| `vector` | string | Full CVSS vector string |
| `severity` | enum\|null | `critical` · `high` · `medium` · `low` · `informational` |
| `source` | string | Scoring authority |
| `advisory` | ref\|null | Link to advisory |

---

### `cwes`

```
Type: array  Unique by: (id, source)
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | e.g. `CWE-122`; joins to the `cwe` dictionary table for the full weakness definition |
| `name` | string\|null | Human-readable name when provided; else filled from the CWE dictionary |
| `source` | string | Who classified it |
| `advisory` | ref\|null | Link to advisory |

The shared weakness definition (mitigations, consequences, likelihood, …) is **not**
duplicated per record — it lives once in the `cwe` dictionary table, populated on-reference
from the [CWE source](../datasources/cwe.md) and keyed by `id`.

---

### `references`

```
Type: array  Unique by: (url)
```

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Link target |
| `type` | enum | `patch` · `advisory` · `article` · `fix` · `report` · `web` |
| `source` | string | Who added the reference |
| `advisory` | ref\|null | Link to advisory |

---

### `advisories`

```
Type: array  Unique by: (@id)
```

Vendor advisories covering this vulnerability. The `@id` is the cross-reference anchor used by `titles[]`, `descriptions[]`, `cvss[]`, `cwes[]`, `packages[]`.

| Field | Type | Description |
|-------|------|-------------|
| `@id` | string | Advisory identifier, e.g. `RHSA-2023:1234`, `2024-Apr` |
| `source` | string | Vendor |
| `url` | string\|null | Advisory URL |
| `published` | datetime\|null | |
| `updated` | datetime\|null | |
| `packages` | string[] | PURLs covered by this advisory within this LVE |
| `vendor_data` | object\|null | Vendor-specific fields with no universal equivalent |

---

### `packages`

```
Type: array  Unique by: (purl, source)
```

Affected and fixed packages across all distros and ecosystems. The `purl` identifies
the package **without** a version — version information lives in `ranges[]`.

The fix state is modelled on **two orthogonal axes**: `affected_state` answers "is this
package affected?" and `remediation_state` answers "is a fix available?". A package can
be `affected_state=affected` and `remediation_state=fixed` at the same time.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string\|null | Human-readable package name, e.g. `kernel`, `curl` |
| `purl` | string | Package identity without version |
| `affected_state` | enum | `affected` · `not_affected` · `not_applicable` · `unknown` |
| `remediation_state` | enum | `fixed` · `will_not_fix` · `pending` · `none` · `unknown` |
| `status_raw` | string\|null | Original vendor status string before normalisation |
| `vex_justification` | string\|null | VEX "not affected" reason (CSAF `flags[].label` / OpenVEX) |
| `ranges` | array\|null | OSV-style `[{type, events[{introduced\|fixed\|last_affected}]}]`; null for not_affected/unknown |
| `source` | string | Who reported this fix |
| `advisory` | ref\|null | Link to advisory |
| `upstream` | ref\|null | Link to `upstream[]` entry |
| `severity` | enum\|null | Vendor-assessed severity for this package |
| `vendor_data` | object\|null | Vendor-specific fields, e.g. `cpe`, `is_backport` |

---

### `upstream`

```
Type: array  Unique by: (@id)
```

Upstream project fix information (PURL, `fix_version`, `fix_commit`, `ranges[]`, `versions[]`). Distro packages reference their upstream via `packages[].upstream`. Populated mainly by GHSA and OSV.

---

### `mitigations`

```
Type: array  Unique by: (source, advisory)
```

Workarounds and mitigation steps that reduce risk without applying a patch.

| Field | Type | Description |
|-------|------|-------------|
| `value` | string | Free-text mitigation/workaround instructions |
| `source` | string | Who provided it |
| `advisory` | ref\|null | Link to advisory |
| `purls` | string[]\|null | PURLs this mitigation applies to; null = all packages |

---

### `impacts`

```
Type: array  Unique by: (source, advisory)
```

Descriptions of what an attacker can concretely achieve, beyond the CVSS vector
(from CSAF `threats[category=impact]` and vendor statement notes).

| Field | Type | Description |
|-------|------|-------------|
| `value` | string | Free-text impact description |
| `source` | string | Who provided it |
| `advisory` | ref\|null | Link to advisory |

---

### `exploits`

```
Type: array  Unique by: (url)
```

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | `metasploit` · `exploitdb` · `poc_github` · `nuclei` |
| `source_id` | string\|null | Source-internal ID |
| `name` | string\|null | Module/script name |
| `url` | string | Link to exploit artifact |
| `metadata` | object | Source-specific metadata |

---

### `history`

Append-only log of changes to this LVE. Written only on first insert (`is_new=True`).

| Event | Meaning |
|-------|---------|
| `created` | LVE first seen |
| `cve_assigned` · `cve_rejected` | CVE state changes |
| `advisory_added` · `advisory_updated` | Vendor advisory ingested / changed |
| `vex_published` · `vex_updated` | VEX document published / revised |
| `affected_state_changed` · `remediation_state_changed` | Package state updated |
| `severity_changed` · `cvss_updated` | Scoring changes |
| `kev_added` · `kev_removed` · `epss_updated` · `ssvc_updated` | Enrichment changes |
| `exploit_added` | New exploit artifact found |
| `description_updated` · `status_changed` | Other updates |

Full event enum: see `history.event` in the embedded `limoza_schema.json` above.
