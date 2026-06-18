# NVD / NIST

NVD is the **CVE baseline**. It is the only source that writes the `cve{}` spine —
`status`, `published`, and `updated` — for every record. Other vendors only seed
`cve.cve_id`; the authoritative CVE lifecycle metadata comes from here.

## NVD CVE API 2.0
- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Official:** Yes — NIST-maintained
- **Format:** JSON (NVD API 2.0); one `cve` object saved per file
- **Local path:** `nvd/api/<year>/<CVE-ID>.json`
- **Sync:** full download on first run (~300k CVEs); incremental afterwards via `lastModStartDate`/`lastModEndDate`, with the last sync time stored in `nvd/last_modified.txt`. Sliding-window rate limit: 5 req/30s without key, 50 req/30s with `NVD_API_KEY`.
- **Content:** authoritative CVE registry — English description, CVE status, published/modified dates, CVSS scores (multiple versions and sources), CWE IDs, and reference URLs with tags.

```
cve/
├── id                                  ✅ → aliases[] + cve.cve_id
├── vulnStatus                          ✅ → cve.status  (mapped, see State mapping)
├── published                           ✅ → cve.published + history[].date (advisory_added)
├── lastModified                        ✅ → cve.updated + history[].date (advisory_updated, if ≠ published)
├── descriptions[]/
│   └── [lang=en].value                 ✅ → descriptions[].value  (first en only)
├── metrics/
│   ├── cvssMetricV40[].cvssData/
│   │   ├── baseScore                   ✅ → cvss[].score   (skipped if falsy)
│   │   ├── vectorString                ✅ → cvss[].vector
│   │   ├── baseSeverity                ✅ → cvss[].severity (mapped)
│   │   └── (version → "4.0")           ✅ → cvss[].version
│   ├── cvssMetricV31[]                  ✅ → cvss[]  (version "3.1")
│   ├── cvssMetricV30[]                  ✅ → cvss[]  (version "3.0")
│   ├── cvssMetricV2[]                   ✅ → cvss[]  (version "2.0")
│   └── [].source                       ✅ → cvss[].source  (default "nvd@nist.gov")
├── weaknesses[]/
│   └── description[]/
│       └── [lang=en].value             ✅ → cwes[].id  (only values starting "CWE-", deduped)
├── references[]/
│   ├── url                             ✅ → references[].url
│   └── tags[]                          ✅ → references[].type  (first mapped tag, else "web")
├── configurations[]                    ✗  CPE applicability trees not parsed
├── cisaExploitAdd / cisaActionDue      ✗  KEV handled by CISA-KEV vendor
└── vendorComments[] / cveTags[]        ✗
```

Legend: ✅ imported  ✗ not imported

## PURL
NVD emits **no PURL and no CPE**. The `configurations[]` CPE applicability trees are
present in the source but are not parsed by the transform, so no `packages[]` or
package identifiers are produced. NVD contributes CVE metadata only.

## State mapping

NVD has no package fix data, so there is no `affected_state` / `remediation_state`
mapping. The only state it maps is the CVE lifecycle status:

| `vulnStatus` (raw) | `cve.status` |
|---|---|
| `Analyzed`, `Modified`, `Published` | `cve_assigned` |
| `Awaiting Analysis`, `Undergoing Analysis`, `Received`, `Deferred` | `cve_pending` |
| `Rejected` | `cve_rejected` |
| `Reserved` | `cve_reserved` |
| (anything else / missing) | `cve_pending` (default) |

CVSS `baseSeverity` is mapped `CRITICAL→critical`, `HIGH→high`, `MEDIUM→medium`,
`LOW→low`, `NONE→informational`.

Reference `tags` are mapped: `Patch→patch`; `Vendor Advisory` /
`Third Party Advisory` / `Mitigation → advisory`; `Release Notes` / `Mailing List` /
`Technical Description` / `Press/Media Coverage → article`; `Issue Tracking → report`;
`VDB Entry` / `Exploit → web`; unmapped → `web`.

## Notes
- NVD is the **only** source that writes `cve.status`, `cve.published`, and `cve.updated`. Vendor sources seed `cve.cve_id` only; they never overwrite the spine.
- CVSS source field distinguishes the scorer: `nvd@nist.gov` = NVD re-score, any other value = original CNA score. Both are kept.
- A CVSS entry with a falsy `baseScore` is skipped entirely.
- `vulnStatus=Rejected` maps to `cve_rejected` — downstream code should not surface rejected CVEs to the scanner.
- NVD frequently lags publication; `Awaiting Analysis` (→ `cve_pending`) is common for recent CVEs.
- The transform never emits `titles[]`, `advisories[]`, `upstream[]`, `packages[]`, `mitigations[]`, `impacts[]`, or `exploits[]`.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve.id]
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  cve.id
│   ├── status                   ✅  cve.vulnStatus → mapped (NVD authoritative)
│   ├── published               ✅  cve.published   (NVD authoritative)
│   ├── updated                 ✅  cve.lastModified (NVD authoritative)
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA-KEV vendor
│   └── ssvc{}                   ❌  CISA-SSVC vendor
│
├── titles[]                     ❌  not written
├── descriptions[]              ✅  descriptions[lang=en].value (first only)
├── cvss[]                       ✅  metrics.cvssMetricV40/V31/V30/V2[].cvssData.*
├── cwes[]                       ✅  weaknesses[].description[lang=en] (CWE-* only); name = null
├── references[]                 ✅  references[].url + mapped tag → type
│
├── advisories[]                 ❌  not written
├── upstream[]                   ❌  not written
│
├── packages[]                   ❌  not written — configurations[] CPE trees not parsed
│
├── mitigations[]                ❌  not written
├── impacts[]                    ❌  not written
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  published (advisory_added) / lastModified (advisory_updated)
    ├── event                    ✅  advisory_added / advisory_updated
    ├── source                   ✅  "nvd"
    └── detail                   ✅  CVE-ID
```
