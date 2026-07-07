# Node.js

The Node.js Security Working Group publishes the authoritative machine-readable database of
**Node.js core** (runtime) vulnerabilities. It is the version-precise source for the Node.js
runtime, which GHSA/OSV don't carry (node core is not an npm package) and which NVD often only
enumerates as sample versions rather than a proper range.

## security-wg / vuln/core
- **URL:** `https://github.com/nodejs/security-wg` (path `vuln/core`)
- **Official:** Yes — maintained by the Node.js Security WG
- **Format:** JSON — one entry per advisory in `vuln/core/index.json`
- **Local path:** `nodejs/vuln/core/` (sparse shallow clone; `git pull` is the incremental)
- **Sync:** `vdb sync nodejs` (member of the `advisories` group)
- **Content:** per advisory — the CVE id(s), affected/patched release lines, severity, a link
  to the security-release blog post, and a description

Each entry gives the fix **per release line** in `patched`, e.g.:

```json
{
  "cve": ["CVE-2026-48930"],
  "vulnerable": "22.x || 24.x || 26.x",
  "patched": "^22.23.0 || ^24.17.0 || ^26.3.1",
  "ref": "https://nodejs.org/en/blog/vulnerability/june-2026-security-releases",
  "severity": "medium",
  "overview": "A flaw in Node.js TLS hostname handling …"
}
```

```
vuln/core/index.json entries[]
├── cve[]                    ✅ → cve spine (skipped when empty — no join key)
├── overview | description   ✅ → cve_desc.value                (origin=nodejs)
├── severity                 ✅ → cve_vendor.data.severity      (source=nodejs)
├── ref                      ✅ → cve_vendor.data.ref → L3 downstream link (cve_levels)
├── description              ✅ → cve_vendor.data.description
└── patched (per line)       ✅ → affected (coord=cpe) — one range row per release line
                                  "^24.17.0" → introduced 24.0.0, fixed 24.17.0

Legend: ✅ imported  ✗ not imported
```

## PURL / CPE

Node.js core is matched in the **CPE lane** against the NVD-validated
`cpe:2.3:a:nodejs:node.js` product. The `patched` field's per-line fixes become one
`affected` row per release line (`introduced = <major>.0.0`, `fixed = <patch>`,
`version_scheme = generic`). These rows **coexist** with NVD's for the same `cpe23` (NVD
collapses the fix to the mainline version, e.g. `fixed 3.15`-style); the matcher ORs both
lanes and the reach-any-fix logic lets a host on a patched line (e.g. Node 24.17.0) clear
NVD's broader row.

## Notes

- `severity` and `ref` fill real gaps: Node rates a CVE (and links the specific
  security-release blog post) often before NVD assigns a CVSS.
- Entries without a CVE id (older, pre-CVE Node advisories) are skipped — the CVE id is the
  only join key.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  overview / description  (origin=nodejs)
cve_vendor         ✅  {severity, ref, description}  (source=nodejs) → L3 tracked (cve_levels via data.ref)
cve_cvss           ❌
cve_cwe            ❌
advisory           ❌  node links a blog post, not a formal advisory id
affected           ✅  coord=cpe — per-release-line fix ranges for cpe:2.3:a:nodejs:node.js
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
