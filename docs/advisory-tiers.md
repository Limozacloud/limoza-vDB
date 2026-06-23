# Advisory tiers (L1–L3)

For any CVE, three questions matter to anyone triaging it:

- **L1 — who assigned it?** The CNA that owns the CVE.
- **L2 — what does the affected product say?** The upstream project's own advisory.
- **L3 — who shipped a fix?** The downstream distros and package ecosystems.

`cve_levels(cve)` is a set-returning SQL function that assembles all three tiers for
one CVE from the rows the sources already wrote. It is tracked in Hasura, so the
same answer is one GraphQL query.

## Return shape

Each row is one advisory link at one tier:

| Column | Description |
|--------|-------------|
| `lvl` | `L1 CNA` \| `L2 Upstream` \| `L3 Downstream` |
| `source` | the issuer (CNA short name, distro, ecosystem, package name) |
| `url` | a link to the advisory / page |
| `tracked_only` | `true` = the distro only *assessed* the CVE (no formal bulletin), so the link is its per-CVE tracking page rather than an advisory |

## How each tier is derived

### L1 — CNA

The assigner from `cve_record.assigner`, joined to the [`cna`](datasources/cna.md)
directory for its name and advisory URL.

### L2 — Upstream

The affected product's own advisory, found three ways:

1. **Dedicated-CNA pattern.** Many products are their own CNA (OpenSSL, curl, the
   Linux kernel, …). `cna.advisory_patterns` holds a per-CNA URL pattern; any
   `cve_ref` from the CVE List matching that pattern is the product's own advisory.
2. **Ecosystem GHSA.** If a [GitHub Advisory](datasources/ghsa.md) covers the CVE,
   it is the ecosystem package's upstream advisory; the package name comes from its
   affected purl.
3. **GHSA reference fallback.** If no GHSA was imported but the CVE List references a
   `…/security/advisories/GHSA-…` URL, that link is used.

### L3 — Downstream

Two kinds of downstream coverage:

1. **Formal advisories** — every `advisory` linked to the CVE that isn't a GHSA:
   distro bulletins (RHSA, USN, DSA, …) and the OSV ecosystem-native DBs.
2. **Distro tracking** — a `cve_vendor` assessment from a distro that issued **no**
   formal bulletin. These rows are marked `tracked_only = true` and link to the
   distro's per-CVE tracking page.

The link a tier shows comes from [`source_url`](#source_url) so the function carries
no hardcoded URLs.

## Querying it

```graphql
query CveLevels($cve: String!) {
  cve_levels(args: { p_cve: $cve }, order_by: { lvl: asc }) {
    lvl
    source
    url
    tracked_only
  }
}
```

```json
{ "cve": "CVE-2024-0001" }
```

A consumer can render `tracked_only: true` rows differently (e.g. a "tracked, no
fix advisory" badge) from formal bulletins.

> **Note:** for some CVEs (notably Linux kernel ones) L2 can return many rows — one
> per upstream fix commit. Page or cap on the client if needed.

## `source_url`

`cve_levels` builds its links from the `source_url` table, a SQL-accessible mirror
of `ingest/advisories/source_urls.json` — the editable single source of truth for
per-source URL templates:

| Column | Meaning |
|--------|---------|
| `cve_url` | the source's per-CVE page, e.g. `https://access.redhat.com/security/cve/{cve}` |
| `advisory_url` | a human advisory page built from an advisory id (overrides the raw source link) |
| `when_id_prefix` | apply `advisory_url` only when the advisory id starts with this |

Edit `source_urls.json`, run `vdb ingest source_urls`, and the change takes effect
everywhere — no code change and no re-import of the source data.
