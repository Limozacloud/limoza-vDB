# GraphQL example queries

Ready-to-run queries against the read-only [GraphQL API](running/graphql.md). All
require a bearer token (`Authorization: Bearer <token>`); mint one with
[`create-token`](running/cli.md#create-token).

The `cve` spine relates to its child rows under these field names: `record` (1:1),
`epss` / `kev` / `ssvc` (1:1), and the arrays `cvss`, `cwes`, `descriptions`, `refs`,
`solutions`, `workarounds`, `impacts`, `aliases`, `vendors`, `advisory_cve`,
`exploits`.

## Everything about one CVE

```graphql
query CveDetail($cve: String!) {
  cve_by_pk(cve_id: $cve) {
    cve_id
    first_seen
    record { state assigner title date_published date_updated }
    epss { score percentile date }
    kev  { date_added due_date known_ransomware }
    ssvc { exploitation automatable technical_impact }
    descriptions { source lang value }
    cvss { source version base_score severity vector }
    cwes { cwe_id cwe { name } }
    refs { source url type }
    solutions   { source value }
    workarounds { source value }
    vendors { source data }
    advisory_cve { advisory { source advisory_id url title severity published } }
    exploits { source name url }
  }
}
```

```json
{ "cve": "CVE-2024-0001" }
```

## Tiered advisory view (L1–L3)

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

See [Advisory tiers (L1–L3)](advisory-tiers.md) for what each tier means.

## Highest-risk CVEs by EPSS

```graphql
query TopEpss {
  epss(order_by: { score: desc }, limit: 10) {
    cve_id
    score
    percentile
    cve { record { title } }
  }
}
```

## Known-exploited (CISA KEV)

```graphql
query Kev {
  kev(order_by: { date_added: desc }, limit: 10) {
    cve_id
    vulnerability_name
    known_ransomware
    date_added
    due_date
  }
}
```

## Recently published CVEs

```graphql
query Recent {
  cve_record(order_by: { date_published: desc }, limit: 20) {
    cve_id
    title
    assigner
    date_published
  }
}
```

## All advisories that reference a CVE

```graphql
query Advisories($cve: String!) {
  advisory_cve(where: { cve_id: { _eq: $cve } }) {
    advisory { source advisory_id url title severity }
  }
}
```

## CVEs an advisory covers

```graphql
query AdvisoryCves($source: String!, $id: String!) {
  advisory_by_pk(source: $source, advisory_id: $id) {
    advisory_id
    title
    cves { cve_id }
  }
}
```

```json
{ "source": "redhat", "id": "RHSA-2024:2011" }
```
