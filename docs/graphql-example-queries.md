# GraphQL Example Queries

## Full CVE Scan

Returns all available data for a single CVE — titles, descriptions, CVSS, packages across all distros, upstream ranges, mitigations, impacts, exploits, and history.

**Variable:** `{ "cve_id": "CVE-2026-49014" }`

```graphql
query FullCVEScan($cve_id: String!) {
  lve_cve(where: { cve_id: { _eq: $cve_id } }) {
    lve_id
    cve_id
    status
    published
    updated
    epss_score
    epss_percentile
    epss_date
    kev_date_added
    kev_due_date
    kev_known_ransomware
    kev_required_action
    ssvc_exploitation
    ssvc_automatable
    ssvc_technical_impact
    lve {
      aliases
      has_exploit
      ingested_at
      titles {
        value
        source
        advisory_ref
      }
      descriptions {
        value
        source
        advisory_ref
      }
      cvss {
        version
        score
        vector
        severity
        source
        product_id
      }
      cwes {
        cwe_id
        name
        source
        cwe {
          abstraction
          description
          extended_description
          likelihood_of_exploit
          common_consequences
          potential_mitigations
          modes_of_introduction
          detection_methods
          related_attack_patterns
          related_weaknesses
        }
      }
      references {
        url
        type
        source
      }
      advisories {
        advisory_id
        source
        url
        published
        updated
        vendor_data
      }
      upstream {
        upstream_id
        purl
        fix_version
        fix_commit
        ranges
        versions
        source
      }
      packages {
        name
        purl
        affected_state
        remediation_state
        status_raw
        vex_justification
        ranges
        severity
        source
        advisory_ref
        vendor_data
      }
      mitigations {
        source
        advisory_ref
        value
        purls
      }
      impacts {
        source
        advisory_ref
        value
      }
      exploits {
        source
        source_id
        name
        url
        metadata
      }
      history(order_by: { date: asc }) {
        date
        event
        source
        detail
      }
    }
  }
}
```

---

## Package Vulnerability Lookup

Returns all CVEs affecting a given package name. The `purl` field contains the distro qualifier (`?distro=el9`, `?distro=jammy`, etc.) — filter client-side as needed.

**Variable:** `{ "name": "openssl" }`

```graphql
query PackageRanges($name: String!) {
  lve_packages(where: {
    name: { _eq: $name }
  }) {
    purl
    remediation_state
    ranges
    lve {
      aliases
    }
  }
}
```

---

## Filter by alias prefix

Finds all LVEs whose `aliases` array contains an identifier matching a pattern — for
example every record carrying a Microsoft `ADV` advisory. This uses the `_any` operator
on the `TEXT[]` column, available via the
[custom Hasura build](running/graphql.md#custom-hasura-build).

```graphql
query AliasPrefix {
  lve(where: { aliases: { _any: { _ilike: "ADV%" } } }) {
    lve_id
    aliases
  }
}
```
