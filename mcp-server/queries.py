"""GraphQL query strings. One per use case — kept verbatim-compatible with
docs/graphql-example-queries.md so the API surface stays the single source of truth.
"""

# Full single-CVE scan: every field for one CVE across all sources.
FULL_CVE_SCAN = """
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
      titles { value source advisory_ref }
      descriptions { value source advisory_ref }
      cvss { version score vector severity source product_id }
      cwes { cwe_id name source }
      references { url type source }
      advisories { advisory_id source url published updated vendor_data }
      upstream { upstream_id purl fix_version fix_commit ranges versions source }
      packages {
        name purl affected_state remediation_state status_raw
        vex_justification ranges severity source advisory_ref vendor_data
      }
      mitigations { source advisory_ref value purls }
      impacts { source advisory_ref value }
      exploits { source source_id name url metadata }
      history(order_by: { date: asc }) { date event source detail }
    }
  }
}
"""
