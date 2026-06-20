"""GraphQL query strings. One per use case — kept verbatim-compatible with
docs/graphql-example-queries.md so the API surface stays the single source of truth.
"""

# Full single-CVE scan: every field for one CVE across all sources.
FULL_CVE_SCAN = """
query CVEDetails($cve_id: String!) {
  lve_cve(where: {cve_id: {_eq: $cve_id}}) {
    cve_id
    published
    updated
    status
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
      lve_id
      aliases
      has_exploit
      titles { value source advisory_ref }
      descriptions { value source advisory_ref }
      cvss { source version vector score severity advisory_ref }
      cwes {
        cwe_id
        cwe {
          name
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
      references { url type source }
      advisories { advisory_id source url published updated vendor_data }
      packages {
        name purl source
        affected_state remediation_state
        status_raw vex_justification
        ranges advisory_ref vendor_data
      }
      exploits { source source_id name url metadata }
      upstream { upstream_id purl fix_version fix_commit versions ranges source advisory_ref }
      mitigations { value source advisory_ref }
      impacts { value source advisory_ref }
      history(order_by: {date: asc}) { date event source detail }
    }
  }
}
"""
