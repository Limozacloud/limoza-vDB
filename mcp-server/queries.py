"""GraphQL query strings. One per use case — kept verbatim-compatible with
docs/graphql-example-queries.md so the API surface stays the single source of truth.
"""

# Full single-CVE scan: every field for one CVE across all sources, plus the tiered
# advisory view (cve_levels). `affected` is high-cardinality (kernel CVEs span many
# distro streams) so it is capped — use the match tool for per-package decisions.
FULL_CVE_SCAN = """
query CVEDetails($cve_id: String!) {
  cve_by_pk(cve_id: $cve_id) {
    cve_id
    first_seen
    record { state assigner title date_published date_updated exploit_note }
    epss { score percentile date }
    kev  { date_added due_date known_ransomware required_action }
    ssvc { exploitation automatable technical_impact }
    descriptions { source lang value }
    cvss { source version vector base_score severity }
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
      }
    }
    refs { source url type }
    solutions   { source value }
    workarounds { source value }
    impacts     { source capec_id description }
    aliases     { source alias }
    vendors     { source data }
    advisory_cve { advisory { source advisory_id url title severity published modified } }
    exploits { source source_id name url metadata }
    affected(limit: 1000, order_by: [{source: asc}, {status: asc}, {package: asc}]) {
      ecosystem package release fixed status source
    }
  }
  affected_aggregate(where: {cve_id: {_eq: $cve_id}}) { aggregate { count } }
  cve_levels(args: {p_cve: $cve_id}, order_by: {lvl: asc}) {
    lvl source url tracked_only
  }
}
"""

# Affected-layer provenance for one CVE (+ optional package filter): per-source, per-release
# status with the raw vendor status (status_raw) and the reason we derived it (justification).
# Feeds explain_status — "why does CVE X have status Y for package Z, with a source link?".
EXPLAIN_STATUS = """
query ExplainStatus($cve: String!, $pkg: String!) {
  affected(
    where: {cve_id: {_eq: $cve}, package: {_ilike: $pkg}}
    order_by: [{source: asc}, {release: asc}, {package: asc}]
    limit: 500
  ) {
    source coord ecosystem package release introduced fixed last_affected status status_raw justification
  }
}
"""

# Package-level provenance (no specific CVE): every CVE tracked for a package, with status +
# reason — feeds explain_status's package mode ("why does package X have no open CVEs?").
EXPLAIN_PACKAGE = """
query ExplainPackage($pkg: String!) {
  affected(
    where: {package: {_ilike: $pkg}}
    order_by: [{release: asc}, {source: asc}, {cve_id: asc}]
    limit: 3000
  ) {
    cve_id source release introduced fixed last_affected status status_raw justification
  }
}
"""
