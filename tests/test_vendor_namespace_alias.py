"""IA-2072: inventory distro namespaces (`ol`, `sles`) resolve to vDB's vendor rows (`oracle`, `suse`),
and /match can return the scoped vendor evidence behind a `compliant` verdict."""
import pytest

from ingest import api
from ingest.match import (_is_suse, _rpm_sources, _rpm_streams, match, match_with_evidence)
from ingest.match.vendor_alias import (VENDOR_ALIASES, canonical_namespace, canonical_purl,
                                       distro_vendor, rhel_family_release)

CVE = "CVE-2026-111497"
# exactly what glance emits for the 194 Oracle Linux 8.10 rows in the Brotli report
OL_BROTLI = "pkg:rpm/ol/brotli@1.0.6-5.el8_10?arch=x86_64&distro=ol-8.10"
SLES_BROTLI = "pkg:rpm/sles/libbrotlicommon1@1.0.7-150200.3.8.1?arch=x86_64&distro=sles-15.7"


def _row(cve, source, release, fixed, status="fixed", rid=1, raw=None, stream=None, intro="0", last=None):
    # (cve_id, source, release, introduced, fixed, last_affected, version_scheme, status,
    #  status_raw, module_stream, id) — the affected SELECT order in _match_purl
    return (cve, source, release, intro, fixed, last, "rpm", status, raw, stream, rid)


class _Cursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, sql, params=None):
        self.conn.calls.append((sql, params))
        self.pkg = params[1] if isinstance(params, tuple) and len(params) > 1 else None

    def fetchall(self):
        return self.conn.rows.get(self.pkg, []) if isinstance(self.pkg, str) else []


class _Conn:
    """Rows keyed by the looked-up package; records every (sql, params) for scoping asserts."""

    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def cursor(self):
        return _Cursor(self)

    def close(self):
        pass


# ── alias map ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,vendor", [
    ("ol", "oracle"), ("ol-8.10", "oracle"), ("OL9", "oracle"), ("oraclelinux-9", "oracle"),
    ("oracle-linux-8.10", "oracle"), ("Oracle Linux 8.10", "oracle"), ("oracle_linux", "oracle"),
    ("oel8", "oracle"), ("oracle", "oracle"),
    ("sles", "suse"), ("sles-15.7", "suse"), ("sled-15.6", "suse"), ("sles_sap-15.5", "suse"),
    ("opensuse-leap-15.6", "suse"), ("opensuse-tumbleweed", "suse"), ("suse", "suse"),
    ("rhel-9.3", "redhat"), ("redhat-8.10", "redhat"), ("centos-7", "centos"),
    ("almalinux-9.4", "almalinux"), ("rockylinux-9", "rocky"),
    ("debian-12", None), ("ubuntu", None), ("el8_10", None), ("", None), (None, None), ("olx-8", None),
])
def test_distro_vendor(value, vendor):
    assert distro_vendor(value) == vendor


@pytest.mark.parametrize("value,expected", [
    ("ol-8.10", ("8", "10")), ("oracle-linux-8.10", ("8", "10")), ("Oracle Linux 8.10", ("8", "10")),
    ("oel8", ("8", None)), ("redhat-9.8", ("9", "8")), ("rhel9", ("9", None)),
    ("sles-15.7", None), ("ol", None), ("rhel-9.3.1", None), ("debian-12", None),
])
def test_rhel_family_release(value, expected):
    assert rhel_family_release(value) == expected


def test_canonical_purl_rewrites_only_reviewed_vendor_namespaces():
    assert canonical_purl(OL_BROTLI) == "pkg:rpm/oracle/brotli@1.0.6-5.el8_10?arch=x86_64&distro=ol-8.10"
    assert canonical_purl(SLES_BROTLI).startswith("pkg:rpm/suse/libbrotlicommon1@1.0.7-150200.3.8.1?")
    assert canonical_purl("pkg:rpm/oraclelinux/bash@4.4") == "pkg:rpm/oracle/bash@4.4"
    for unchanged in ("pkg:rpm/redhat/bash@4.4?distro=redhat-9.8", "pkg:rpm/rocky/bash@4.4",
                      "pkg:deb/ubuntu/libbrotli1@1.1.0-2ubuntu0.1?distro=noble", "pkg:rpm/brotli@1.0",
                      "pkg:pypi/brotli@1.1.0", "cpe:2.3:a:google:brotli:1.0.9:*:*:*:*:*:*:*"):
        assert canonical_purl(unchanged) == unchanged
    assert canonical_namespace("ol") == "oracle" and canonical_namespace("redhat") == "redhat"


def test_every_suse_alias_is_on_the_suse_lane():
    # _is_suse decides the SUSE lane on its own prefix list; the alias map must never disagree with it
    for alias in (a for a, v in VENDOR_ALIASES.items() if v == "suse"):
        assert _is_suse(None, alias, "1.0"), alias


@pytest.mark.parametrize("distro,namespace,sources", [
    # unchanged vendor scoping for every value the matcher already understood
    ("redhat-9.8", "redhat", ["redhat"]), ("rhel-9", None, ["redhat"]), ("centos-7", None, ["redhat"]),
    ("ol-8.10", "ol", ["oracle", "redhat"]), ("oraclelinux-9", None, ["oracle", "redhat"]),
    ("almalinux-9.4", None, ["almalinux", "redhat"]), ("rocky-9", None, ["rocky", "redhat"]),
    (None, "ol", ["oracle", "redhat"]), ("el8_10", "ol", ["oracle", "redhat"]),
    (None, None, None), ("fedora-40", "fedora", None),
    # IA-2072 additions — previously the unscoped whole-family pool or (display name) the namespace
    ("Oracle Linux 8.10", None, ["oracle", "redhat"]), ("oracle-linux-8.10", None, ["oracle", "redhat"]),
    (None, "oel", ["oracle", "redhat"]),
])
def test_rpm_vendor_sources(distro, namespace, sources):
    assert _rpm_sources(distro, namespace) == sources


def test_display_name_distro_keeps_the_host_minor_stream():
    # a bare .el8 package inherits the OS minor; `Oracle Linux 8.10` used to lose it
    assert _rpm_streams("4.4.20-5.el8", "Oracle Linux 8.10") == ["el8", "el8_10"]
    assert _rpm_streams("4.4.20-5.el8", "oracle-linux-8.10") == ["el8", "el8_10"]
    assert _rpm_streams("4.4.20-5.el8", "ol-8.10") == ["el8", "el8_10"]


# ── matcher evidence ─────────────────────────────────────────────────────────────────────

def test_oracle_brotli_meets_the_vendor_fix():
    conn = _Conn({"brotli": [_row(CVE, "oracle", "el8_10", "1.0.6-5.el8_10", rid=4729594829)]})
    assert match(conn, OL_BROTLI, curations={}) == {}
    sql, params = conn.calls[0]
    assert params == ("rpm", "brotli", ["el8", "el8_10"], ["oracle", "redhat"])

    findings, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations={})
    assert findings == {}
    assert ev["id"] == CVE and ev["verdict"] == "fixed"
    assert ev["records"] == [{"affected_id": 4729594829, "source": "oracle", "package": "brotli",
                              "package_match": "binary", "release": "el8_10", "status": "fixed",
                              "fixed": "1.0.6-5.el8_10", "outcome": "meets_fix"}]


def test_oracle_host_below_the_fix_is_vulnerable_with_the_same_record():
    conn = _Conn({"brotli": [_row(CVE, "oracle", "el8_10", "1.0.6-5.el8_10", rid=7)]})
    below = "pkg:rpm/ol/brotli@1.0.6-3.el8?arch=x86_64&distro=ol-8.10"
    assert set(match(conn, below, curations={})) == {CVE}
    findings, (ev,) = match_with_evidence(conn, below, [CVE], curations={})
    assert set(findings) == {CVE}
    assert ev["verdict"] == "vulnerable" and ev["records"][0]["outcome"] == "affected"


def test_no_in_scope_record_is_no_record_never_fixed():
    conn = _Conn({"brotli": [_row("CVE-2026-1", "oracle", "el8_10", "1.0.6-5.el8_10")]})
    findings, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations={})
    assert findings == {} and ev == {"id": CVE, "verdict": "no_record", "records": []}


def test_under_investigation_only_is_inconclusive():
    conn = _Conn({"brotli": [_row(CVE, "redhat", "el8", None, status="under_investigation")]})
    _, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations={})
    assert ev["verdict"] == "inconclusive"


def test_fix_deferred_is_wont_fix_not_fixed():
    conn = _Conn({"brotli": [_row(CVE, "redhat", "el8", None, status="affected", raw="Fix deferred")]})
    findings, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations={})
    assert findings == {} and ev["verdict"] == "wont_fix"


def test_a_foreign_variant_fix_is_not_evidence():
    # an Oracle ksplice build is a parallel line — never proof for a regular host
    conn = _Conn({"brotli": [_row(CVE, "oracle", "el8", "2:1.0.6-5.0.1.ksplice1.el8")]})
    _, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations={})
    assert ev["verdict"] == "no_record"


def test_curation_suppress_is_reported_as_suppressed():
    conn = _Conn({"brotli": [_row(CVE, "oracle", "el8_10", "1.0.7-1.el8_10")]})
    curations = {CVE: [{"cve_id": CVE, "action": "suppress", "coord": None, "ecosystem": None,
                        "package": "brotli", "cpe23": None, "release": None, "source": None,
                        "status": None, "fixed": None, "introduced": None, "last_affected": None}]}
    findings, (ev,) = match_with_evidence(conn, OL_BROTLI, [CVE], curations=curations)
    assert findings == {} and ev["verdict"] == "suppressed"
    assert ev["records"][0]["curated"] is True


def test_deb_source_fallback_is_labelled_source():
    deb = "pkg:deb/ubuntu/libbrotli1@1.1.0-2ubuntu0.1?arch=amd64&distro=ubuntu-24.04&upstream=brotli"
    conn = _Conn({"brotli": [(CVE, "ubuntu", "noble", "0", "1.1.0-2ubuntu0.1", None, "deb", "fixed",
                              None, None, 9)]})
    _, (ev,) = match_with_evidence(conn, deb, [CVE], curations={})
    assert ev["verdict"] == "fixed"
    assert ev["records"][0]["package"] == "brotli" and ev["records"][0]["package_match"] == "source"


def test_suse_fix_in_the_host_codestream_is_fixed():
    conn = _Conn({"libbrotlicommon1": [
        _row(CVE, "suse", "sles15sp7", "1.0.7-150200.3.8.1", rid=4705053434)]})
    findings, (ev,) = match_with_evidence(conn, SLES_BROTLI, [CVE], curations={})
    assert findings == {} and ev["verdict"] == "fixed"
    assert "source = 'suse'" in conn.calls[0][0]


FIREFOX_ROWS = {"mozillafirefox": [
    _row(CVE, "suse", "sles15sp5", None, status="not_affected", rid=4705057985),
    _row(CVE, "suse", "sles15sp7", None, status="affected", rid=4705061600)]}


def test_suse_not_affected_for_the_hosts_own_service_pack():
    sp5 = "pkg:rpm/sles/MozillaFirefox@68.1.0-109.92.1?arch=x86_64&distro=sles-15.5"
    findings, (ev,) = match_with_evidence(_Conn(FIREFOX_ROWS), sp5, [CVE], curations={})
    assert findings == {} and ev["verdict"] == "not_affected"


def test_suse_not_affected_for_another_service_pack_is_not_proof():
    # the matcher's lane-agnostic VEX override hides the SP7 "affected" row (findings unchanged);
    # the evidence must not present SP5's statement as not_affected for an SP7 host
    sp7 = "pkg:rpm/sles/MozillaFirefox@140.7.0-150200.152.216.1?arch=x86_64&distro=sles-15.7"
    findings, (ev,) = match_with_evidence(_Conn(FIREFOX_ROWS), sp7, [CVE], curations={})
    assert findings == match(_Conn(FIREFOX_ROWS), sp7, curations={})
    assert ev["verdict"] == "inconclusive"
    assert {r["outcome"] for r in ev["records"]} == {"foreign_lane"}


def test_evidence_is_rejected_for_cpe_and_unsupported_for_third_party():
    with pytest.raises(ValueError):
        match_with_evidence(_Conn({}), "cpe:2.3:a:google:brotli:1.0.9:*:*:*:*:*:*:*", [CVE], curations={})
    remi = "pkg:rpm/ol/php-cli@8.4.24-1.el8.remi?distro=ol-8.10&vendor=Remi"
    assert match_with_evidence(_Conn({}), remi, [CVE], curations={}) == (
        {}, [{"id": CVE, "verdict": "unsupported", "reason": "third_party_build", "records": []}])


# ── REST /match ──────────────────────────────────────────────────────────────────────────

@pytest.fixture
def bulk(monkeypatch):
    def run(rows, components, evidence_cves=None):
        monkeypatch.setattr(api, "get_conn", lambda: _Conn(rows))
        monkeypatch.setattr(api, "load_curations", lambda conn: {})
        return api._bulk_match(components, evidence_cves=evidence_cves)
    return run


def test_api_response_is_unchanged_without_evidence_cves(bulk):
    (res,) = bulk({"brotli": [_row(CVE, "oracle", "el8_10", "1.0.6-5.el8_10")]}, [{"purl": OL_BROTLI}])
    assert res["status"] == "compliant"
    assert "evidence" not in res and "canonical_component" not in res


def test_api_returns_canonical_component_and_evidence(bulk):
    rows = {"brotli": [_row(CVE, "oracle", "el8_10", "1.0.6-5.el8_10", rid=4729594829)]}
    (res,) = bulk(rows, [{"purl": OL_BROTLI}], [CVE])
    assert res["status"] == "compliant"
    assert res["component"] == OL_BROTLI
    assert res["canonical_component"] == "pkg:rpm/oracle/brotli@1.0.6-5.el8_10?arch=x86_64&distro=ol-8.10"
    (ev,) = res["evidence"]
    assert ev["verdict"] == "fixed" and ev["records"][0]["affected_id"] == 4729594829


def test_api_evidence_is_unsupported_for_cpe_and_error(bulk):
    cpe = {"cpe": "cpe:2.3:a:google:brotli:1.0.9:*:*:*:*:*:*:*", "version": "1.0.9"}
    no_version = {"purl": "pkg:rpm/ol/brotli?distro=ol-8.10"}
    res_cpe, res_err = bulk({}, [cpe, no_version], [CVE])
    assert res_cpe["evidence"] == [{"id": CVE, "verdict": "unsupported", "reason": "cpe_identity",
                                    "records": []}]
    assert res_err["status"] == "unknown" and res_err["evidence"][0]["reason"] == "error"


def test_api_validates_evidence_cves():
    assert api._evidence_cves(None) == []
    assert api._evidence_cves([" cve-2026-111497 ", "CVE-2026-111497"]) == [CVE]
    for bad in ("CVE-2026-111497", ["not-a-cve"], [1], ["CVE-2026-1000"] * 2 + [f"CVE-2026-{i:05}" for i in range(30)]):
        with pytest.raises(ValueError):
            api._evidence_cves(bad)
