"""Third-party rpm builds (glance's `vendor` qualifier) are not matched against distro advisories."""
from ingest import api
from ingest.match import is_third_party_build, match

# exactly what glance emits for Remi's php-cli on Oracle Linux 8 (vendor only on third-party builds)
REMI = ("pkg:rpm/ol/php-cli@8.4.24-1.module_php.8.4.el8.remi?arch=x86_64"
        "&rpmmod=php%3Aremi-8.4%3A8100020260729084016%3A00000000&distro=ol-8.10&upstream=php"
        "&upstream_version=8.4.24-1.module_php.8.4.el8.remi&vendor=Remi%27s%20RPM%20repository")
DISTRO = "pkg:rpm/ol/bash@4.4.20-5.el8?arch=x86_64&distro=ol-8.10"


class _NoDB:
    """Any query is a test failure: a third-party build must be decided without the DB."""

    def cursor(self):
        raise AssertionError("third-party build must not be matched against the DB")

    def close(self):
        pass


def test_vendor_qualifier_marks_a_third_party_build():
    assert is_third_party_build(REMI)
    assert not is_third_party_build(DISTRO)
    assert not is_third_party_build(DISTRO + "&vendor=")
    assert not is_third_party_build("pkg:deb/ubuntu/php8.3@8.3.6-0ubuntu0.24.04.5?vendor=x")
    assert not is_third_party_build("cpe:2.3:a:php:php:8.4.24:*:*:*:*:*:*:*")


def test_third_party_build_gets_no_distro_findings():
    assert match(_NoDB(), REMI) == {}


def test_bulk_reports_third_party_build_as_unknown_not_compliant(monkeypatch):
    monkeypatch.setattr(api, "get_conn", lambda: _NoDB())
    monkeypatch.setattr(api, "load_curations", lambda conn: {})
    (res,) = api._bulk_match([{"purl": REMI}])
    assert res["status"] == "unknown"
    assert res["reason"] == "third_party_build"
    assert res["cves"] == []
