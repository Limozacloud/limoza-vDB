"""Products that the Tenable vs ITRION comparison found missing from the affected table."""
from ingest.affected import COLS, cpe_norm
from ingest.affected.sources import cvelistv5


def test_msrc_windows_sdk_cpe_resolves_to_the_nvd_product(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("microsoft", "windows_software_development_kit")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    key, version = cpe_norm.canonical("cpe:2.3:a:microsoft:.windows_sdk:*:*:*:*:*:*:*:*")
    assert key == "cpe:2.3:a:microsoft:windows_software_development_kit:*:*:*:*:*:*:*:*"
    assert version is None
    # the no-CPE fallback by product name lands on the same key (an application, not an OS)
    assert cpe_norm.from_name("Windows SDK") == key


def test_windows_sdk_alias_does_not_touch_other_products(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("microsoft", "windows_server_2022")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    assert cpe_norm.canonical("cpe:2.3:a:microsoft:.windows_sdk:*:*:*:*:*:*:*:*")[0] is None
    assert cpe_norm.from_name("Windows Server 2022").startswith("cpe:2.3:o:microsoft:windows_server_2022")


def test_jetbrains_pycharm_cna_ranges_become_cpe_rows(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("jetbrains", "pycharm")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    doc = {
        "cveMetadata": {"cveId": "CVE-2026-118696"},
        "containers": {"cna": {"affected": [
            {"vendor": "JetBrains", "product": "PyCharm", "defaultStatus": "unaffected", "versions": [
                {"status": "affected", "version": "2026.2", "lessThan": "2026.2.4", "versionType": "semver"},
                {"status": "affected", "version": "0", "lessThan": "2025.3.6.2", "versionType": "semver"},
            ]},
            {"vendor": "JetBrains", "product": "PhpStorm", "defaultStatus": "unaffected", "versions": [
                {"status": "affected", "version": "0", "lessThan": "2026.2.4", "versionType": "semver"},
            ]},
        ]}},
    }
    rows = list(cvelistv5._file_rows(doc))
    cpe, intro, fixed = COLS.index("cpe23"), COLS.index("introduced"), COLS.index("fixed")
    assert sorted((r[intro], r[fixed]) for r in rows) == [("0", "2025.3.6.2"), ("2026.2", "2026.2.4")]
    assert {r[cpe] for r in rows} == {"cpe:2.3:a:jetbrains:pycharm:*:*:*:*:*:*:*:*"}
