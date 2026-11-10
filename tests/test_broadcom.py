"""Broadcom (VMware) advisories: Response Matrix parsing, the affected rows built from it, and the sync."""
import json

import pytest

from ingest.advisories.broadcom import matrix, sync
from ingest.affected import COLS, cpe_norm
from ingest.affected.sources import broadcom

HEAD = ("<tr><th>Product</th><th>Component</th><th>Version</th><th>Running On</th><th>CVE</th>"
        "<th>CVSSv3</th><th>Severity</th><th>Fixed Version</th><th>Workaround</th><th>Additional Documents</th></tr>")


def _row(product, component, version, running_on, cve, fixed):
    return (f"<tr><td>{product}</td><td>{component}</td><td>{version}</td><td>{running_on}</td><td>{cve}</td>"
            f"<td>7.8</td><td>Important</td><td>{fixed}</td><td>None</td><td>None</td></tr>")


# shaped like VMSA-2025-0015 / -0013 (one table per CVE group, a layout table around them)
PAGE = f"""<html><body><table><tr><td>layout</td></tr></table>
<table>{HEAD}
{_row("VMware Cloud Foundation<br>VMware vSphere Foundation", "VMware Tools", "13.x.x.x [2]", "Windows, Linux", "CVE-2025-41244", "13.0.5.0")}
{_row("VMware Aria Operations", "VMware Aria Operations", "8.x", "Any", "CVE-2025-41244, CVE-2025-41245", "8.18.5")}
{_row("VMware Tools", "N/A", "13.x.x", "Windows, Linux", "CVE-2025-41244", "13.0.5")}
{_row("VMware Tools", "N/A", "12.x.x, 11.x.x", "Windows, Linux", "CVE-2025-41244", "12.5.4")}
</table>
<table>{HEAD}
{_row("VMware Tools [2]", "N/A", "12.x.x, 11.x.x", "Windows", "CVE-2025-41246", "12.5.4")}
{_row("VMware Tools", "N/A", "12.x.x, 11.x.x", "Linux", "CVE-2025-41246", "Unaffected")}
{_row("VMware Tools", "N/A", "12.x.x, 11.x.x", "macOS", "CVE-2025-41239", "12.5.3")}
{_row("VMware Workstation Pro", "N/A", "17.x", "Windows", "CVE-2025-1", "KB92148")}
</table>
<table><tr><th>Old</th><th>Layout</th></tr><tr><td>a</td><td>b</td></tr></table>
</body></html>"""


def test_parse_matrices_reads_the_response_matrix_rows():
    rows = matrix.parse_matrices(PAGE)
    assert len(rows) == 8
    first = rows[0]
    assert first["product"] == "VMware Cloud Foundation VMware vSphere Foundation"
    assert (first["component"], first["version"], first["fixed"]) == ("VMware Tools", "13.x.x.x [2]", "13.0.5.0")
    assert rows[1]["cves"] == ["CVE-2025-41244", "CVE-2025-41245"]
    assert rows[4]["product"] == "VMware Tools"            # footnote marker removed


@pytest.mark.parametrize("cell, expected", [
    ("13.x.x.x [2]", "13"), ("13.x.x", "13"), ("12.x.x, 11.x.x", "11"), ("12.5.x", "12.5"),
    ("8.0 U3", "8.0"), ("17.x", "17"), ("N/A", None), ("", None),
])
def test_lower_bound(cell, expected):
    assert matrix.lower_bound(cell) == expected


@pytest.mark.parametrize("cell, expected", [
    ("12.5.4", "12.5.4"), ("13.0.5.0", "13.0.5.0"), ("Unaffected", None), ("KB92148", None),
    ("N/A", None), ("Patch Pending", None), ("", None),
])
def test_fixed_version(cell, expected):
    assert matrix.fixed_version(cell) == expected


def _extract(monkeypatch, tmp_path):
    monkeypatch.setattr(cpe_norm, "load", lambda conn: None)
    monkeypatch.setattr(cpe_norm, "_VP", {("vmware", "tools"), ("vmware", "workstation")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    (tmp_path / "advisories").mkdir()
    (tmp_path / "index.json").write_text(json.dumps({"36149": {"documentId": "VCDSA36149"}}))
    (tmp_path / "advisories" / "36149.html").write_text(PAGE)
    return list(broadcom.extract(None, {"broadcom": str(tmp_path)}))


def test_extract_builds_version_ranges_for_vmware_tools(monkeypatch, tmp_path):
    rows = _extract(monkeypatch, tmp_path)
    i = {c: COLS.index(c) for c in ("cve_id", "cpe23", "introduced", "fixed", "origin", "status")}
    got = sorted((r[i["cve_id"]], r[i["introduced"]], r[i["fixed"]]) for r in rows)
    assert got == [
        ("CVE-2025-41244", "11", "12.5.4"),
        ("CVE-2025-41244", "13", "13.0.5.0"),            # 13.0.5 from the second row is the same version
        ("CVE-2025-41246", "11", "12.5.4"),
    ]
    assert {r[i["cpe23"]] for r in rows} == {"cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*"}
    assert {r[i["origin"]] for r in rows} == {"broadcom"}


def test_extract_skips_linux_only_unaffected_kb_and_unmapped_products(monkeypatch, tmp_path):
    rows = _extract(monkeypatch, tmp_path)
    cves = {r[COLS.index("cve_id")] for r in rows}
    assert "CVE-2025-41239" not in cves                    # macOS only
    assert "CVE-2025-1" not in cves                        # fixed value is a KB number
    assert "CVE-2025-41245" not in cves                    # VMware Aria Operations: no mapping


def test_extract_without_data_yields_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(cpe_norm, "load", lambda conn: None)
    assert list(broadcom.extract(None, {"broadcom": str(tmp_path)})) == []


def _entry(i, updated="2026-10-01"):
    return {"notificationId": i, "documentId": f"VCDSA{i}", "updated": updated,
            "notificationUrl": f"https://x/{i}", "affectedCve": "CVE-2025-1"}


def test_sync_retries_a_failed_download_and_skips_unchanged_pages(monkeypatch, tmp_path):
    monkeypatch.setattr(sync, "_SEGMENTS", ("VC",))
    monkeypatch.setattr(sync, "list_all", lambda seg: [_entry(1), _entry(2)])
    fetched, failures = [], {"left": 1}

    def fetch(entry):
        fetched.append(entry["notificationId"])
        if entry["notificationId"] == 2 and failures["left"]:
            failures["left"] -= 1
            raise OSError("boom")
        return b"<html>" + b"x" * 1200

    monkeypatch.setattr(sync, "_fetch_page", fetch)
    assert sync.run({"broadcom": str(tmp_path)}) == 1                  # advisory 2 failed
    assert set(json.loads((tmp_path / "index.json").read_text())) == {"1"}
    fetched.clear()
    assert sync.run({"broadcom": str(tmp_path)}) == 1                  # only the failed one again
    assert fetched == [2]
    assert set(json.loads((tmp_path / "index.json").read_text())) == {"1", "2"}
    fetched.clear()
    assert sync.run({"broadcom": str(tmp_path)})["status"] == "no_new_data"
    assert fetched == []


def test_sync_fetches_an_advisory_again_when_it_was_updated(monkeypatch, tmp_path):
    monkeypatch.setattr(sync, "_SEGMENTS", ("VC",))
    monkeypatch.setattr(sync, "_fetch_page", lambda e: b"<html>" + b"x" * 1200)
    monkeypatch.setattr(sync, "list_all", lambda seg: [_entry(1)])
    sync.run({"broadcom": str(tmp_path)})
    monkeypatch.setattr(sync, "list_all", lambda seg: [_entry(1, updated="2026-11-01")])
    assert sync.run({"broadcom": str(tmp_path)}) == 1
    assert json.loads((tmp_path / "index.json").read_text())["1"]["updated"] == "2026-11-01"


def test_parse_matrices_reads_the_older_column_layouts():
    old = ("<table><tr><th>VMware Product</th><th>Version</th><th>Running On</th><th>CVE Identifier</th>"
           "<th>CVSSv3</th><th>Severity</th><th>Fixed Version</th><th>Workarounds</th>"
           "<th>Additional Documentation</th></tr>"
           "<tr><td>VMware Tools</td><td>12.x.x, 11.x.x</td><td>Windows</td><td>CVE-2025-41239</td><td>7.1</td>"
           "<td>Important</td><td>12.5.3</td><td>None</td><td>None</td></tr></table>")
    (r,) = matrix.parse_matrices(old)
    assert (r["product"], r["component"], r["cves"], r["fixed"]) == ("VMware Tools", "", ["CVE-2025-41239"], "12.5.3")


def test_extract_reads_the_older_layout_too(monkeypatch, tmp_path):
    monkeypatch.setattr(cpe_norm, "load", lambda conn: None)
    monkeypatch.setattr(cpe_norm, "_VP", {("vmware", "tools")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    (tmp_path / "advisories").mkdir()
    (tmp_path / "index.json").write_text(json.dumps({"35877": {}}))
    (tmp_path / "advisories" / "35877.html").write_text(
        "<table><tr><th>Product</th><th>Version</th><th>Running On</th><th>CVE Identifier</th><th>CVSSv3</th>"
        "<th>Severity</th><th>Fixed Version</th><th>Workarounds</th><th>Additional Documents</th></tr>"
        "<tr><td>VMware Tools</td><td>12.x.x, 11.x.x</td><td>Windows</td><td>CVE-2025-41239</td><td>7.1</td>"
        "<td>Important</td><td>12.5.3</td><td>None</td><td>None</td></tr></table>")
    rows = list(broadcom.extract(None, {"broadcom": str(tmp_path)}))
    assert [(r[COLS.index("cve_id")], r[COLS.index("introduced")], r[COLS.index("fixed")]) for r in rows] == [
        ("CVE-2025-41239", "11", "12.5.3")]
