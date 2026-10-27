from ingest.affected import COLS, cpe_norm
from ingest.affected.sources import microsoft
from ingest.affected.sources.microsoft import _doc_rows
from ingest.match import _legacy_remediation, _microsoft_applicability, match_cpe


class _RowsCursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, _sql, _params):
        return None

    def fetchall(self):
        return self.rows


class _RowsConnection:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return _RowsCursor(self.rows)


def _source_data(row):
    return row[COLS.index("source_data")].adapted


def test_microsoft_rows_preserve_dotnet_platform_and_compound_fix(monkeypatch):
    monkeypatch.setattr(
        cpe_norm,
        "_VP",
        {("microsoft", ".net_framework"), ("microsoft", "windows_server_2022")},
    )
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    doc = {
        "ProductTree": {
            "FullProductName": [
                {
                    "ProductID": "server-dotnet",
                    "Value": "Microsoft .NET Framework 3.5 AND 4.8 on Windows Server 2022",
                    "CPE": "cpe:2.3:a:microsoft:.net:4.8:*:*:*:*:*:*:*",
                },
                {
                    "ProductID": "windows-dotnet",
                    "Value": (
                        "Microsoft .NET Framework 4.8.1 on Windows 11 version 26H1 "
                        "for x64-based Systems"
                    ),
                    "CPE": "cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*",
                },
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-62886",
                "Remediations": [
                    {
                        "FixedBuild": "2.0.50727.9183 & 3.0.30729.9169 & 4.8.4805.0",
                        "Description": {"Value": "5120705"},
                        "SubType": "Security Update",
                        "ProductID": ["server-dotnet"],
                    },
                    {
                        "FixedBuild": "4.8.9344.0",
                        "Description": {"Value": "5120711"},
                        "SubType": "Security Update",
                        "ProductID": ["windows-dotnet"],
                    },
                ],
            }
        ],
    }

    rows = list(_doc_rows(doc))

    assert [row[COLS.index("fix_kb")] for row in rows] == ["KB5120705", "KB5120711"]
    assert rows[0][COLS.index("cpe23")].split(":")[4] == ".net_framework"
    assert rows[0][COLS.index("fixed")] == "4.8.4805.0"
    assert _source_data(rows[0])["dotnet_framework_product"] == "4.8"
    assert _source_data(rows[0])["windows_product"] == "windows_server_2022"
    assert _source_data(rows[1])["dotnet_framework_product"] == "4.8.1"
    assert _source_data(rows[1])["windows_product"] == "windows_11_26h1"
    assert _source_data(rows[1])["architecture"] == "x64"


def test_microsoft_rows_preserve_explicit_hotpatch_channel(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("microsoft", "windows_server_2022")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    doc = {
        "ProductTree": {
            "FullProductName": [
                {
                    "ProductID": "11923",
                    "Value": "Windows Server 2022",
                    "CPE": (
                        "cpe:2.3:o:microsoft:windows_server_2022:"
                        "10.0.20348.5499:*:*:*:*:*:*:*"
                    ),
                }
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-0001",
                "Remediations": [
                    {
                        "FixedBuild": "10.0.20348.5440",
                        "Description": {"Value": "5120229"},
                        "SubType": "Security Hotpatch Update",
                        "ProductID": ["11923"],
                    }
                ],
            }
        ],
    }

    row = list(_doc_rows(doc))[0]

    assert _source_data(row)["servicing_channel"] == "hotpatch"
    assert _source_data(row)["windows_product"] == "windows_server_2022"


def test_hotpatch_is_incompatible_with_standard_server_edition():
    result = _microsoft_applicability(
        {"windows_product": "windows_server_2022", "servicing_channel": "hotpatch"},
        host={"windows_product": "windows_server_2022", "windows_edition_id": "ServerStandard"},
    )

    assert result["state"] == "incompatible"


def test_dotnet_fix_requires_matching_framework_and_windows_product():
    source_data = {
        "windows_product": "windows_server_2022",
        "dotnet_framework_product": "4.8",
        "servicing_channel": "standard",
    }
    result = _microsoft_applicability(
        source_data,
        host={"windows_product": "windows_server_2022"},
        component_metadata={"dotnet_framework_product": "4.8"},
    )
    wrong_host = _microsoft_applicability(
        source_data,
        host={"windows_product": "windows_11_26h1"},
        component_metadata={"dotnet_framework_product": "4.8"},
    )

    assert result["state"] == "applicable"
    assert wrong_host["state"] == "incompatible"


def test_missing_applicability_context_returns_no_target_kb():
    evidence = {
        "state": "unknown",
        "source_data": {
            "windows_product": "windows_server_2022",
            "dotnet_framework_product": "4.8",
        },
    }
    findings = {
        "CVE-2026-62886": [
            ("microsoft", "fixed", "4.8.4805.0", "KB5120705", "generic", evidence)
        ]
    }

    result = _legacy_remediation(findings)

    assert result["selection"] == "ambiguous"
    assert result["fixed"] is None
    assert result["fix_kb"] is None
    assert result["candidates"][0]["fix_kb"] == "KB5120705"


def test_product_variants_with_same_cpe_and_build_are_preserved(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("microsoft", ".net_framework")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    products = [
        {
            "ProductID": f"win11-{architecture}",
            "Value": (
                "Microsoft .NET Framework 4.8.1 on Windows 11 version 26H1 "
                f"for {architecture}-based Systems"
            ),
            "CPE": "cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*",
        }
        for architecture in ("x64", "ARM64")
    ]
    doc = {
        "ProductTree": {"FullProductName": products},
        "Vulnerability": [
            {
                "CVE": "CVE-2026-62886",
                "Remediations": [
                    {
                        "FixedBuild": "4.8.9344.0",
                        "Description": {"Value": "5120711"},
                        "SubType": "Security Update",
                        "ProductID": ["win11-x64", "win11-ARM64"],
                    }
                ],
            }
        ],
    }

    rows = list(_doc_rows(doc))

    assert len(rows) == 2
    assert {_source_data(row)["architecture"] for row in rows} == {"x64", "arm64"}


def test_match_cpe_selects_standard_server_and_dotnet_48_fixes():
    os_rows = [
        (
            "CVE-2026-0001", "microsoft", "10.0", "10.0.20348.5440", None,
            "generic", "fixed", "KB5120229", "windows_server_2022",
            {
                "windows_product": "windows_server_2022",
                "servicing_channel": "hotpatch",
            },
        ),
        (
            "CVE-2026-0001", "microsoft", "10.0", "10.0.20348.5499", None,
            "generic", "fixed", "KB5120242", "windows_server_2022",
            {
                "windows_product": "windows_server_2022",
                "servicing_channel": "standard",
            },
        ),
    ]
    dotnet_rows = [
        (
            "CVE-2026-62886", "microsoft", "4.8", "4.8.4805.0", None,
            "generic", "fixed", "KB5120705", ".net_framework",
            {
                "windows_product": "windows_server_2022",
                "dotnet_framework_product": "4.8",
                "servicing_channel": "standard",
            },
        ),
        (
            "CVE-2026-62886", "microsoft", "4.8", "4.8.9344.0", None,
            "generic", "fixed", "KB5120711", ".net_framework",
            {
                "windows_product": "windows_11_26h1",
                "dotnet_framework_product": "4.8.1",
                "architecture": "x64",
                "servicing_channel": "standard",
            },
        ),
    ]
    host = {
        "windows_product": "windows_server_2022",
        "windows_edition_id": "ServerStandard",
        "architecture": "x64",
    }

    os_findings = match_cpe(
        _RowsConnection(os_rows),
        "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
        "10.0.20348.3091",
        curations={},
        host=host,
    )
    dotnet_findings = match_cpe(
        _RowsConnection(dotnet_rows),
        "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*",
        "4.8.04161",
        curations={},
        host=host,
        component_metadata={"dotnet_framework_product": "4.8"},
    )

    assert os_findings["CVE-2026-0001"][0][3] == "KB5120242"
    assert dotnet_findings["CVE-2026-62886"][0][3] == "KB5120705"


def _row(cve, fixed, name, product="excel", introduced="16.0", **extra):
    return (cve, "microsoft", introduced, fixed, None, "generic", "fixed", None, product,
            {"msrc_product_name": name, **extra})


def test_foreign_platform_rows_never_apply_to_a_windows_host():
    rows = [
        _row("CVE-2026-45649", "16.0.20131.20024", "Microsoft Excel for Android"),
        _row("CVE-2024-49069", "16.0.5478.1002", "Microsoft Excel 2016 (64-bit edition)"),
    ]
    findings = match_cpe(_RowsConnection(rows), "cpe:2.3:a:microsoft:excel:*:*:*:*:*:*:*:*",
                         "16.0.5404.1000", curations={})
    assert "CVE-2026-45649" not in findings          # Android-only CVE on a Windows Excel
    assert "CVE-2024-49069" in findings              # its own Windows fix still applies


def test_windows_subsystem_for_linux_is_a_windows_product():
    evidence = _microsoft_applicability({"msrc_product_name": "Windows Subsystem for Linux (WSL2)"})
    assert evidence["state"] == "applicable"


def test_dotnet_platform_follows_the_component_target_sw():
    rows = [
        _row("CVE-2026-32178", "10.0.6", ".NET 10.0 installed on Mac OS", product=".net_framework",
             introduced="10.0"),
        _row("CVE-2026-26171", "10.0.6", ".NET 10.0 installed on Linux", product=".net_framework",
             introduced="10.0"),
    ]
    on_windows = match_cpe(
        _RowsConnection(rows),
        "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:server:windows_server_2022:x64:10.0.0",
        "10.0.0", curations={})
    on_linux = match_cpe(
        _RowsConnection(rows), "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:linux:*:*",
        "10.0.0", curations={})
    assert on_windows == {}
    assert set(on_linux) == {"CVE-2026-26171"}


def test_per_os_dotnet_products_are_stored_as_dotnet_with_the_runtime_fix(monkeypatch):
    monkeypatch.setattr(cpe_norm, "_VP", {("microsoft", ".net_framework")})
    monkeypatch.setattr(cpe_norm, "_VPU", set())
    monkeypatch.setattr(microsoft, "_DOTNET_SDK_RUNTIME", {"8.0.427": "8.0.33"})
    doc = {
        "ProductTree": {"FullProductName": [
            {"ProductID": "22220", "Value": ".NET 8.0 installed on Windows",
             "CPE": "cpe:2.3:a:microsoft:.net_8.0_installed_on_windows:*:*:*:*:*:*:*:*"},
            {"ProductID": "22221", "Value": ".NET 8.0 installed on Linux",
             "CPE": "cpe:2.3:a:microsoft:.net_8.0_installed_on_linux:*:*:*:*:*:*:*:*"},
        ]},
        "Vulnerability": [{"CVE": "CVE-2026-111497", "Remediations": [
            {"FixedBuild": "8.0.427", "Description": {"Value": "5133964"},
             "SubType": "Security Update", "ProductID": ["22220", "22221"]},
        ]}],
    }

    rows = list(_doc_rows(doc))

    assert [r[COLS.index("cpe23")].split(":")[4] for r in rows] == [".net_framework"] * 2
    assert [(r[COLS.index("introduced")], r[COLS.index("fixed")]) for r in rows] == [("8.0", "8.0.33")] * 2
    assert sorted(_source_data(r)["msrc_product_name"] for r in rows) == [
        ".NET 8.0 installed on Linux", ".NET 8.0 installed on Windows"]


def test_dotnet_family_defaults_from_the_version_when_the_cpe_has_none():
    rows = [
        _row("CVE-2026-70197", "10.0.13", ".NET 10.0 runtime installed on Windows",
             product=".net_framework", introduced="10.0", dotnet_framework_product="10.0.0"),
        _row("CVE-2025-55248", "10.0.14393.8519",
             "Microsoft .NET Framework 4.8 on Windows 10 Version 1607 for x64-based Systems",
             product=".net_framework", introduced="10.0", dotnet_framework_product="4.8"),
    ]
    findings = match_cpe(_RowsConnection(rows), "cpe:2.3:a:microsoft:.net:10.0.5:*:*:*:*:*:*:*",
                         "10.0.5", curations={})
    assert set(findings) == {"CVE-2026-70197"}      # a .NET Framework fix never hits .NET 10


def test_office_msi_host_is_not_compared_against_another_servicing_train():
    rows = [
        _row("CVE-2022-33631", "16.0.14931.20612", "Microsoft Excel 2016 (32-bit edition)"),
        _row("CVE-2024-49059", "16.0.5478.1004", "Microsoft Excel 2016 (32-bit edition)"),
    ]
    findings = match_cpe(_RowsConnection(rows), "cpe:2.3:a:microsoft:excel:*:*:*:*:*:*:*:*",
                         "16.0.5478.1002", curations={})
    assert "CVE-2022-33631" not in findings          # LTSC 2021 build, not the MSI line
    assert "CVE-2024-49059" in findings              # MSI fix 5478.1004 > installed 5478.1002


def test_distinct_office_products_do_not_leak_into_desktop_office():
    rows = [
        _row("CVE-2024-30042", "16.0.10410.20003", "Office Online Server", product="office"),
        _row("CVE-2023-21823", "16.0.14326.21330", "Microsoft Office for Universal", product="office"),
        _row("CVE-2026-20943", "16.0.19426.20170", "Microsoft Office Deployment Tool", product="office"),
    ]
    for build in ("16.0.5404.1000", "16.0.10417.20000", "16.0.14300.20000"):
        findings = match_cpe(_RowsConnection(rows), "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
                             build, curations={})
        assert findings == {}, build


class _RecordingCursor(_RowsCursor):
    def __init__(self, rows, seen):
        super().__init__(rows)
        self.seen = seen

    def execute(self, _sql, params):
        self.seen.append(params)


class _RecordingConnection(_RowsConnection):
    def __init__(self, rows):
        super().__init__(rows)
        self.seen = []

    def cursor(self):
        return _RecordingCursor(self.rows, self.seen)


def test_update_field_is_looked_up_in_both_spellings():
    conn = _RecordingConnection([])
    match_cpe(conn, "cpe:2.3:a:ibm:java:1.8.0:update_231:*:*:*:*:*:*", "1.8.0", curations={})
    keys = conn.seen[0][0]
    assert "cpe:2.3:a:ibm:java:*:update_231:*:*:*:*:*:*" in keys
    assert "cpe:2.3:a:ibm:java:*:update231:*:*:*:*:*:*" in keys


def test_oracle_java_reads_every_row_of_the_product():
    # "and earlier" needs all update keys of the product, not the host's exact key (test_oracle_java)
    conn = _RecordingConnection([])
    match_cpe(conn, "cpe:2.3:a:oracle:jre:1.8.0:update_231:*:*:*:*:*:*", "1.8.0", curations={})
    assert conn.seen[0][0] == ["jre", "java_se"]
