from ingest.affected import COLS, cpe_norm
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
    assert result["candidates"][0]["source_fix_kb"] == "KB5120705"


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
