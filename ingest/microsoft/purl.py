import re
from typing import Optional


def _purl(type_: str, namespace: str, name: str, version: str = None, **qualifiers) -> str:
    """Build a canonical PURL: version in @, qualifiers sorted alphabetically."""
    base = f"pkg:{type_}/{namespace}/{name}"
    if version:
        base += f"@{version}"
    active = {k: v for k, v in qualifiers.items() if v}
    if active:
        base += "?" + "&".join(f"{k}={v}" for k, v in sorted(active.items()))
    return base


def derive_identifiers(product_name: str) -> tuple[Optional[str], Optional[str]]:
    """Return (purl, cpe) for an MSRC product name. Either may be None."""
    if not product_name:
        return None, None

    # ── Azure Linux / CBL Mariner platform nodes — skip ──────────────────────
    if re.match(r"^(Azure Linux|CBL Mariner) \d", product_name):
        return None, None

    # ── RPM full-filename entries ─────────────────────────────────────────────
    # "mysql-8.0.26-1.cm1.x86_64.rpm on CBL Mariner 1.0 x64"
    # "libdb-5.3.28-8.azl3.x86_64.rpm on Azure Linux 3.0 x64"
    m = re.match(r"^(.+?)-(\d[\w.~\-]+?)\.(?:cm\d|azl\d)\.\w+\.rpm on (CBL Mariner|Azure Linux)", product_name)
    if m:
        pkg, ver, distro = m.group(1), m.group(2), m.group(3)
        ns = "azurelinux" if "Azure" in distro else "cbl-mariner"
        return _purl("rpm", ns, pkg, ver), None

    # ── CBL Mariner / Azure Linux named package entries ───────────────────────
    m = re.match(r"^azl3 (\S+)\s+(?:(?!on\s)(\S+)\s+)?on Azure Linux 3\.0", product_name)
    if m:
        return _purl("rpm", "azurelinux", m.group(1), m.group(2)), None

    m = re.match(r"^(?:cbl2|cm2) (\S+)\s+(?:(?!on\s)(\S+)\s+)?on CBL Mariner 2\.0", product_name)
    if m:
        return _purl("rpm", "cbl-mariner", m.group(1), m.group(2)), None

    m = re.match(r"^cm1 (\S+)\s+(?:(?!on\s)(\S+)\s+)?on CBL Mariner 1\.0", product_name)
    if m:
        return _purl("rpm", "cbl-mariner", m.group(1), m.group(2), distro="cbl-mariner-1.0"), None

    m = re.match(r"^(\S+) (\S+) \(Azure Linux 2\.0", product_name)
    if m:
        return _purl("rpm", "azurelinux", m.group(1), m.group(2)), None

    # ── Windows Server SAC ────────────────────────────────────────────────────
    m = re.search(r"Windows Server, version (\w+)", product_name)
    if m:
        v       = m.group(1).lower()
        variant = "server-core" if "Server Core" in product_name else None
        purl    = _purl("generic", "microsoft", "windows-server", v, variant=variant)
        cpe     = f"cpe:2.3:o:microsoft:windows_server:{v}:*:*:*:*:*:*:*"
        return purl, cpe

    # ── Windows Server LTSC ───────────────────────────────────────────────────
    _WS = [
        (r"Windows Server 2025 \(Server Core",      "windows-server-2025",     "windows_server_2025",     "server-core"),
        (r"Windows Server 2025",                     "windows-server-2025",     "windows_server_2025",     None),
        (r"Windows Server 2022, 23H2.*Server Core",  "windows-server-2022-23h2","windows_server_2022_23h2","server-core"),
        (r"Windows Server 2022, 23H2",               "windows-server-2022-23h2","windows_server_2022_23h2", None),
        (r"Windows Server 2022 \(Server Core",       "windows-server-2022",     "windows_server_2022",     "server-core"),
        (r"Windows Server 2022",                     "windows-server-2022",     "windows_server_2022",     None),
        (r"Windows Server 2019 \(Server Core",       "windows-server-2019",     "windows_server_2019",     "server-core"),
        (r"Windows Server 2019",                     "windows-server-2019",     "windows_server_2019",     None),
        (r"Windows Server 2016 \(Server Core",       "windows-server-2016",     "windows_server_2016",     "server-core"),
        (r"Windows Server 2016",                     "windows-server-2016",     "windows_server_2016",     None),
        (r"Windows Server 2012 R2 \(Server Core",    "windows-server-2012-r2",  "windows_server_2012_r2",  "server-core"),
        (r"Windows Server 2012 R2",                  "windows-server-2012-r2",  "windows_server_2012_r2",  None),
        (r"Windows Server 2012 \(Server Core",       "windows-server-2012",     "windows_server_2012",     "server-core"),
        (r"Windows Server 2012",                     "windows-server-2012",     "windows_server_2012",     None),
        (r"Windows Server 2008 R2",                  "windows-server-2008-r2",  "windows_server_2008_r2",  None),
        (r"Windows Server 2008",                     "windows-server-2008",     "windows_server_2008",     None),
    ]
    for pattern, slug, cpe_product, variant in _WS:
        if re.search(pattern, product_name):
            purl = _purl("generic", "microsoft", slug, variant=variant)
            if cpe_product.endswith("_r2"):
                cpe = f"cpe:2.3:o:microsoft:{cpe_product[:-3]}:r2:*:*:*:*:*:*:*"
            else:
                cpe = f"cpe:2.3:o:microsoft:{cpe_product}:-:*:*:*:*:*:*:*"
            return purl, cpe

    # ── Windows 11 ────────────────────────────────────────────────────────────
    m = re.search(r"Windows 11 [Vv]ersion (\w+) for (ARM64|ARM|x64|x86|32-bit)", product_name)
    if m:
        v    = m.group(1).lower()
        arch = "arm64" if m.group(2).upper().startswith("ARM") else m.group(2).lower()
        return (_purl("generic", "microsoft", "windows-11", v, arch=arch),
                f"cpe:2.3:o:microsoft:windows_11_{v}:*:*:*:*:*:*:{arch}:*")

    # ── Windows 10 ────────────────────────────────────────────────────────────
    m = re.search(r"Windows 10 Version (\w+) for (ARM64|x64|x86|32-bit)", product_name)
    if m:
        v    = m.group(1).lower()
        arch = m.group(2).lower().replace("32-bit", "x86")
        return (_purl("generic", "microsoft", "windows-10", v, arch=arch),
                f"cpe:2.3:o:microsoft:windows_10_{v}:*:*:*:*:*:*:{arch}:*")

    m = re.search(r"Windows 10 for (ARM64|x64|x86|32-bit)", product_name)
    if m:
        arch = m.group(1).lower().replace("32-bit", "x86")
        return (_purl("generic", "microsoft", "windows-10", arch=arch),
                f"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:{arch}:*")

    # ── Windows 8.1 / RT / 7 / Vista ─────────────────────────────────────────
    if re.search(r"Windows RT 8\.1", product_name):
        return _purl("generic", "microsoft", "windows-rt-8.1"), "cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*"
    if re.search(r"Windows 8\.1", product_name):
        return _purl("generic", "microsoft", "windows-8.1"), "cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*"
    if re.search(r"Windows 7", product_name):
        return _purl("generic", "microsoft", "windows-7"), "cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*"
    if re.search(r"Windows Vista", product_name):
        return _purl("generic", "microsoft", "windows-vista"), "cpe:2.3:o:microsoft:windows_vista:-:*:*:*:*:*:*:*"

    # ── Remote Desktop / Windows App client ───────────────────────────────────
    if re.search(r"Remote Desktop client|Windows App Client", product_name):
        return _purl("generic", "microsoft", "remote-desktop-client"), "cpe:2.3:a:microsoft:remote_desktop:-:*:*:*:*:*:*:*"

    # ── Internet Explorer ─────────────────────────────────────────────────────
    m = re.search(r"Internet Explorer (\d+)", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "internet-explorer", v),
                f"cpe:2.3:a:microsoft:internet_explorer:{v}:*:*:*:*:*:*:*")

    # ── Visual Studio / VS Code ───────────────────────────────────────────────
    if re.search(r"Visual Studio Code", product_name):
        return (_purl("generic", "microsoft", "visual-studio-code"),
                "cpe:2.3:a:microsoft:visual_studio_code:-:*:*:*:*:*:*:*")
    m = re.search(r"Microsoft Visual Studio (\d{4})", product_name)
    if m:
        v = m.group(1)
        # NVD uses visual_studio_YYYY for 2017+ but visual_studio:YYYY for older
        if int(v) < 2017:
            cpe = f"cpe:2.3:a:microsoft:visual_studio:{v}:*:*:*:*:*:*:*"
        else:
            cpe = f"cpe:2.3:a:microsoft:visual_studio_{v}:*:*:*:*:*:*:*:*"
        return (_purl("generic", "microsoft", "visual-studio", v), cpe)
    if re.search(r"Microsoft Visual Studio", product_name):
        return (_purl("generic", "microsoft", "visual-studio"),
                "cpe:2.3:a:microsoft:visual_studio:-:*:*:*:*:*:*:*")

    # ── SQL Server ────────────────────────────────────────────────────────────
    m = re.search(r"Microsoft SQL Server (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "sql-server", v),
                f"cpe:2.3:a:microsoft:sql_server:{v}:*:*:*:*:*:*:*")

    # ── ODBC / OLE DB Driver for SQL Server ──────────────────────────────────
    m = re.search(r"(?:ODBC|OLE DB) Driver (\d+) for SQL Server", product_name)
    if m:
        v    = m.group(1)
        kind_purl = "odbc" if "ODBC" in product_name else "ole-db"
        kind_cpe  = "odbc" if "ODBC" in product_name else "ole_db"
        return (_purl("generic", "microsoft", f"sql-server-{kind_purl}-driver", v),
                f"cpe:2.3:a:microsoft:{kind_cpe}_driver_for_sql_server:{v}:*:*:*:*:*:*:*")

    # ── Exchange Server ───────────────────────────────────────────────────────
    if re.search(r"Exchange Server Subscription Edition", product_name):
        return (_purl("generic", "microsoft", "exchange-server", "subscription"),
                "cpe:2.3:a:microsoft:exchange_server:subscription:*:*:*:*:*:*:*")
    m = re.search(r"Microsoft Exchange Server (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "exchange-server", v),
                f"cpe:2.3:a:microsoft:exchange_server:{v}:*:*:*:*:*:*:*")

    # ── SharePoint ────────────────────────────────────────────────────────────
    if re.search(r"SharePoint.*Subscription Edition", product_name):
        return (_purl("generic", "microsoft", "sharepoint-server", "subscription"),
                "cpe:2.3:a:microsoft:sharepoint_server:subscription:*:*:*:*:*:*:*")
    m = re.search(r"Microsoft SharePoint (?:Server|Enterprise Server|Foundation) (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "sharepoint-server", v),
                f"cpe:2.3:a:microsoft:sharepoint_server:{v}:*:*:*:*:*:*:*")

    # ── .NET Framework ────────────────────────────────────────────────────────
    m = re.search(r"(?:Microsoft )?\.NET Framework ([\d.]+)", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "dotnet-framework", v),
                f"cpe:2.3:a:microsoft:.net_framework:{v}:*:*:*:*:*:*:*")

    # ── .NET Core / 5+ ───────────────────────────────────────────────────────
    m = re.search(r"(?<!\w)\.NET(?:\s+Core)? ([\d.]+)", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "dotnet", v),
                f"cpe:2.3:a:microsoft:.net:{v}:*:*:*:*:*:*:*")

    # ── PowerShell ────────────────────────────────────────────────────────────
    m = re.search(r"PowerShell(?:\s+Core)? ([\d.]+)", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "powershell", v),
                f"cpe:2.3:a:microsoft:powershell:{v}:*:*:*:*:*:*:*")

    # ── Microsoft Edge (Chromium) ─────────────────────────────────────────────
    if re.search(r"Microsoft Edge", product_name):
        return (_purl("generic", "microsoft", "edge"),
                "cpe:2.3:a:microsoft:edge_chromium:-:*:*:*:*:*:*:*")

    # ── Office 365 / Microsoft 365 ───────────────────────────────────────────
    if re.search(r"Microsoft 365 Apps|Office 365 ProPlus", product_name):
        return (_purl("generic", "microsoft", "microsoft-365-apps"),
                "cpe:2.3:a:microsoft:365_apps:-:*:*:*:*:*:*:*")

    if re.search(r"Office Online Server|Office Web Apps", product_name):
        return (_purl("generic", "microsoft", "office-online-server"),
                "cpe:2.3:a:microsoft:office_online_server:-:*:*:*:*:*:*:*")

    if re.search(r"Microsoft Office LTSC for Mac", product_name):
        m = re.search(r"(\d{4})", product_name)
        if m:
            return _purl("generic", "microsoft", "office-ltsc-mac", m.group(1)), None

    m = re.search(r"Microsoft Office (?:LTSC )?(\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "office", v),
                f"cpe:2.3:a:microsoft:office:{v}:*:*:*:*:*:*:*")

    if re.search(r"Office Compatibility Pack", product_name):
        return _purl("generic", "microsoft", "office-compatibility-pack"), None

    if re.search(r"Office.*Viewer|Word Viewer|Excel Viewer", product_name):
        return _purl("generic", "microsoft", "office-viewer"), None

    if re.search(r"Microsoft Office for Android", product_name):
        return (_purl("generic", "microsoft", "office-android"),
                "cpe:2.3:a:microsoft:office:-:*:*:*:*:android:*:*")

    # ── Office apps (standalone) ──────────────────────────────────────────────
    m = re.search(r"Microsoft (Access|Excel|Word|Outlook|PowerPoint|Publisher|Visio|Project) (\d{4})", product_name)
    if m:
        app, v = m.group(1).lower(), m.group(2)
        return (_purl("generic", "microsoft", f"office-{app}", v),
                f"cpe:2.3:a:microsoft:{app}:{v}:*:*:*:*:*:*:*")

    # ── Azure DevOps Server ───────────────────────────────────────────────────
    m = re.search(r"Azure DevOps Server (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "azure-devops-server", v),
                f"cpe:2.3:a:microsoft:azure_devops_server:{v}:*:*:*:*:*:*:*")

    # ── Skype for Business ────────────────────────────────────────────────────
    m = re.search(r"Skype for Business(?:\s+Server)? (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "skype-for-business", v),
                f"cpe:2.3:a:microsoft:skype_for_business:{v}:*:*:*:*:*:*:*")

    # ── Lync ──────────────────────────────────────────────────────────────────
    m = re.search(r"Microsoft Lync(?:\s+Basic)? (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "lync", v),
                f"cpe:2.3:a:microsoft:lync:{v}:*:*:*:*:*:*:*")

    # ── Team Foundation Server ────────────────────────────────────────────────
    m = re.search(r"Team Foundation Server (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "team-foundation-server", v),
                f"cpe:2.3:a:microsoft:team_foundation_server:{v}:*:*:*:*:*:*:*")

    # ── ChakraCore ────────────────────────────────────────────────────────────
    if re.search(r"ChakraCore", product_name):
        return (_purl("generic", "microsoft", "chakracore"),
                "cpe:2.3:a:microsoft:chakracore:-:*:*:*:*:*:*:*")

    # ── Dynamics ──────────────────────────────────────────────────────────────
    m = re.search(r"Dynamics NAV (\d{4})", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "dynamics-nav", v),
                f"cpe:2.3:a:microsoft:dynamics_nav:{v}:*:*:*:*:*:*:*")
    if re.search(r"Dynamics Business Central", product_name):
        m = re.search(r"(\d{4})", product_name)
        v = m.group(1) if m else None
        return (_purl("generic", "microsoft", "dynamics-business-central", v),
                f"cpe:2.3:a:microsoft:dynamics_365_business_central:{v or '-'}:*:*:*:*:*:*:*")
    if re.search(r"Dynamics CRM", product_name):
        m = re.search(r"(\d{4})", product_name)
        v = m.group(1) if m else None
        # NVD uses dynamics_crm_YYYY as product name, no standalone dynamics_crm
        cpe_product = f"dynamics_crm_{v}" if v else None
        return (_purl("generic", "microsoft", "dynamics-crm", v),
                f"cpe:2.3:a:microsoft:{cpe_product}:*:*:*:*:*:*:*:*" if cpe_product else None)
    m = re.search(r"Dynamics 365.*?(\d+\.\d+)", product_name)
    if m:
        v = m.group(1)
        return (_purl("generic", "microsoft", "dynamics-365", v),
                f"cpe:2.3:a:microsoft:dynamics_365:{v}:*:*:*:*:*:*:*")
    if re.search(r"Dynamics 365", product_name):
        return (_purl("generic", "microsoft", "dynamics-365"),
                "cpe:2.3:a:microsoft:dynamics_365:-:*:*:*:*:*:*:*")

    # ── Azure Sphere ──────────────────────────────────────────────────────────
    if re.search(r"Azure Sphere", product_name):
        return (_purl("generic", "microsoft", "azure-sphere"),
                "cpe:2.3:a:microsoft:azure_sphere:-:*:*:*:*:*:*:*")

    # ── Azure Site Recovery ───────────────────────────────────────────────────
    if re.search(r"Azure Site Recovery", product_name):
        return (_purl("generic", "microsoft", "azure-site-recovery"),
                "cpe:2.3:a:microsoft:azure_site_recovery:-:*:*:*:*:*:*:*")

    # ── Microsoft Defender for IoT ────────────────────────────────────────────
    if re.search(r"Defender for IoT", product_name):
        return (_purl("generic", "microsoft", "defender-for-iot"),
                "cpe:2.3:a:microsoft:defender_for_iot:-:*:*:*:*:*:*:*")

    # ── 3D Builder / HEVC ────────────────────────────────────────────────────
    if re.search(r"3D Builder", product_name):
        return _purl("generic", "microsoft", "3d-builder"), None
    if re.search(r"HEVC Video Extensions", product_name):
        return _purl("generic", "microsoft", "hevc-video-extensions"), None

    return None, None
