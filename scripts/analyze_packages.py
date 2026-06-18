"""Analyze sync sources — one output file per vendor, sorted by CVE count desc."""
import json, re
from pathlib import Path
from collections import defaultdict

NVR_RE     = re.compile(r"^(.+?)-\d+[:.].+$")
ALL_ARCHES = {".x86_64",".aarch64",".noarch",".i686",".s390x",".ppc64le",".ppc64",".src"}

def strip_arch_nvr(s):
    for arch in ALL_ARCHES:
        if s.endswith(arch):
            s = s[:-len(arch)]
            break
    m = NVR_RE.match(s)
    return m.group(1) if m else s.split("-")[0]

def write_output(vendor, counts):
    rows = sorted(
        ((name, len(cves)) for name, cves in counts.items()),
        key=lambda x: -x[1]
    )
    out = Path(f"/scripts/{vendor}_packages.md")
    with out.open("w") as fh:
        fh.write(f"# {vendor.title()} Packages\n\n")
        fh.write(f"Distinct packages: **{len(rows)}**\n\n")
        fh.write("| Package | CVE Count |\n")
        fh.write("|---------|----------:|\n")
        for name, cnt in rows:
            fh.write(f"| {name} | {cnt} |\n")
    print(f"  → {out.name}: {len(rows)} packages", flush=True)


# ── Red Hat ───────────────────────────────────────────────────────────────────
rh_dir = Path("/data/redhat/vex")
if rh_dir.exists():
    print("Red Hat...", flush=True)
    counts = defaultdict(set)
    for f in rh_dir.rglob("*.json"):
        try:
            data = json.loads(f.read_bytes())
            vuln = (data.get("vulnerabilities") or [{}])[0]
            cve_id = (vuln.get("cve") or "").upper()
            if not cve_id: continue
            ps = vuln.get("product_status", {})
            for status in ("fixed","known_not_affected","known_affected","under_investigation"):
                for pid in (ps.get(status) or []):
                    colon = pid.find(":")
                    if colon < 0: continue
                    name = strip_arch_nvr(pid[colon+1:])
                    if name:
                        counts[name].add(cve_id)
        except Exception:
            pass
    write_output("redhat", counts)


# ── Ubuntu ────────────────────────────────────────────────────────────────────
usn_dir = Path("/data/ubuntu-usn/usn")
if usn_dir.exists():
    print("Ubuntu...", flush=True)
    counts = defaultdict(set)
    for f in usn_dir.glob("*.json"):
        try:
            data = json.loads(f.read_bytes())
            cves = [c for c in (data.get("cves") or []) if str(c).startswith("CVE-")]
            if not cves: continue
            for rel_data in (data.get("releases") or {}).values():
                # sources: {pkg_name: {version, description}}
                for pkg_name in (rel_data.get("sources") or {}):
                    for cve_id in cves:
                        counts[pkg_name].add(cve_id)
                # binaries: {pkg_name: {version}}
                for pkg_name in (rel_data.get("binaries") or {}):
                    for cve_id in cves:
                        counts[pkg_name].add(cve_id)
        except Exception:
            pass
    write_output("ubuntu", counts)


# ── AlmaLinux ─────────────────────────────────────────────────────────────────
alma_dir = Path("/data/almalinux-errata")
if alma_dir.exists():
    print("AlmaLinux...", flush=True)
    counts = defaultdict(set)
    NEVRA_RE = re.compile(r"^(.+?)-\d+[:.].+\.rpm$")
    for f in alma_dir.glob("[0-9]*.json"):
        try:
            raw = json.loads(f.read_bytes())
            if not isinstance(raw, list): continue
            for item in raw:
                refs = item.get("references") or []
                cve_ids = [r["id"] for r in refs
                           if r.get("type") == "cve" and r.get("id","").startswith("CVE-")]
                if not cve_ids: continue
                pkglist = item.get("pkglist") or {}
                # pkglist can be dict {repo: {packages: [...]}} or dict {repo: repo_name}
                # try nested packages list
                if isinstance(pkglist, dict):
                    for val in pkglist.values():
                        if isinstance(val, dict):
                            for pkg in (val.get("packages") or []):
                                name = pkg.get("name","")
                                if name:
                                    for cve_id in cve_ids:
                                        counts[name].add(cve_id)
                        elif isinstance(val, list):
                            for pkg in val:
                                name = pkg.get("name","") if isinstance(pkg,dict) else ""
                                if name:
                                    for cve_id in cve_ids:
                                        counts[name].add(cve_id)
                elif isinstance(pkglist, list):
                    for pkg in pkglist:
                        name = pkg.get("name","") if isinstance(pkg,dict) else ""
                        if name:
                            for cve_id in cve_ids:
                                counts[name].add(cve_id)
        except Exception:
            pass
    write_output("almalinux", counts)


# ── Rocky ─────────────────────────────────────────────────────────────────────
rocky_dir = Path("/data/rocky-errata/advisories")
if rocky_dir.exists():
    print("Rocky...", flush=True)
    counts = defaultdict(set)
    NEVRA_RE = re.compile(r"^(.+?)-\d+[:.].+$")
    for f in rocky_dir.rglob("*.json"):
        try:
            data = json.loads(f.read_bytes())
            if not isinstance(data, dict): continue
            # cves is list of {cve: "CVE-xxx", ...}
            cve_ids = [c["cve"] for c in (data.get("cves") or [])
                       if isinstance(c, dict) and c.get("cve","").startswith("CVE-")]
            if not cve_ids: continue
            for pkg in (data.get("packages") or []):
                nevra = pkg.get("nevra","")
                # nevra: kernel-0:5.14.0-687.15.1.el9_8.aarch64.rpm
                m = NEVRA_RE.match(nevra)
                name = m.group(1) if m else nevra.split("-")[0]
                if name:
                    for cve_id in cve_ids:
                        counts[name].add(cve_id)
        except Exception:
            pass
    write_output("rocky", counts)

# ── SUSE ─────────────────────────────────────────────────────────────────────
suse_dir = Path("/data/suse-vex")
if suse_dir.exists():
    print("SUSE...", flush=True)
    counts = defaultdict(set)
    for f in suse_dir.rglob("*.json"):
        try:
            data = json.loads(f.read_bytes())
            vuln = (data.get("vulnerabilities") or [{}])[0]
            cve_id = (vuln.get("cve") or "").upper()
            if not cve_id: continue
            ps = vuln.get("product_status", {})
            for status in ("fixed","recommended","known_affected","first_fixed"):
                for pid in (ps.get(status) or []):
                    colon = pid.find(":")
                    if colon < 0: continue
                    pkg_str = pid[colon+1:]
                    parts = pkg_str.split("-")
                    name = pkg_str
                    for i, part in enumerate(parts):
                        if i > 0 and part and part[0].isdigit() and "." in part:
                            name = "-".join(parts[:i])
                            break
                    if name:
                        counts[name].add(cve_id)
        except Exception:
            pass
    write_output("suse", counts)


# ── Debian ────────────────────────────────────────────────────────────────────
deb_file = Path("/data/debian-tracker/data.json")
if deb_file.exists():
    print("Debian...", flush=True)
    counts = defaultdict(set)
    try:
        data = json.loads(deb_file.read_bytes())
        for pkg_name, cves in data.items():
            if not isinstance(cves, dict): continue
            for cve_id in cves:
                if cve_id.startswith("CVE-"):
                    counts[pkg_name].add(cve_id)
    except Exception:
        pass
    write_output("debian", counts)


# ── Alpine ────────────────────────────────────────────────────────────────────
alpine_dir = Path("/data/alpine-secdb")
if alpine_dir.exists():
    print("Alpine...", flush=True)
    counts = defaultdict(set)
    for f in alpine_dir.rglob("*.json"):
        try:
            data = json.loads(f.read_bytes())
            for pkg_entry in (data.get("packages") or []):
                pkg = pkg_entry.get("pkg", {})
                name = pkg.get("name", "")
                for cve_list in (pkg.get("secfixes") or {}).values():
                    for cve_id in (cve_list or []):
                        if str(cve_id).startswith("CVE-"):
                            counts[name].add(cve_id)
        except Exception:
            pass
    write_output("alpine", counts)


# ── Oracle ────────────────────────────────────────────────────────────────────
oracle_dir = Path("/data/oracle-oval")
if oracle_dir.exists():
    print("Oracle...", flush=True)
    import xml.etree.ElementTree as ET
    counts = defaultdict(set)
    for f in oracle_dir.rglob("*.xml"):
        try:
            root = ET.parse(f).getroot()
            ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
            for defn in root.iter(f"{{{ns}}}definition"):
                meta = defn.find(f".//{{{ns}}}metadata")
                if meta is None: continue
                cve_ids = [
                    r.get("ref_id","") for r in meta.iter(f"{{{ns}}}reference")
                    if r.get("source") == "CVE" and r.get("ref_id","").startswith("CVE-")
                ]
                if not cve_ids: continue
                for crit in defn.iter(f"{{{ns}}}criterion"):
                    m = re.match(r"^(\S+)\s+is\s+", crit.get("comment",""))
                    if m:
                        for cve_id in cve_ids:
                            counts[m.group(1)].add(cve_id)
        except Exception:
            pass
    write_output("oracle", counts)


print("Done.", flush=True)
