"""Ingest Debian security-tracker → cve_desc + cve_vendor (origin/source='debian').

Single pass: load the tracker JSON, invert package→CVE, write description +
urgency/scope. Debian has no formal CVE-level advisory feed we can fetch, so no
advisory rows; per-release fixed versions are phase-3 affected.
"""
import json
import zipfile
from pathlib import Path


from ingest.advisories import delete_scope, flush, new_bundle, vendor_row
from ingest.advisories.debian.transform import invert, parse, parse_osv_advisory

ORIGIN = "debian"
SOURCE = "debian"
BATCH  = 5_000


def run(conn, dirs: dict) -> int:
    f = Path(dirs["debian"]) / "tracker.json"
    if not f.exists():
        print("  debian: tracker.json not found — run `sync debian` first")
        return 0
    per = invert(parse(f.read_bytes()))
    print(f"  debian: {len(per):,} distinct CVEs")

    delete_scope(conn, ORIGIN, SOURCE)

    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for cid, e in per.items():
            b["spine"].append((cid,))
            if e["desc"]:
                b["desc"].append((cid, ORIGIN, None, "en", e["desc"]))   # Debian = non-CNA → source NULL
            data = {}
            if e["urgency"]:
                data["urgency"] = e["urgency"]
            if e["scope"]:
                data["scope"] = e["scope"]
            if data:
                b["cve_vendor"].append(vendor_row(SOURCE, cid, data))
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

    adv = _ingest_advisories(conn, Path(dirs["debian"]) / "osv.zip")
    print(f"  debian: {n:,} CVEs (desc + urgency/scope) · {adv:,} DSA/DLA advisories")
    return n


def _ingest_advisories(conn, zip_path) -> int:
    """DSA/DLA/DTSA advisories from the OSV Debian export → advisory + advisory_cve."""
    if not zip_path.exists():
        print("  debian: osv.zip not found — skipping advisory pass")
        return 0
    z = zipfile.ZipFile(zip_path)
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for fn in z.namelist():
            if not (fn.startswith(("DSA-", "DLA-", "DTSA-")) and fn.endswith(".json")):
                continue
            try:
                a = parse_osv_advisory(json.loads(z.read(fn)))
            except Exception:
                continue
            if not a:
                continue
            aid, title, pub, mod, cves = a
            if not cves:
                continue
            url = f"https://security-tracker.debian.org/tracker/{aid}"
            b["advisory"].append((SOURCE, aid, url, title, None, pub, mod))
            for c in set(cves):
                b["spine"].append((c,))
                b["advisory_cve"].append((SOURCE, aid, c))
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    return n
