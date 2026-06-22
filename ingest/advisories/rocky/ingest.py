"""Ingest Rocky Linux (Apollo) → advisory/advisory_cve + cve_cvss + cve_cwe + cve_vendor.

origin/source='rocky'. Not a CNA → cve_cvss/cve_cwe.source = NULL (origin identifies);
de-duped in code since NULL source defeats ON CONFLICT. CVSS uses the API's base
score (vector kept too); cve_vendor severity = highest RLSA severity per CVE.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle, vendor_row
from ingest.advisories.rocky.transform import parse, parse_advisory
from ingest.core.cvss import score_from_vector, severity_from_score

ORIGIN = "rocky"
SOURCE = "rocky"
BATCH  = 2_000
_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}


def run(conn, dirs: dict) -> int:
    f = Path(dirs["rocky"]) / "advisories.json"
    if not f.exists():
        print("  rocky: advisories.json not found — run `sync rocky` first")
        return 0
    advs = parse(f.read_bytes())

    delete_scope(conn, ORIGIN, SOURCE)

    cve_sev = {}
    seen_cvss, seen_cwe = set(), set()
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for adv in advs:
            a = parse_advisory(adv)
            if not a:
                continue
            name, title, sev, pub, upd, cves = a
            if not cves:
                continue
            url = f"https://errata.rockylinux.org/{name}"
            b["advisory"].append((SOURCE, name, url, title, sev, pub, upd))
            for cid, vec, score_s, cwe in cves:
                b["spine"].append((cid,))
                b["advisory_cve"].append((SOURCE, name, cid))
                if vec and vec.startswith("CVSS:") and (cid, vec) not in seen_cvss:
                    seen_cvss.add((cid, vec))
                    ver = vec.split("/", 1)[0].split(":", 1)[1]
                    try:
                        score = float(score_s) if score_s else None
                    except ValueError:
                        score = None
                    if score is None:
                        ver, score = score_from_vector(vec)
                    if score is not None:
                        b["cvss"].append((cid, ORIGIN, None, ver, score,
                                          severity_from_score(score, ver), vec))
                if cwe and cwe.startswith("CWE-") and (cid, cwe) not in seen_cwe:
                    seen_cwe.add((cid, cwe))
                    b["cwe"].append((cid, ORIGIN, None, cwe.split()[0]))
                if sev:
                    rk = _SRANK.get(sev.lower(), 0)
                    if rk > cve_sev.get(cid, (0, None))[0]:
                        cve_sev[cid] = (rk, sev)
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for cid, (_, sev) in cve_sev.items():
            vb["cve_vendor"].append(vendor_row(SOURCE, cid, {"severity": sev}))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  rocky: {n:,} RLSAs · {len(cve_sev):,} CVEs · {len(seen_cvss):,} cvss · {len(seen_cwe):,} cwe")
    return n
