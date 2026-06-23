"""Ingest AlmaLinux errata → advisory/advisory_cve + cve_vendor (origin/source='almalinux').

Not a CNA → no cve_cvss/cve_cwe (Alma carries none anyway). cve_vendor severity =
the highest ALSA severity seen per CVE.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.almalinux.transform import parse, parse_advisory

ORIGIN = "almalinux"
SOURCE = "almalinux"
BATCH  = 2_000
_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}


def run(conn, dirs: dict) -> int:
    base = Path(dirs["almalinux"])
    files = sorted(base.glob("[0-9]*.json"))
    if not files:
        print("  almalinux: no errata json — run `sync almalinux` first")
        return 0

    delete_scope(conn, ORIGIN, SOURCE)

    cve_sev = {}
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for f in files:
            major = f.stem
            data = parse(f.read_bytes())
            advs = data if isinstance(data, list) else (data.get("data") or [])
            for adv in advs:
                a = parse_advisory(adv)
                if not a:
                    continue
                aid, title, sev, iss, upd, cves = a
                if not cves:
                    continue
                url = f"https://errata.almalinux.org/{major}/{aid.replace(':', '-')}.html"
                b["advisory"].append((SOURCE, aid, url, title, sev, iss, upd))
                for c in cves:
                    b["spine"].append((c,))
                    b["advisory_cve"].append((SOURCE, aid, c))
                    if sev:
                        rk = _SRANK.get(sev.lower(), 0)
                        if rk > cve_sev.get(c, (0, None))[0]:
                            cve_sev[c] = (rk, sev)
                n += 1
                if n % BATCH == 0:
                    flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for c, (_, sev) in cve_sev.items():
            vb["cve_vendor"].append((c, SOURCE, Json({"severity": sev})))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  almalinux: {n:,} ALSAs · {len(cve_sev):,} CVEs")
    return n
