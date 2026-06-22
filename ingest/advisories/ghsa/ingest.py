"""Ingest GHSA (github-reviewed) → advisory + advisory_cve + cve_cvss/cve_cwe
+ cve_vendor (affected ecosystem packages).

origin/source='ghsa'. cve_* source = GitHub's CNA uuid (GitHub_M). The affected
packages (purl + version ranges) are aggregated per CVE into cve_vendor.data —
L3 ecosystem + L4 ranges — pending the phase-3 affected table.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.ghsa.transform import parse, transform

ORIGIN = "ghsa"
SOURCE = "ghsa"
BATCH  = 2_000


def _source_uuid(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT uuids[1] FROM cna WHERE lower(short_name) = %s", ("github_m",))
        r = cur.fetchone()
        return r[0] if r and r[0] else None


def run(conn, dirs: dict) -> int:
    base = Path(dirs["ghsa"]) / "advisories" / "github-reviewed"
    if not base.exists():
        print("  ghsa: no advisories — run `sync ghsa` first")
        return 0
    src = _source_uuid(conn)
    print(f"  ghsa: source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    cve_pkgs = {}                      # cid -> {"packages":[], "ghsa":[], "_seen":set()}
    seen_cvss, seen_cwe, seen_desc = set(), set(), set()
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for f in base.rglob("*.json"):
            a = transform(parse(f.read_bytes()), src)
            if not a:
                continue
            b["advisory"].append((SOURCE, a["id"], a["url"], a["title"],
                                  a["severity"], a["published"], a["modified"]))
            for cid in a["cves"]:
                b["spine"].append((cid,))
                b["advisory_cve"].append((SOURCE, a["id"], cid))
                if a["details"] and cid not in seen_desc:
                    seen_desc.add(cid)
                    b["desc"].append((cid, ORIGIN, src, "en", a["details"]))
                for s, ver, sc, sev, vec in a["cvss"]:
                    if (cid, vec) in seen_cvss:
                        continue
                    seen_cvss.add((cid, vec))
                    b["cvss"].append((cid, ORIGIN, s, ver, sc, sev, vec))
                for s, cw in a["cwe"]:
                    if (cid, cw) in seen_cwe:
                        continue
                    seen_cwe.add((cid, cw))
                    b["cwe"].append((cid, ORIGIN, s, cw))
                acc = cve_pkgs.setdefault(cid, {"packages": [], "ghsa": [], "_seen": set()})
                acc["ghsa"].append(a["id"])
                for p in a["packages"]:
                    key = (p["purl"], p["ranges"])
                    if key not in acc["_seen"]:
                        acc["_seen"].add(key)
                        acc["packages"].append(p)
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for cid, acc in cve_pkgs.items():
            data = {"packages": acc["packages"], "ghsa": acc["ghsa"]}
            vb["cve_vendor"].append((cid, SOURCE, Json(data)))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  ghsa: {n:,} advisories · {len(cve_pkgs):,} CVEs · "
          f"cvss {len(seen_cvss):,} · cwe {len(seen_cwe):,}")
    return n
