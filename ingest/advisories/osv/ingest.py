"""Ingest OSV native ecosystem advisories → advisory + advisory_cve (L3).

Sources written: pypa · go · rustsec · eef · drupal. No cve_* enrichment
(GHSA/cvelistv5 own that); purls/versions are L4.
"""
import zipfile
from pathlib import Path

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.osv.transform import parse, transform

SOURCES = ("pypa", "go", "rustsec", "eef", "drupal")
BATCH   = 2_000


def run(conn, dirs: dict) -> int:
    zips = sorted(Path(dirs["osv"]).glob("*.zip"))
    if not zips:
        print("  osv: no zips — run `sync osv` first")
        return 0
    for s in SOURCES:
        delete_scope(conn, s, s)

    b = new_bundle()
    n = 0
    skipped = 0
    per = {}
    seen_desc = set()
    with conn.cursor() as cur:
        # GHSA's precise CVE→purl map disambiguates PYSEC/RustSec/… loose multi-CVE aliases
        cur.execute("SELECT cve_id, data->'packages' FROM cve_vendor WHERE source = 'ghsa'")
        ghsa_purls = {cid: {p["purl"] for p in (pkgs or []) if p.get("purl")}
                      for cid, pkgs in cur.fetchall()}

        for zf in zips:
            z = zipfile.ZipFile(zf)
            for name in z.namelist():
                a = transform(parse(z.read(name)))
                if not a:
                    continue
                b["advisory"].append((a["source"], a["id"], a["url"], a["title"],
                                      None, a["published"], a["modified"]))
                multi = len(a["cves"]) > 1
                for cid in a["cves"]:
                    # multi-CVE alias + the CVE has a known (GHSA) package that the
                    # advisory's package does NOT cover → loose cross-alias, drop the link
                    known = ghsa_purls.get(cid)
                    if multi and known and a["purls"] and not (a["purls"] & known):
                        skipped += 1
                        continue
                    b["spine"].append((cid,))
                    b["advisory_cve"].append((a["source"], a["id"], cid))
                    if a["details"] and (cid, a["source"]) not in seen_desc:
                        seen_desc.add((cid, a["source"]))
                        b["desc"].append((cid, a["source"], None, "en", a["details"]))
                per[a["source"]] = per.get(a["source"], 0) + 1
                n += 1
                if n % BATCH == 0:
                    flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    print(f"  osv: {n:,} native advisories · " + " · ".join(f"{k}={v}" for k, v in sorted(per.items()))
          + f" · {skipped} cross-alias links dropped")
    return n
