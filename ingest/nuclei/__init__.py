import json
from pathlib import Path
from ingest.db import upsert_lve_record


def _clean(s: str) -> str:
    return (s or "").replace("\x00", "")


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["nuclei"]) / "nuclei_index.json"
    if not index_path.exists():
        print("  Nuclei: index not found — run `sync nuclei` first")
        return

    data: dict = json.loads(index_path.read_bytes())

    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
    print(f"  Nuclei: {len(data)} CVEs with templates")

    total = 0
    with conn.cursor() as cur:
        for cve_id, entries in data.items():
            exploits = [
                {
                    "source":    "nuclei",
                    "source_id": e.get("id", cve_id),
                    "name":      _clean(e.get("name", "")),
                    "url":       e.get("url", ""),
                    "metadata":  {
                        "severity":    e.get("severity", ""),
                        "description": _clean(e.get("description") or "")[:500],
                    },
                }
                for e in entries
                if e.get("url")
            ]
            if not exploits:
                continue
            upsert_lve_record(cur, {
                "aliases":      [cve_id],
                "has_exploit":  True,
                "cve":          {"cve_id": cve_id},
                "exploits":     exploits,
                "titles": [], "descriptions": [], "cvss": [], "cwes": [],
                "references": [], "advisories": [], "upstream": [],
                "packages": [], "notices": [], "history": [],
            })
            total += 1

    conn.commit()
    print(f"  Nuclei: {total} LVE records upserted")
