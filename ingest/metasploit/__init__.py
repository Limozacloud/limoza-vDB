import json
from pathlib import Path
from ingest.db import upsert_lve_record


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["metasploit"]) / "metasploit_index.json"
    if not index_path.exists():
        print("  Metasploit: index not found — run `sync metasploit` first")
        return

    data: dict = json.loads(index_path.read_bytes())

    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
    print(f"  Metasploit: {len(data)} CVEs with modules")

    total = 0
    with conn.cursor() as cur:
        for cve_id, entries in data.items():
            exploits = [
                {
                    "source":    "metasploit",
                    "source_id": e.get("module", ""),
                    "name":      e.get("name", ""),
                    "url":       f"https://github.com/rapid7/metasploit-framework/blob/master/modules/{e.get('module', '')}.rb",
                    "metadata":  {"rank": e.get("rank", ""), "type": e.get("type", "")},
                }
                for e in entries
            ]
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
    print(f"  Metasploit: {total} LVE records upserted")
