from ingest import json_compat as json
from pathlib import Path
from ingest.db import ingest_records


def _clean(s: str) -> str:
    return (s or "").replace("\x00", "")


def _iter_records(data: dict):
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
        yield {
            "aliases":      [cve_id],
            "has_exploit":  True,
            "cve":          {"cve_id": cve_id},
            "exploits":     exploits,
            "titles": [], "descriptions": [], "cvss": [], "cwes": [],
            "references": [], "advisories": [], "upstream": [],
            "packages": [], "notices": [], "history": [],
        }


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["nuclei"]) / "nuclei_index.json"
    if not index_path.exists():
        print("  Nuclei: index not found — run `sync nuclei` first")
        return

    data: dict = json.loads(index_path.read_bytes())

    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
    print(f"  Nuclei: {len(data)} CVEs with templates")

    total, skipped, errors = ingest_records(
        conn,
        _iter_records(data),
        label="Nuclei",
        cve_filter=cve_filter,
    )
    print(f"  Nuclei: {total} LVE records upserted")
