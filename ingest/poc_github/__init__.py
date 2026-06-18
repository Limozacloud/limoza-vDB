import json
from pathlib import Path
from ingest.db import upsert_lve_record


def _date(val) -> str | None:
    return val[:10] if val else None


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["poc_github"])
    if not base.exists():
        print("  PoC-in-GitHub: data not found — run `sync poc_github` first")
        return

    if cve_filter:
        year  = cve_filter.split("-")[1]
        files = [f for f in [base / year / f"{cve_filter}.json"] if f.exists()]
    else:
        files = sorted(base.rglob("CVE-*.json"))
    print(f"  PoC-in-GitHub: {len(files)} CVE files")

    total = 0
    with conn.cursor() as cur:
        for f in files:
            try:
                entries = json.loads(f.read_bytes())
                if not isinstance(entries, list) or not entries:
                    continue
                cve_id = f.stem
                if not cve_id.startswith("CVE-"):
                    continue

                exploits = [
                    {
                        "source":    "poc_github",
                        "source_id": repo.get("full_name", ""),
                        "name":      (repo.get("description") or "")[:200],
                        "url":       repo.get("html_url") or f"https://github.com/{repo.get('full_name', '')}",
                        "metadata":  {
                            "stars":      int(repo.get("stargazers_count") or 0),
                            "created_at": _date(repo.get("created_at")),
                            "pushed_at":  _date(repo.get("pushed_at")),
                            "is_fork":    bool(repo.get("fork", False)),
                        },
                    }
                    for repo in entries
                    if repo.get("full_name")
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
            except Exception as e:
                print(f"  Error {f.name}: {e}")

    conn.commit()
    print(f"  PoC-in-GitHub: {total} LVE records upserted")
