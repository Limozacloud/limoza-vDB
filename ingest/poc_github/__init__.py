from ingest import json_compat as json
import multiprocessing as mp
from pathlib import Path
from ingest.db import ingest_files
from ingest.incremental import ImportState

N_WORKERS = mp.cpu_count()


def _date(val) -> str | None:
    return val[:10] if val else None


def _transform_file(f: Path):
    entries = json.loads(f.read_bytes())
    if not isinstance(entries, list) or not entries:
        return None
    cve_id = f.stem
    if not cve_id.startswith("CVE-"):
        return None

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
        return None

    return {
        "aliases":      [cve_id],
        "has_exploit":  True,
        "cve":          {"cve_id": cve_id},
        "exploits":     exploits,
        "titles": [], "descriptions": [], "cvss": [], "cwes": [],
        "references": [], "advisories": [], "upstream": [],
        "packages": [], "notices": [], "history": [],
    }


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["poc_github"])
    if not base.exists():
        print("  PoC-in-GitHub: data not found — run `sync poc_github` first")
        return

    state = ImportState(base / ".import_state.json", base)

    if cve_filter:
        year  = cve_filter.split("-")[1]
        files = [f for f in [base / year / f"{cve_filter}.json"] if f.exists()]
    else:
        all_files = sorted(base.rglob("CVE-*.json"))
        files = state.changed(all_files)
    print(f"  PoC-in-GitHub: {len(files)} CVE files")

    total, skipped, errors = ingest_files(
        conn,
        files,
        _transform_file,
        label="PoC-in-GitHub",
        cve_filter=cve_filter,
        n_workers=N_WORKERS if not cve_filter else 1,
        state=state if not cve_filter else None,
    )
    print(f"  PoC-in-GitHub: {total} LVE records upserted")
