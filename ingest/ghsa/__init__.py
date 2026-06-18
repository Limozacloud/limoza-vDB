import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.ghsa.transform import transform


def _walk(base: Path):
    for subdir in ("github-reviewed", "unreviewed"):
        d = base / "advisories" / subdir
        if d.exists():
            yield from d.rglob("GHSA-*.json")


def _build_index(base: Path) -> dict:
    idx: dict[str, list] = {}
    for f in _walk(base):
        try:
            raw = f.read_bytes()
            if b"CVE-" not in raw:
                continue
            data = json.loads(raw)
            for alias in (data.get("aliases") or []):
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    idx.setdefault(alias, []).append(str(f.relative_to(base)))
        except Exception:
            pass
    out = base / "cve_index.json"
    out.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    return idx


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["ghsa"])
    if not base.exists():
        print(f"  GHSA: {base} not found — run `sync ghsa` first")
        return

    if cve_filter:
        index_path = base / "cve_index.json"
        if index_path.exists():
            idx = json.loads(index_path.read_bytes())
        else:
            print("  GHSA: building CVE index (~2 min on first run)...")
            idx = _build_index(base)
        files = [base / p for p in idx.get(cve_filter, [])]
        print(f"  GHSA: filter {cve_filter} → {len(files)} advisories")
    else:
        files = list(_walk(base))
        print(f"  GHSA: {len(files)} advisory files")

    total   = 0
    skipped = 0
    with conn.cursor() as cur:
        for f in files:
            try:
                records = transform(json.loads(Path(f).read_bytes()))
                for r in records:
                    upsert_lve_record(cur, r)
                    total += 1
                if not records:
                    skipped += 1
            except Exception as e:
                print(f"  Error {Path(f).name}: {e}")

    conn.commit()
    print(f"  GHSA: {total} LVE records upserted · {skipped} skipped (no CVE alias or withdrawn)")
