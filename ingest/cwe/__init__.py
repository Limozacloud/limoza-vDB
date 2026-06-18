"""CWE name lookup from local json_repo/W/ clone."""
import json
from pathlib import Path

_cache: dict[str, str] | None = None


def _load(dirs: dict) -> dict[str, str]:
    global _cache
    if _cache is not None:
        return _cache
    w_path = Path(dirs["cwe_db"]) / "json_repo" / "W"
    if not w_path.exists():
        _cache = {}
        return _cache
    index = {}
    for f in w_path.glob("*.json"):
        try:
            d = json.loads(f.read_bytes())
            cwe_id = f"CWE-{d['ID']}"
            index[cwe_id] = d.get("Name", "")
        except Exception:
            pass
    _cache = index
    return _cache


def lookup(cwe_id: str, dirs: dict) -> str | None:
    """Return CWE name for 'CWE-NNN', or None if not found."""
    return _load(dirs).get(cwe_id)
