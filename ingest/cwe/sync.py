"""Sync CWE definitions from CWE-CAPEC/REST-API-wg (json_repo/W/ only)."""
import subprocess
from pathlib import Path

_REPO        = "https://github.com/CWE-CAPEC/REST-API-wg"
_SPARSE_DIRS = ["json_repo/W"]


def sync(dirs: dict) -> None:
    dest = Path(dirs["cwe_db"])
    dest.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        print("  CWE: updating...")
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set"] + _SPARSE_DIRS, check=True)
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        print("  CWE: cloning CWE-CAPEC/REST-API-wg (sparse)...")
        subprocess.run([
            "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
            _REPO, str(dest),
        ], check=True)
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + _SPARSE_DIRS,
            check=True,
        )

    count = sum(1 for _ in (dest / "json_repo" / "W").glob("*.json")) if (dest / "json_repo" / "W").exists() else 0
    print(f"  CWE: {count} weakness definitions")
