"""Sync GHSA — sparse shallow clone of github/advisory-database (reviewed only).

The GitHub Advisory Database is the authentic GHSA source (OSV format), covering
all language ecosystems (npm/pypi/maven/go/rust/nuget/composer/…). We take only
advisories/github-reviewed/. git pull is the incremental; ingest re-reads all
(delete_scope makes it idempotent).
"""
import subprocess
from pathlib import Path

_REPO   = "https://github.com/github/advisory-database"
_SPARSE = ["advisories/github-reviewed"]


def run(dirs: dict):
    dest = Path(dirs["ghsa"])
    print("── sync ghsa ──")
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
                        _REPO, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)

    base = dest / "advisories" / "github-reviewed"
    n = sum(1 for _ in base.rglob("*.json")) if base.exists() else 0
    print(f"  ghsa: {n:,} advisories")
    return n
