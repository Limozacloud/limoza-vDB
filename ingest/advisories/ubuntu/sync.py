"""Sync Ubuntu security data — sparse shallow clone of canonical/ubuntu-security-notices.

Only the dirs we need: usn/ (advisories) + osv/cve/ (per-CVE). git pull is the
incremental; the ingest re-reads everything (delete_scope makes it idempotent).
"""
import subprocess
from pathlib import Path

_REPO   = "https://github.com/canonical/ubuntu-security-notices"
_SPARSE = ["usn", "osv/cve"]


def run(dirs: dict):
    dest = Path(dirs["ubuntu"])
    print("── sync ubuntu ──")
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
                        _REPO, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)

    usn = sum(1 for _ in (dest / "usn").glob("*.json")) if (dest / "usn").exists() else 0
    osv = sum(1 for _ in (dest / "osv" / "cve").rglob("*.json")) if (dest / "osv" / "cve").exists() else 0
    print(f"  ubuntu: {usn:,} USN · {osv:,} OSV files")
    return usn + osv
