"""Sync Ubuntu security notices from canonical/ubuntu-security-notices.

Sparse clone:
  usn/       USN advisories — title, timestamp, CVE mappings
  vex/cve/   OpenVEX per-CVE files — fix status, fix version
  osv/cve/   OSV per-CVE files — Ubuntu severity label, CVSS vectors
"""
import subprocess
from pathlib import Path

_REPO        = "https://github.com/canonical/ubuntu-security-notices"
_SPARSE_DIRS = ["usn", "vex/cve", "osv/cve"]


def sync(dirs: dict) -> None:
    dest = Path(dirs["ubuntu_usn"])
    dest.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        print("  Ubuntu: updating sparse checkout...")
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set"] + _SPARSE_DIRS, check=True)
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        print("  Ubuntu: cloning canonical/ubuntu-security-notices (sparse)...")
        subprocess.run([
            "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
            _REPO, str(dest),
        ], check=True)
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + _SPARSE_DIRS,
            check=True,
        )

    usn_count = sum(1 for _ in (dest / "usn").glob("*.json"))          if (dest / "usn").exists()          else 0
    vex_count = sum(1 for _ in (dest / "vex" / "cve").rglob("*.json")) if (dest / "vex" / "cve").exists() else 0
    osv_count = sum(1 for _ in (dest / "osv" / "cve").rglob("*.json")) if (dest / "osv" / "cve").exists() else 0
    print(f"  Ubuntu: {usn_count} USN · {vex_count} VEX · {osv_count} OSV files")
