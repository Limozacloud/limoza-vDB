"""Sync NVD CVE JSON from the Limozacloud mirror (git-based, no API key needed).

A shallow git clone of Limozacloud/nvd-mirror; subsequent runs fetch + hard-reset.
The mirror updates every 4 hours from official NIST feeds.

Override the source repo via NVD_MIRROR_REPO env var (must have the same layout
and _state.csv format: cve,sha256,imported_at,updated_at).

Fallback: set NVD_MIRROR_REPO to the fkie-cad mirror for the student-maintained
version (_state.csv there has different columns but cve+sha256 are present).
"""
import csv
import os
import subprocess
from pathlib import Path

_DEFAULT_REPO = "https://github.com/Limozacloud/nvd-mirror"
_BRANCH       = "main"


def sync(dirs: dict) -> None:
    dest = Path(dirs["nvd"])
    repo = os.environ.get("NVD_MIRROR_REPO", _DEFAULT_REPO)
    dest.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        print(f"  NVD: updating from {repo} ...")
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth=1", "origin", _BRANCH], check=True)
        subprocess.run(["git", "-C", str(dest), "reset", "--hard", f"origin/{_BRANCH}"], check=True)
    else:
        print(f"  NVD: cloning {repo} (shallow) ...")
        subprocess.run(
            ["git", "clone", "--depth=1", "--branch", _BRANCH, repo, str(dest)],
            check=True,
        )

    state = dest / "_state.csv"
    if not state.exists():
        print("  NVD: WARNING — _state.csv not found in repo")
        return

    total = 0
    with open(state, newline="", encoding="utf-8") as f:
        for _ in csv.DictReader(f):
            total += 1
    print(f"  NVD: {total:,} CVEs in mirror")

