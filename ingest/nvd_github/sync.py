"""Sync NVD CVE JSON from a GitHub mirror (default: fkie-cad/nvd-json-data-feeds).

A plain shallow git clone; subsequent runs fetch + hard-reset to the remote. The
mirror force-pushes its branch on the weekly rebuild, so `pull --ff-only` would
break — reset is the robust update.

The mirror ships `_state.csv` (cve,new,changed,sha256,lastModifiedNVD). The import
step uses the per-CVE sha256 as a content manifest to re-import only changed CVEs,
so there is no NVD API call, no rate limit, and no NVD_API_KEY here.

Swap the source by setting NVD_GITHUB_REPO to any repo with the same layout +
_state.csv.
"""
import csv
import os
import subprocess
from pathlib import Path

_DEFAULT_REPO = "https://github.com/fkie-cad/nvd-json-data-feeds"
_BRANCH       = "main"


def sync(dirs: dict) -> None:
    dest = Path(dirs["nvd_github"])
    repo = os.environ.get("NVD_GITHUB_REPO", _DEFAULT_REPO)
    dest.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        print(f"  NVD-GitHub: updating from {repo} ...")
        subprocess.run(["git", "-C", str(dest), "fetch", "--depth=1", "origin", _BRANCH], check=True)
        subprocess.run(["git", "-C", str(dest), "reset", "--hard", f"origin/{_BRANCH}"], check=True)
    else:
        print(f"  NVD-GitHub: cloning {repo} (shallow) ...")
        subprocess.run(
            ["git", "clone", "--depth=1", "--branch", _BRANCH, repo, str(dest)],
            check=True,
        )

    state = dest / "_state.csv"
    if not state.exists():
        print("  NVD-GitHub: WARNING — _state.csv not found in repo")
        return

    total = new = changed = 0
    with open(state, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            total   += 1
            new     += row.get("new")     == "1"
            changed += row.get("changed") == "1"
    print(f"  NVD-GitHub: {total} CVEs · {new} new · {changed} changed (latest mirror build)")
