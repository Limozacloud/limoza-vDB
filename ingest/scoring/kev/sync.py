"""Fetch the CISA KEV catalog (cisagov/kev-data) via shallow git clone/pull."""
from pathlib import Path

from ingest.core.gitsync import clone_or_pull

_REPO = "https://github.com/cisagov/kev-data"


def run(dirs: dict) -> None:
    repo = Path(dirs["kev"]) / "repo"
    print("── sync kev ──")
    clone_or_pull(_REPO, repo)
    print(f"  done → {repo}")
