"""Sync NVD CVE data (Limozacloud/nvd-sync) — shallow clone/pull.

nvd-mirror mirrors the NVD CVE 2.0 feeds to per-CVE JSON files (data/CVE-{year}/…/{id}.json)
and keeps them current via its own GitHub Action. Both the metadata ingest (records/nvd)
and the cpe extractor (affected/sources/nvd) read this one clone.
"""
from pathlib import Path

from ingest.core.gitsync import clone_or_pull, head
from ingest.core.incremental import Gate

_REPO = "https://github.com/Limozacloud/nvd-mirror"


def run(dirs: dict):
    dest = Path(dirs["nvd"])
    repo = dest / "repo"
    gate = Gate(dest / ".sync_state.json")

    print("── sync nvd ──")
    before = head(repo)
    clone_or_pull(_REPO, repo)
    after = head(repo)

    if gate.unchanged(after) and before == after:
        print(f"  unchanged ({after[:8]}) — nothing pulled (gate)")
        return {"status": "no_new_data", "message": f"unchanged ({after[:8]}) (gate)"}

    gate.commit(after)
    print(f"  done → {repo} (HEAD {after[:8]})")
    return None
