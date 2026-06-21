"""Sync the CVE List v5 (CVEProject/cvelistV5) — shallow clone/pull.

~280k per-CVE JSONs under cves/YYYY/Nxxx/CVE-….json. No index is built here; the
ingest reads the files directly and tracks its own last-ingested commit for the
incremental diff. Gate avoids a redundant pull when HEAD is unchanged.
"""
from pathlib import Path

from ingest.core.gitsync import clone_or_pull, head
from ingest.core.incremental import Gate

_REPO = "https://github.com/CVEProject/cvelistV5"


def run(dirs: dict):
    dest = Path(dirs["cvelistv5"])
    repo = dest / "repo"
    gate = Gate(dest / ".sync_state.json")

    print("── sync cvelistv5 ──")
    before = head(repo)
    clone_or_pull(_REPO, repo)
    after = head(repo)

    if gate.unchanged(after) and before == after:
        print(f"  unchanged ({after[:8]}) — nothing pulled (gate)")
        return {"status": "no_new_data", "message": f"unchanged ({after[:8]}) (gate)"}

    gate.commit(after)
    print(f"  done → {repo} (HEAD {after[:8]})")
    return None
