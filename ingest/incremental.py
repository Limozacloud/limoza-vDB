"""Central incremental-import tracking.

Pick a detector per sync technology:

  * Gate (full-dataset feeds: cpe, epss, osv)
        Sources that rewrite their whole dataset each run gain nothing from
        per-file/per-record diffing. Gate the WHOLE run on the source's own
        change-marker (feed lastModified, ETag, checkpoint) — skip if unchanged.

  * ImportState (size+mtime, the default for file-per-record sources)
        stat() only, no read. Correct when sync writes ONLY the files it changed
        (changes.csv-based RedHat/SUSE, per-file caches, skip-if-exists).
        A file is mark()ed only after it imports cleanly, so failures retry.

  * git_changed_paths (git-pull sources)
        Exact changeset between the pre-pull HEAD and the new HEAD — sharper than
        mtime, since a sparse checkout can touch more files than really changed.

State lives in a small JSON manifest next to the source data.
"""
import json
import os
from pathlib import Path


# ── Gate: whole-run skip for full-dataset feeds ────────────────────────────────
class Gate:
    """Skip an entire sync when the source's change-marker is unchanged."""

    def __init__(self, state_path):
        self.state_path = Path(state_path)

    def _stored(self):
        try:
            return json.loads(self.state_path.read_text()).get("marker")
        except (ValueError, OSError):
            return None

    def unchanged(self, marker) -> bool:
        return bool(marker) and self._stored() == marker

    def commit(self, marker) -> None:
        if marker:
            self.state_path.write_text(json.dumps({"marker": marker}))


# ── ImportState: per-file size+mtime manifest ──────────────────────────────────
def _sig(path: Path) -> str:
    st = path.stat()
    return f"{st.st_size}:{st.st_mtime_ns}"


class ImportState:
    """Tracks imported files by (size, mtime) so unchanged files are skipped."""

    def __init__(self, state_path, base):
        self.state_path = Path(state_path)
        self.base       = Path(base)
        self._stored: dict = {}
        if self.state_path.exists():
            try:
                self._stored = json.loads(self.state_path.read_bytes())
            except (ValueError, OSError):
                self._stored = {}
        self._marked: dict = {}

    def _key(self, path) -> str:
        return Path(path).relative_to(self.base).as_posix()

    def changed(self, files, *, full: bool = False) -> list:
        if full:
            return list(files)
        out = []
        for f in files:
            try:
                if _sig(f) != self._stored.get(self._key(f)):
                    out.append(f)
            except OSError:
                out.append(f)
        return out

    def mark(self, path) -> None:
        try:
            self._marked[self._key(path)] = _sig(path)
        except OSError:
            pass

    def commit(self) -> None:
        self._stored.update(self._marked)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(self._stored, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.state_path)
        self._marked.clear()


# ── git_changed_paths: exact changeset for git-pull sources ────────────────────
def git_changed_paths(repo_dir, since_ref, *, pathspec=None) -> set:
    import subprocess
    cmd = ["git", "-C", str(repo_dir), "diff", "--name-only", f"{since_ref}..HEAD"]
    if pathspec:
        cmd += ["--", *pathspec]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if line}
