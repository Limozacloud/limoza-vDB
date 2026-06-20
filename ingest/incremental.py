"""Central incremental-import tracking.

Most importers iterate a set of files and upsert every record on every run. This
helper lets an importer re-process only the files that changed since the last
successful import.

Detectors (pick per sync technology — see the per-vendor table in the docs):

  * size+mtime (ImportState, the default)
        stat() only, no file read. Correct for every sync that writes ONLY the
        files it changed: changes.csv-based RedHat/SUSE, per-file caches,
        "skip if exists" downloads. Measured: SUSE 1,415 changed of 148,692.

  * git diff (git_changed_paths)
        For git-pull sources, where a checkout/sparse-update can touch more files
        than actually changed. The exact changeset between the pre-pull HEAD and
        the new HEAD. Sharper than mtime there (Ubuntu: git touched 18% of files).

  * source-provided hashes
        When the source already ships a per-record hash (e.g. the nvd-github
        mirror's _state.csv sha256) — diff that map directly, no stat/read.

  * gate (not here — trivial per vendor)
        Sources that rewrite their whole dataset each sync (epss, cpe, osv) gain
        nothing from file mtime. Skip the whole import when the source's own
        checkpoint/ETag says nothing changed.

State lives in a per-vendor JSON manifest {relpath: "size:mtime_ns"}. A file is
mark()ed only after it imports cleanly, so a failed file retries next run.
commit() writes the manifest atomically at the end.
"""
from ingest import json_compat as json
import os
from pathlib import Path


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
        """Files whose size/mtime differs from the manifest (or all, if full)."""
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
        """Record a cleanly-imported file; its manifest entry advances on commit()."""
        try:
            self._marked[self._key(path)] = _sig(path)
        except OSError:
            pass

    def commit(self) -> None:
        """Merge this run's marks into the stored manifest and write it atomically."""
        self._stored.update(self._marked)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(self._stored, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.state_path)
        self._marked.clear()


def git_changed_paths(repo_dir, since_ref, *, pathspec=None) -> set:
    """Paths changed in `repo_dir` between `since_ref` and HEAD (git-pull sources).

    Returns paths relative to the repo (empty set = no changes). The caller
    records the pre-pull HEAD (`git rev-parse HEAD`) before pulling, then passes
    it here after the pull.
    """
    import subprocess
    cmd = ["git", "-C", str(repo_dir), "diff", "--name-only", f"{since_ref}..HEAD"]
    if pathspec:
        cmd += ["--", *pathspec]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if line}
