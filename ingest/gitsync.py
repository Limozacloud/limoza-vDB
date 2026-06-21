"""Central git helpers for repo-based syncs.

Thin wrappers around the `git` CLI (the same thing GitPython shells out to, minus
the extra dependency). One place for shallow/sparse clone + ff-only pull, so each
source's sync.py stays a one-liner.

  clone_or_pull(repo, dest)                       shallow clone, else ff pull
  clone_or_pull(repo, dest, branch="develop")     pin a branch
  clone_or_pull(repo, dest, sparse=["json_repo/W"])  partial + sparse checkout

Pair with incremental.git_changed_paths() when you need the exact changeset.
"""
import os
import subprocess
from pathlib import Path

from ingest.retry import retry

_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def _git(*args) -> None:
    subprocess.run(["git", *args], check=True, env=_ENV)


def _git_net(*args) -> None:
    """A network git op (clone/pull) — retried on transient failures."""
    retry(lambda: _git(*args), label=f"git {args[0]}")


def head(dest) -> str | None:
    """Current HEAD sha, or None if not a repo (use before a pull to diff later)."""
    dest = Path(dest)
    if not (dest / ".git").exists():
        return None
    out = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                         capture_output=True, text=True, env=_ENV)
    return out.stdout.strip() or None


def clone_or_pull(repo: str, dest, *, branch: str | None = None, sparse: list[str] | None = None) -> None:
    """Shallow-clone `repo` into `dest` if absent, else fast-forward pull.

    branch : restrict clone to a single branch.
    sparse : subdirs for a blob-less sparse checkout (only those paths materialise).
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        if sparse:
            _git("-C", str(dest), "sparse-checkout", "set", *sparse)  # local
        _git_net("-C", str(dest), "pull", "--ff-only")               # network
        return

    cmd = ["clone", "--depth=1"]
    if branch:
        cmd += ["--branch", branch]
    if sparse:
        cmd += ["--filter=blob:none", "--sparse"]
    cmd += [repo, str(dest)]
    _git_net(*cmd)                                                    # network
    if sparse:
        _git("-C", str(dest), "sparse-checkout", "set", *sparse)      # local
