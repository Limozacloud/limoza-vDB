"""SUSE sync: a VEX file is fetched again whenever the local copy is older than SUSE's change time,
and a failed download never moves a checkpoint past the files that are still missing."""
import json
import os
from datetime import datetime, timezone

from ingest.advisories.suse import sync

CHANGES = (
    '"2026/cve-2026-1.json","2026-11-05T17:35:29Z"\n'      # changed after our copy -> stale
    '"2026/cve-2026-2.json","2026-11-05T17:35:29Z"\n'      # our year copy is newer -> fresh
    '"2024/cve-2024-3.json","2026-11-05T17:35:29Z"\n'      # only an old flat copy -> stale
    '"2026/cve-2026-4.json","2026-11-05T17:35:29Z"\n'      # no local file at all -> missing
    '"2026/not-a-vex.txt","2026-11-05T17:35:29Z"\n'
)
T = datetime(2026, 11, 5, 17, 35, 29, tzinfo=timezone.utc).timestamp()


def _touch(path, mtime):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    os.utime(path, (mtime, mtime))


def test_stale_lists_missing_and_older_copies(monkeypatch, tmp_path):
    monkeypatch.setattr(sync, "_get", lambda url: CHANGES.encode())
    _touch(tmp_path / "2026" / "cve-2026-1.json", T - 86400)      # old year copy
    _touch(tmp_path / "2026" / "cve-2026-2.json", T + 60)         # fresh
    _touch(tmp_path / "cve-2024-3.json", T - 30 * 86400)          # old flat copy
    got = sync._stale("https://x/csaf-vex", tmp_path)
    assert sorted(got) == ["2024/cve-2024-3.json", "2026/cve-2026-1.json", "2026/cve-2026-4.json"]


def test_a_flat_copy_newer_than_the_change_counts_as_fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(sync, "_get", lambda url: b'"2024/cve-2024-3.json","2026-11-05T17:35:29Z"\n')
    _touch(tmp_path / "cve-2024-3.json", T + 5)
    assert sync._stale("https://x", tmp_path) == []


def test_fetch_many_reports_the_failed_names(monkeypatch, tmp_path):
    def get(url):
        if url.endswith("bad.json"):
            raise OSError("404")
        return b"{}"
    monkeypatch.setattr(sync, "_get", get)
    ok, failed = sync._fetch_many("https://x", tmp_path, ["2026/good.json", "2026/bad.json"])
    assert (ok, failed) == (1, ["2026/bad.json"])
    assert (tmp_path / "2026" / "good.json").exists()


def test_failed_advisory_downloads_keep_the_checkpoint(monkeypatch, tmp_path):
    ckpt = tmp_path / "checkpoint.json"
    ckpt.write_text(json.dumps({"last_vex": "2026-11-01", "last_adv": "2026-11-01"}))
    monkeypatch.setattr(sync, "_sync_vex", lambda base, since: (0, []))
    monkeypatch.setattr(sync, "_sync_adv", lambda base, since: (1, ["2026/suse-su-2026_1-1.json"]))
    sync.run({"suse": str(tmp_path)})
    state = json.loads(ckpt.read_text())
    assert state["last_adv"] == "2026-11-01"        # not advanced: the failed advisory is asked for again
    assert state["last_vex"] != "2026-11-01"        # VEX is compared per file, the date is only informative


def test_clean_run_moves_the_advisory_checkpoint(monkeypatch, tmp_path):
    ckpt = tmp_path / "checkpoint.json"
    ckpt.write_text(json.dumps({"last_vex": "2026-11-01", "last_adv": "2026-11-01"}))
    monkeypatch.setattr(sync, "_sync_vex", lambda base, since: (3, []))
    monkeypatch.setattr(sync, "_sync_adv", lambda base, since: (2, []))
    assert sync.run({"suse": str(tmp_path)}) == 5
    assert json.loads(ckpt.read_text())["last_adv"] != "2026-11-01"
