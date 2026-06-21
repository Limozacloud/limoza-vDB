"""v2 ingest CLI.

  python -m ingest.run schema                  apply schema.sql
  python -m ingest.run sync   [target...]      download source data (default: all)
  python -m ingest.run ingest [target...]      write downloaded data into the DB

A target is a source key (epss, kev, …, exploitdb, …) or a group (exploits).
Each source has a module dir with sync.py/ingest.py exposing run(); a sync run()
returns an int (items), None, or {"status":"no_new_data","message":...} when gated.
Ingest counts are read from the source's table before/after. Every phase is timed,
recorded in sync_log, and isolated — one source failing never aborts the rest.

Data dirs default to $DATA_DIR/<key> (DATA_DIR defaults to /data).
"""
import datetime
import importlib
import os
import sys

# key -> (module, table, source_value)
#   table        = the DB table the ingest writes to
#   source_value = filters the row count to this source (shared tables); None = whole table
SOURCES = {
    "epss":       ("ingest.scoring.epss",        "epss", None),
    "kev":        ("ingest.scoring.kev",         "kev",  None),
    "ssvc":       ("ingest.scoring.ssvc",        "ssvc", None),
    "cna":        ("ingest.reference.cna",       "cna",  None),
    "cpe":        ("ingest.reference.cpe",       "cpe",  None),
    "cwe":        ("ingest.reference.cwe",       "cwe",  None),
    "cvelistv5":  ("ingest.records.cvelistv5",   "cve_record", None),
    "exploitdb":  ("ingest.exploits.exploitdb",  "exploits", "exploitdb"),
    "metasploit": ("ingest.exploits.metasploit", "exploits", "metasploit"),
    "nuclei":     ("ingest.exploits.nuclei",     "exploits", "nuclei"),
    "poc_github": ("ingest.exploits.poc_github", "exploits", "poc_github"),
}

GROUPS = {
    "reference": ["cna", "cpe", "cwe"],
    "scoring":   ["epss", "kev", "ssvc"],
    "records":   ["cvelistv5"],
    "exploits":  ["exploitdb", "metasploit", "nuclei", "poc_github"],
}


def _dirs() -> dict:
    base = os.environ.get("DATA_DIR", "/data")
    return {key: os.path.join(base, key) for key in SOURCES}


def _expand(targets) -> list:
    out = []
    for t in targets:
        out.extend(GROUPS.get(t, [t]))
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1

    cmd, raw_targets = argv[0], (argv[1:] or list(SOURCES))

    if cmd == "schema":
        from ingest.core.db import apply_schema
        apply_schema()
        return 0

    if cmd not in ("sync", "ingest"):
        print(f"unknown command: {cmd}\n{__doc__}")
        return 1

    targets = _expand(raw_targets)
    unknown = [t for t in targets if t not in SOURCES]
    if unknown:
        print(f"unknown target(s): {', '.join(unknown)}")
        return 1

    from ingest.core.db import get_conn, log_run, table_count

    dirs = _dirs()
    conn = get_conn()
    failures = 0
    try:
        for t in targets:
            module, table, source_value = SOURCES[t]
            mod = importlib.import_module(f"{module}.{cmd}")
            started = datetime.datetime.now(datetime.timezone.utc)
            try:
                if cmd == "sync":
                    _log_sync(conn, t, mod.run(dirs), started, log_run)
                else:
                    before = table_count(conn, table, source_value)
                    mod.run(conn, dirs)
                    after = table_count(conn, table, source_value)
                    delta = after - before
                    note = f"{delta:+,} added" if delta else "no row change"
                    log_run(conn, t, "ingest", "success", count_before=before,
                            count_after=after, message=f"{after:,} total · {note}",
                            started_at=started)
            except Exception as e:
                conn.rollback()  # clear any aborted txn so the log insert succeeds
                failures += 1
                log_run(conn, t, cmd, "failed", message=f"{type(e).__name__}: {e}",
                        started_at=started)
                print(f"  ✗ {t} {cmd} failed: {type(e).__name__}: {e}")
    finally:
        conn.close()

    return 1 if failures else 0


def _log_sync(conn, source, result, started, log_run) -> None:
    """Normalise a sync run()'s return value into a sync_log row."""
    if isinstance(result, dict):  # gated → {"status": "no_new_data", "message": ...}
        log_run(conn, source, "sync", result.get("status", "no_new_data"),
                message=result.get("message"), started_at=started)
    else:
        items = result if isinstance(result, int) else None
        msg   = f"fetched {items:,}" if items is not None else "fetched"
        log_run(conn, source, "sync", "success", items=items, message=msg, started_at=started)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
