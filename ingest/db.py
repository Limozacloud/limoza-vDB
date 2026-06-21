"""Database helpers for v2 ingest.

Connection comes from POSTGRES_DSN. Schema is applied idempotently via pgschema.
"""
import datetime
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import psycopg2

_SCHEMA = Path(__file__).parent.parent / "schema.sql"


def get_conn():
    return psycopg2.connect(os.environ["POSTGRES_DSN"])


def table_count(conn, table, source_value=None) -> int:
    """Row count of a source's table (names come from the SOURCES registry, not user
    input). When source_value is set, count only that source's slice of a shared table."""
    with conn.cursor() as cur:
        if source_value is None:
            cur.execute(f"SELECT count(*) FROM {table}")
        else:
            cur.execute(f"SELECT count(*) FROM {table} WHERE source = %s", (source_value,))
        return cur.fetchone()[0]


def log_run(conn, source, phase, status, *, items=None, count_before=None,
            count_after=None, message=None, started_at=None) -> None:
    """Record one sync/ingest run in sync_log (best-effort — never raises)."""
    finished = datetime.datetime.now(datetime.timezone.utc)
    duration_ms = int((finished - started_at).total_seconds() * 1000) if started_at else None
    msg = (message or "")[:2000] or None
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sync_log
                   (source, phase, status, items, count_before, count_after,
                    message, started_at, finished_at, duration_ms)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (source, phase, status, items, count_before, count_after,
                 msg, started_at, finished, duration_ms),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  [sync_log] could not record {source}/{phase}: {e}")


def apply_schema() -> None:
    """Apply schema.sql idempotently with pgschema."""
    parsed = urlparse(os.environ["POSTGRES_DSN"])
    env = os.environ.copy()
    env.update({
        "PGHOST":     parsed.hostname or "localhost",
        "PGPORT":     str(parsed.port or 5432),
        "PGDATABASE": parsed.path.lstrip("/"),
        "PGUSER":     parsed.username or "",
        "PGPASSWORD": parsed.password or "",
    })
    subprocess.run(
        ["pgschema", "apply", "--file", str(_SCHEMA), "--auto-approve", "--no-color"],
        check=True,
        env=env,
    )
