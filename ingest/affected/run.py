"""Central L4 pass — derive the affected-version layer from the already
synced/ingested sources. Runs once after sync+ingest (``vdb affected``).

Each extractor's slice is rebuilt with an ATOMIC per-origin swap so ``/match`` never
observes a partial slice. The old code delete-scoped an origin (committed) and then
re-inserted in batches (each committed), leaving that origin near-empty for the WHOLE
(slow) extraction — minutes to hours — during which the matcher returned false negatives
for every host of that vendor. Instead we stream the fresh rows into a session TEMP
staging table (no lock on ``affected``, free to commit), then a single short transaction
deletes the origin's old rows and copies the new ones in. Readers keep seeing the OLD
complete slice until that one commit, then the NEW complete slice — never an empty/partial
one. It is also more resilient: if an extractor fails mid-run the swap never happens, so
the origin's previous rows stay intact instead of being lost to an already-committed delete.
"""
from ingest.affected import COLS, flush
from ingest.affected.sources import (almalinux, cvelistv5, debian, ghsa, github_repo, lve,
                                     microsoft, nodejs, nvd, oracle, osv, redhat, rocky, suse,
                                     ubuntu)

# order matters only for the clones (almalinux/rocky/oracle inherit redhat's rows),
# so redhat must come first; otherwise each source owns its own slice.
# `nvd` is the authoritative cpe lane (NVD configurations); `lve` materialises the
# user-defined lve table → affected (truncate-safe re-seed).
EXTRACTORS = (redhat, suse, ubuntu, debian, almalinux, rocky, oracle, cvelistv5,
              microsoft, nvd, osv, ghsa, github_repo, nodejs, lve)
BATCH = 5_000
_COLS = ",".join(COLS)


def run(conn, dirs: dict, only=None) -> int:
    total = 0
    # session-scoped staging table with exactly the insertable columns (no id/synced_at,
    # so their defaults fire on the swap). Reused across origins via TRUNCATE.
    with conn.cursor() as cur:
        cur.execute(f"CREATE TEMP TABLE IF NOT EXISTS affected_stg "
                    f"AS SELECT {_COLS} FROM affected WHERE false")
    conn.commit()
    for mod in EXTRACTORS:
        if only and mod.ORIGIN not in only:
            continue
        # 1) stream the fresh slice into staging — no lock on `affected`, commit freely
        with conn.cursor() as cur:
            cur.execute("TRUNCATE affected_stg")
        conn.commit()
        n, buf = 0, []
        with conn.cursor() as cur:
            for r in mod.extract(conn, dirs):
                buf.append(r)
                if len(buf) >= BATCH:
                    flush(cur, buf, "affected_stg"); conn.commit(); n += len(buf); buf = []
            if buf:
                flush(cur, buf, "affected_stg"); conn.commit(); n += len(buf)
        # 2) atomic swap: one transaction — readers see the OLD complete slice until it commits
        with conn.cursor() as cur:
            cur.execute("DELETE FROM affected WHERE origin = %s", (mod.ORIGIN,))
            cur.execute(f"INSERT INTO affected ({_COLS}) SELECT {_COLS} FROM affected_stg")
        conn.commit()
        print(f"  affected[{mod.ORIGIN}]: {n:,} rows", flush=True)
        total += n
    print(f"  affected: {total:,} rows total")
    return total
