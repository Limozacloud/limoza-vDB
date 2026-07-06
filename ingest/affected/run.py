"""Central L4 pass — derive the affected-version layer from the already
synced/ingested sources. Runs once after sync+ingest (``vdb affected``).

Each extractor yields rows; we delete-scope that source's slice (by ``origin``)
and stream-insert in batches so the swap is dashboard-safe.
"""
from ingest.affected import delete_scope, flush
from ingest.affected.sources import (almalinux, cvelistv5, debian, ghsa, lve, microsoft,
                                     nodejs, nvd, oracle, osv, redhat, rocky, suse, ubuntu)

# order matters only for the clones (almalinux/rocky/oracle inherit redhat's rows),
# so redhat must come first; otherwise each source owns its own slice.
# `nvd` is the authoritative cpe lane (NVD configurations); `lve` materialises the
# user-defined lve table → affected (truncate-safe re-seed).
EXTRACTORS = (redhat, suse, ubuntu, debian, almalinux, rocky, oracle, cvelistv5,
              microsoft, nvd, osv, ghsa, nodejs, lve)
BATCH = 5_000


def run(conn, dirs: dict, only=None) -> int:
    total = 0
    for mod in EXTRACTORS:
        if only and mod.ORIGIN not in only:
            continue
        delete_scope(conn, mod.ORIGIN)
        n, buf = 0, []
        with conn.cursor() as cur:
            for r in mod.extract(conn, dirs):
                buf.append(r)
                if len(buf) >= BATCH:
                    flush(cur, buf); conn.commit(); n += len(buf); buf = []
            if buf:
                flush(cur, buf); conn.commit(); n += len(buf)
        print(f"  affected[{mod.ORIGIN}]: {n:,} rows", flush=True)
        total += n
    print(f"  affected: {total:,} rows total")
    return total
