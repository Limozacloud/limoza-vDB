#!/bin/sh
# Source .env if mounted (used by ofelia job-run)
if [ -f /config/.env ]; then
    set -a; . /config/.env; set +a
fi
if [ $# -eq 0 ]; then
    chown -R ingest:ingest /data
    exec sleep infinity
fi
exec gosu ingest python -m ingest.run "$@"
