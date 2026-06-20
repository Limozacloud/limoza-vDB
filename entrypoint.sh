#!/bin/sh
# Source .env if mounted (used by ofelia job-run)
if [ -f /config/.env ]; then
    set -a; . /config/.env; set +a
fi
chown -R ingest:ingest /data
exec gosu ingest python -m ingest.run "$@"
