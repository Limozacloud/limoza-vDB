#!/bin/sh
chown -R ingest:ingest /data
exec gosu ingest python -m ingest.run "$@"
