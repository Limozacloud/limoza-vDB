"""AlmaLinux affected — inherits Red Hat status (1:1 RHEL rebuild, el8+)."""
from ingest.affected.sources._clone import inherit

ORIGIN = SOURCE = "almalinux"


def extract(conn, dirs):
    yield from inherit(SOURCE, min_major=8)
