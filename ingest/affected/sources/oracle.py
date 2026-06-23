"""Oracle Linux affected — inherits Red Hat status (RHEL rebuild, el5+; UEK ships as
`kernel-uek*` so it never matches an inherited `kernel` row)."""
from ingest.affected.sources._clone import inherit

ORIGIN = SOURCE = "oracle"


def extract(conn, dirs):
    yield from inherit(SOURCE)
