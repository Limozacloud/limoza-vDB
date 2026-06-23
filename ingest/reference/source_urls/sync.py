"""source_urls is a bundled config (advisories/source_urls.json) — nothing to download."""


def run(dirs: dict):
    return {"status": "no_new_data", "message": "bundled config"}
