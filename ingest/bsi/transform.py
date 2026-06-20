"""Transform BSI WID CSAF advisories → upsert_lve_record format."""
from ingest import json_compat as json
from pathlib import Path
from typing import Optional


def _note(notes: list, category: str) -> Optional[str]:
    for n in notes:
        if n.get("category") == category:
            text = (n.get("text") or "").strip()
            return text or None
    return None


def _parse_date(ts: Optional[str]) -> Optional[str]:
    """Normalise ISO 8601 date to YYYY-MM-DDTHH:MM:SSZ."""
    if not ts:
        return None
    import datetime
    try:
        dt = datetime.datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts.strip() or None


def load_csaf(csaf_dir: Path, wid_id: str) -> Optional[dict]:
    """Load a cached CSAF file by WID ID (searches all year subdirs)."""
    wid_lower = wid_id.lower()
    # WID-SEC-W-2024-0794 → year 2024
    parts = wid_lower.split("-")
    year  = parts[3] if len(parts) > 3 else None
    if year:
        candidate = csaf_dir / year / f"{wid_lower}.json"
        if candidate.exists():
            try:
                return json.loads(candidate.read_bytes())
            except Exception:
                return None
    # fallback: glob
    for f in csaf_dir.rglob(f"{wid_lower}.json"):
        try:
            return json.loads(f.read_bytes())
        except Exception:
            return None
    return None


def transform(cve_id: str, wid_id: str, wid_url: str,
              csaf_dir: Optional[Path]) -> dict:
    title       = None
    description = None
    published   = None
    updated     = None

    if csaf_dir and wid_id:
        csaf = load_csaf(csaf_dir, wid_id)
        if csaf:
            doc      = csaf.get("document", {})
            notes    = doc.get("notes", [])
            tracking = doc.get("tracking", {})

            raw_title = (doc.get("title") or "").strip()
            title       = raw_title or None
            description = _note(notes, "summary") or _note(notes, "description")
            published   = _parse_date(tracking.get("initial_release_date"))
            updated     = _parse_date(tracking.get("current_release_date"))

    history = []
    if published:
        history.append({"date": published, "event": "advisory_added",   "source": "bsi", "detail": wid_id})
    if updated and updated != published:
        history.append({"date": updated,   "event": "advisory_updated", "source": "bsi", "detail": wid_id})

    adv = {"@id": wid_id, "source": "bsi", "url": wid_url}
    if published:
        adv["published"] = published
    if updated and updated != published:
        adv["updated"] = updated

    return {
        "aliases":      [cve_id, wid_id.upper()],
        "has_exploit":  False,
        "cve":          {"cve_id": cve_id},
        "titles":       ([{"value": title, "source": "bsi", "advisory": wid_id}] if title else []),
        "descriptions": ([{"value": description, "source": "bsi", "advisory": wid_id}] if description else []),
        "cvss":         [],
        "cwes":         [],
        "references":   ([{"url": wid_url, "type": "advisory", "source": "bsi", "advisory": wid_id}] if wid_url else []),
        "advisories":   [adv],
        "upstream":     [],
        "packages":     [],
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }
