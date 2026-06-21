"""Central retry for transient failures (network / git / flaky HTTP).

  retry(fn, retries=3)      run fn(), retry on transient errors with backoff
  http_get(url, ...)        httpx.get with raise_for_status + retry built in

Transient = network/transport errors, git clone/pull failures, and HTTP
403/429/5xx (rate limits + server hiccups, common with NVD/FIRST). Permanent
errors (404, parse errors, bad data) are NOT retried — they re-raise immediately.
"""
import subprocess
import time

import httpx

_TRANSIENT_STATUS = {403, 429, 500, 502, 503, 504}


def is_transient(exc: Exception) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _TRANSIENT_STATUS
    if isinstance(exc, subprocess.CalledProcessError):
        return True  # git clone/pull over the network
    return False


def retry(fn, *, retries: int = 3, base_delay: float = 5.0, label: str = ""):
    """Call fn(); on a transient error retry up to `retries` times (capped backoff)."""
    for attempt in range(retries + 1):
        try:
            return fn()
        except Exception as e:
            if not is_transient(e) or attempt == retries:
                raise
            delay = min(30.0, base_delay * (attempt + 1))
            tag = label or type(e).__name__
            print(f"  transient error ({tag}) — retry {attempt + 1}/{retries} in {delay:.0f}s")
            time.sleep(delay)


def http_get(url: str, *, retries: int = 3, **kwargs) -> httpx.Response:
    """GET with raise_for_status, retried on transient failures."""
    kwargs.setdefault("timeout", 60)
    kwargs.setdefault("follow_redirects", True)

    def _do():
        resp = httpx.get(url, **kwargs)
        resp.raise_for_status()
        return resp

    return retry(_do, retries=retries, label=f"GET {url.split('?')[0]}")
