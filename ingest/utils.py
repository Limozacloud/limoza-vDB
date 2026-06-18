"""CPE format utilities — shared across all vendor ingestors."""
import time
import urllib.parse
from contextlib import contextmanager


_steps: list[tuple[str, float]] = []
_total_start: float | None = None


def timer_start() -> None:
    global _steps, _total_start
    _steps = []
    _total_start = time.monotonic()


@contextmanager
def timer_step(label: str):
    t0 = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - t0
        _steps.append((label, elapsed))
        print(f"  ✓ {label}: {_fmt(elapsed)}")


def timer_summary() -> None:
    if _total_start is None:
        return
    total = time.monotonic() - _total_start
    print("\n── timings ──────────────────────────")
    for label, elapsed in _steps:
        print(f"  {label:<35} {_fmt(elapsed):>8}")
    print(f"  {'total':<35} {_fmt(total):>8}")
    print("─────────────────────────────────────")


def _fmt(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s"


def walk_branches(branches: list, platform_map: dict) -> None:
    """Recursively collect product_id → (cpe23, cpe22, name) from a CSAF product_tree."""
    for b in branches:
        prod = b.get("product")
        if prod:
            pid   = prod.get("product_id", "")
            cpe22 = prod.get("product_identification_helper", {}).get("cpe", "")
            name  = prod.get("name", "")
            if pid and cpe22:
                platform_map[pid] = (cpe22_to_cpe23(cpe22), cpe22, name)
        walk_branches(b.get("branches", []), platform_map)


def cpe22_to_cpe23(cpe22: str) -> str:
    """Convert CPE 2.2 URI to CPE 2.3 formatted string per NIST IR 7695.

    Examples:
      cpe:/o:redhat:enterprise_linux:9          -> cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*
      cpe:/a:redhat:enterprise_linux:8::appstream -> cpe:2.3:a:redhat:enterprise_linux:8:*:appstream:*:*:*:*
    """
    if not cpe22.startswith("cpe:/"):
        return cpe22
    parts = cpe22[5:].split(":")

    def get(idx: int) -> str:
        if idx >= len(parts) or not parts[idx]:
            return "*"
        return urllib.parse.unquote(parts[idx]).lower()

    part    = get(0)
    vendor  = get(1)
    product = get(2)
    version = get(3)
    update  = get(4)
    ed_raw  = urllib.parse.unquote(parts[5]).lower() if len(parts) > 5 else ""

    if ed_raw.startswith("~"):
        segs = ed_raw[1:].split("~")
        edition, sw_ed, tgt_sw, tgt_hw, other = [
            segs[i] if i < len(segs) and segs[i] else "*" for i in range(5)
        ]
    else:
        edition = ed_raw or "*"
        sw_ed = tgt_sw = tgt_hw = other = "*"

    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{sw_ed}:{tgt_sw}:{tgt_hw}:{other}"
