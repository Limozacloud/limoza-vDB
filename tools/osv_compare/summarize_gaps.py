"""Summarize gaps from an OSV delta file (_osv_delta_*.md from run.py).

Usage:
    python tools/osv_compare/summarize_gaps.py tools/osv_compare/output/_osv_delta_CVE-XXXX-XXXXX.md
"""
import sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else None
if not path:
    print("Usage: python tools/osv_compare/summarize_gaps.py <_osv_delta_*.md>")
    sys.exit(1)

rows = []
with open(path, encoding='utf-8') as f:
    for line in f:
        if 'only OSV' in line or 'only ours' in line or 'VERSION DIFF' in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 7:
                rows.append(parts[1:7])

by_pkg = collections.defaultdict(lambda: {'osv': '', 'ours': '', 'status': ''})
for r in rows:
    if len(r) < 6:
        continue
    # columns from _osv_delta_*.md: OS | CPE | Package | OSV | Ingest | Status
    os_label, cpe, pkg, osv_v, our_v, status = r
    key = pkg.strip('`')
    by_pkg[key] = {'os': os_label, 'cpe': cpe.strip('`'), 'osv': osv_v, 'ours': our_v, 'status': status}

counts = collections.Counter(d['status'] for d in by_pkg.values())

print('| OS | Package | OSV | Ingest | Status |')
print('|---|---|---|---|---|')
for pkg, d in sorted(by_pkg.items(), key=lambda x: x[1]['status']):
    print(f'| {d["os"]} | `{pkg}` | {d["osv"]} | {d["ours"]} | {d["status"]} |')

print()
print('## Summary')
print('| Status | Count |')
print('|---|---|')
for s, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'| {s} | {n} |')
