#!/usr/bin/env python3
"""Summarize completed runs without changing original simulation evidence."""
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
runs = []
def quantile(xs, q):
    return sorted(xs)[int((len(xs)-1)*q)]
for file in sorted(root.glob('*/summary.json')):
    summary = json.loads(file.read_text())
    configured, observed = [], []
    for line in (file.parent/'trace.jsonl').read_text().splitlines():
        e=json.loads(line)['event']
        if e['kind']=='delivery_timing':
            configured.append(e['configured_delay_ms'])
            observed.append(e['measured_delay_ms'])
            assert observed[-1] >= configured[-1]
    assert len(observed)==summary['stats']['delivered']
    runs.append({**summary,'retries':summary['stats']['sent']-summary['events_per_peer']*summary['peers'],
        'configured_latency_ms': {k:quantile(configured,q) for k,q in [('min',0),('p50',.5),('p95',.95),('p99',.99),('max',1)]},
        'measured_latency_ms': {k:quantile(observed,q) for k,q in [('min',0),('p50',.5),('p95',.95),('p99',.99),('max',1)]}})
assert runs, 'No completed runs'
print(json.dumps({'runs':runs,'total_applied':sum(r['stats']['applied'] for r in runs),'total_retries':sum(r['retries'] for r in runs),'summed_wall_clock_ms':sum(r['elapsed_ms'] for r in runs)},indent=2))
