# AkesoAV Performance Benchmark Report

**Status:** Template — run `python scripts/benchmark.py` to populate with real numbers.

## How to Run

```powershell
# Full benchmark (generates 10K corpus, ~30 min):
python scripts\benchmark.py

# Smaller test run (1K files, ~3 min):
python scripts\benchmark.py --count 1000

# With ClamAV comparison:
python scripts\benchmark.py --clamscan "C:\Program Files\ClamAV\clamscan.exe"

# With custom corpus:
python scripts\benchmark.py --corpus C:\path\to\corpus

# With signature database:
python scripts\benchmark.py --db testdata\test.akavdb
```

## Metrics Collected

| Metric | Description |
|--------|-------------|
| Throughput | Files scanned per second (cold and warm passes) |
| p50 latency | Median per-file scan time in milliseconds |
| p95 latency | 95th percentile per-file scan time |
| p99 latency | 99th percentile per-file scan time |
| Cache hit rate | Percentage of files served from cache on second pass |
| Peak memory | Working set of akavscan process (per-invocation) |
| Detections | Number of files flagged (should be 0 for clean corpus) |

## Acceptance Criteria

- [ ] Reproducible numbers across runs
- [ ] ClamAV comparison table (when clamscan available)
- [ ] Cache hit rate >90% on second pass
- [ ] Integrated latency <2x standalone (when EDR loaded)

## Results

*Run `python scripts/benchmark.py` to generate results below.*
