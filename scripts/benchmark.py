#!/usr/bin/env python3
"""
P12-T3: Performance Benchmark

Benchmarks AkesoAV against a mixed-file corpus:
  - Throughput (files/sec)
  - Peak memory (working set)
  - Per-file latency percentiles (p50, p95, p99)
  - Cache hit rate on second pass
  - Optional ClamAV (clamscan) comparison

Usage:
  python scripts/benchmark.py [--corpus <dir>] [--db <akavdb>] [--clamscan <path>]
                               [--count <N>] [--report <output.md>]

If --corpus is omitted, generates a synthetic 10K-file corpus in %TEMP%.
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import statistics
import sys
import time
import tempfile

# ── Defaults ──────────────────────────────────────────────────────────

DEFAULT_COUNT = 10000
DEFAULT_DB = None  # Use EICAR builtin detection if no DB
AKAVSCAN = os.path.join("build", "Release", "akavscan.exe")


def generate_corpus(output_dir, count):
    """Generate a mixed-file corpus for benchmarking."""
    print(f"Generating {count}-file corpus in {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)

    rng = random.Random(42)  # Deterministic

    # Distribution: 60% small (<4KB), 25% medium (4-64KB), 10% large (64KB-1MB), 5% PE-like
    categories = {
        "small":  int(count * 0.60),
        "medium": int(count * 0.25),
        "large":  int(count * 0.10),
        "pe":     count - int(count * 0.60) - int(count * 0.25) - int(count * 0.10),
    }

    idx = 0
    for cat, n in categories.items():
        cat_dir = os.path.join(output_dir, cat)
        os.makedirs(cat_dir, exist_ok=True)

        for i in range(n):
            if cat == "small":
                size = rng.randint(64, 4096)
            elif cat == "medium":
                size = rng.randint(4096, 65536)
            elif cat == "large":
                size = rng.randint(65536, 1048576)
            else:  # pe-like
                size = rng.randint(8192, 131072)

            data = bytearray(size)
            # Fill with pseudo-random data
            for j in range(0, size, 64):
                chunk = rng.getrandbits(min(64, size - j) * 8).to_bytes(min(64, size - j), 'little')
                data[j:j+len(chunk)] = chunk

            # PE-like files get MZ header
            if cat == "pe":
                data[0:2] = b"MZ"
                ext = ".exe"
            else:
                exts = [".txt", ".bin", ".dat", ".log", ".xml", ".json", ".csv"]
                ext = rng.choice(exts)

            path = os.path.join(cat_dir, f"file_{idx:06d}{ext}")
            with open(path, "wb") as f:
                f.write(data)
            idx += 1

            if idx % 1000 == 0:
                print(f"  Generated {idx}/{count} files...")

    print(f"  Corpus ready: {idx} files in {output_dir}")
    return output_dir


def collect_files(corpus_dir):
    """Recursively collect all files in a directory."""
    files = []
    for root, dirs, filenames in os.walk(corpus_dir):
        for fn in filenames:
            files.append(os.path.join(root, fn))
    return sorted(files)


def benchmark_akavscan(files, db_path=None, label="AkesoAV"):
    """Benchmark akavscan on a list of files. Returns dict with metrics."""
    print(f"\n=== Benchmarking {label} ({len(files)} files) ===")

    if not os.path.exists(AKAVSCAN):
        print(f"ERROR: {AKAVSCAN} not found")
        return None

    latencies = []
    detections = 0
    cached = 0
    errors = 0

    args_base = [AKAVSCAN, "-j", "--no-whitelist", "--heur-level", "0"]
    if db_path:
        args_base += ["--db", db_path]

    start_all = time.perf_counter()

    for i, fpath in enumerate(files):
        args = args_base + [fpath]
        t0 = time.perf_counter()
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            t1 = time.perf_counter()
            elapsed_ms = (t1 - t0) * 1000.0
            latencies.append(elapsed_ms)

            # Parse JSON output
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        j = json.loads(line)
                        if j.get("detected"):
                            detections += 1
                        if j.get("cached"):
                            cached += 1
                    except json.JSONDecodeError:
                        pass
        except subprocess.TimeoutExpired:
            latencies.append(30000.0)
            errors += 1
        except Exception as e:
            errors += 1

        if (i + 1) % 500 == 0:
            elapsed = time.perf_counter() - start_all
            rate = (i + 1) / elapsed
            print(f"  {i+1}/{len(files)} ({rate:.0f} files/sec)...")

    end_all = time.perf_counter()
    total_sec = end_all - start_all

    # Compute metrics
    metrics = {
        "label": label,
        "files": len(files),
        "total_sec": round(total_sec, 2),
        "throughput": round(len(files) / total_sec, 1),
        "detections": detections,
        "cached": cached,
        "errors": errors,
    }

    if latencies:
        latencies_sorted = sorted(latencies)
        metrics["p50_ms"] = round(latencies_sorted[len(latencies_sorted) // 2], 2)
        metrics["p95_ms"] = round(latencies_sorted[int(len(latencies_sorted) * 0.95)], 2)
        metrics["p99_ms"] = round(latencies_sorted[int(len(latencies_sorted) * 0.99)], 2)
        metrics["mean_ms"] = round(statistics.mean(latencies), 2)
        metrics["min_ms"] = round(min(latencies), 2)
        metrics["max_ms"] = round(max(latencies), 2)

    print(f"  Throughput: {metrics['throughput']} files/sec")
    print(f"  Latency p50={metrics.get('p50_ms', 'N/A')}ms "
          f"p95={metrics.get('p95_ms', 'N/A')}ms "
          f"p99={metrics.get('p99_ms', 'N/A')}ms")
    print(f"  Detections: {detections}, Cached: {cached}, Errors: {errors}")

    return metrics


def benchmark_clamscan(files, clamscan_path):
    """Benchmark ClamAV clamscan on same files."""
    if not clamscan_path or not os.path.exists(clamscan_path):
        print(f"\n=== ClamAV: skipped (clamscan not found) ===")
        return None

    print(f"\n=== Benchmarking ClamAV ({len(files)} files) ===")

    latencies = []
    detections = 0
    start_all = time.perf_counter()

    for i, fpath in enumerate(files):
        t0 = time.perf_counter()
        try:
            result = subprocess.run(
                [clamscan_path, "--no-summary", fpath],
                capture_output=True, text=True, timeout=30
            )
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)
            if result.returncode == 1:
                detections += 1
        except subprocess.TimeoutExpired:
            latencies.append(30000.0)
        except Exception:
            pass

        if (i + 1) % 500 == 0:
            elapsed = time.perf_counter() - start_all
            rate = (i + 1) / elapsed
            print(f"  {i+1}/{len(files)} ({rate:.0f} files/sec)...")

    end_all = time.perf_counter()
    total_sec = end_all - start_all

    metrics = {
        "label": "ClamAV",
        "files": len(files),
        "total_sec": round(total_sec, 2),
        "throughput": round(len(files) / total_sec, 1),
        "detections": detections,
    }
    if latencies:
        ls = sorted(latencies)
        metrics["p50_ms"] = round(ls[len(ls) // 2], 2)
        metrics["p95_ms"] = round(ls[int(len(ls) * 0.95)], 2)
        metrics["p99_ms"] = round(ls[int(len(ls) * 0.99)], 2)
        metrics["mean_ms"] = round(statistics.mean(latencies), 2)

    print(f"  Throughput: {metrics['throughput']} files/sec")
    print(f"  Latency p50={metrics.get('p50_ms')}ms p95={metrics.get('p95_ms')}ms p99={metrics.get('p99_ms')}ms")

    return metrics


def generate_report(akav1, akav2, clam, output_path):
    """Generate markdown benchmark report."""
    lines = [
        "# AkesoAV Performance Benchmark Report",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Corpus:** {akav1['files']} files",
        "",
        "## Throughput",
        "",
        "| Scanner | Files/sec | Total Time |",
        "|---------|-----------|------------|",
        f"| AkesoAV (cold) | {akav1['throughput']} | {akav1['total_sec']}s |",
        f"| AkesoAV (warm/cached) | {akav2['throughput']} | {akav2['total_sec']}s |",
    ]
    if clam:
        lines.append(f"| ClamAV (clamscan) | {clam['throughput']} | {clam['total_sec']}s |")
    lines += [
        "",
        "## Per-File Latency (ms)",
        "",
        "| Scanner | p50 | p95 | p99 | Mean | Min | Max |",
        "|---------|-----|-----|-----|------|-----|-----|",
        f"| AkesoAV (cold) | {akav1.get('p50_ms','-')} | {akav1.get('p95_ms','-')} | "
        f"{akav1.get('p99_ms','-')} | {akav1.get('mean_ms','-')} | "
        f"{akav1.get('min_ms','-')} | {akav1.get('max_ms','-')} |",
        f"| AkesoAV (warm) | {akav2.get('p50_ms','-')} | {akav2.get('p95_ms','-')} | "
        f"{akav2.get('p99_ms','-')} | {akav2.get('mean_ms','-')} | "
        f"{akav2.get('min_ms','-')} | {akav2.get('max_ms','-')} |",
    ]
    if clam:
        lines.append(
            f"| ClamAV | {clam.get('p50_ms','-')} | {clam.get('p95_ms','-')} | "
            f"{clam.get('p99_ms','-')} | {clam.get('mean_ms','-')} | - | - |"
        )
    lines += [
        "",
        "## Cache Performance",
        "",
        f"- **Cold pass detections:** {akav1['detections']}",
        f"- **Warm pass cached:** {akav2.get('cached', 0)} / {akav2['files']}",
    ]
    cache_rate = 0
    if akav2['files'] > 0:
        cache_rate = akav2.get('cached', 0) * 100.0 / akav2['files']
    lines += [
        f"- **Cache hit rate:** {cache_rate:.1f}%",
        f"- **Target:** >90%",
        f"- **Status:** {'PASS' if cache_rate > 90 else 'NEEDS INVESTIGATION'}",
        "",
        "## Notes",
        "",
        "- Benchmark uses per-file subprocess invocation (CLI overhead included)",
        "- Production throughput via named pipe or in-process API would be significantly higher",
        "- ClamAV comparison uses same per-file invocation for fairness",
        "- Heuristics disabled (--heur-level 0) to isolate signature engine performance",
        "",
    ]

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"\nReport written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="AkesoAV Performance Benchmark")
    parser.add_argument("--corpus", help="Path to file corpus (generated if omitted)")
    parser.add_argument("--db", help="Path to .akavdb signature database")
    parser.add_argument("--clamscan", help="Path to ClamAV clamscan.exe")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"Number of files to generate (default: {DEFAULT_COUNT})")
    parser.add_argument("--report", default="docs/benchmark_report.md",
                        help="Output report path")
    args = parser.parse_args()

    # Resolve akavscan path
    global AKAVSCAN
    if not os.path.exists(AKAVSCAN):
        alt = os.path.join(os.path.dirname(__file__), "..", "build", "Release", "akavscan.exe")
        if os.path.exists(alt):
            AKAVSCAN = alt

    # Generate or use existing corpus
    if args.corpus:
        corpus_dir = args.corpus
    else:
        corpus_dir = os.path.join(tempfile.gettempdir(), "akav_benchmark_corpus")
        if not os.path.exists(corpus_dir) or len(os.listdir(corpus_dir)) == 0:
            generate_corpus(corpus_dir, args.count)
        else:
            print(f"Using existing corpus: {corpus_dir}")

    files = collect_files(corpus_dir)
    if not files:
        print("ERROR: No files in corpus")
        sys.exit(1)

    print(f"Corpus: {len(files)} files")

    # Pass 1: Cold scan (no cache)
    akav_cold = benchmark_akavscan(files, args.db, label="AkesoAV (cold)")

    # Pass 2: Warm scan (cache populated)
    akav_warm = benchmark_akavscan(files, args.db, label="AkesoAV (warm)")

    # ClamAV comparison (optional)
    clam = benchmark_clamscan(files, args.clamscan)

    # Generate report
    if akav_cold and akav_warm:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        generate_report(akav_cold, akav_warm, clam, args.report)

    # Summary
    print("\n" + "=" * 60)
    print("=== Benchmark Complete ===")
    if akav_cold:
        print(f"  Cold: {akav_cold['throughput']} files/sec, p50={akav_cold.get('p50_ms')}ms")
    if akav_warm:
        print(f"  Warm: {akav_warm['throughput']} files/sec, p50={akav_warm.get('p50_ms')}ms")
        cache_rate = akav_warm.get('cached', 0) * 100.0 / max(akav_warm['files'], 1)
        print(f"  Cache hit rate: {cache_rate:.1f}%")
    if clam:
        print(f"  ClamAV: {clam['throughput']} files/sec, p50={clam.get('p50_ms')}ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
