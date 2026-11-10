"""Benchmark audit components and derivative clustering scaling across vault sizes."""
import argparse
import csv
import functools
import os
import sys
import time
import tracemalloc
from unittest.mock import patch
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from vault.models import Entry, Profile
from vault.audit import audit_vault, AuditConfig, detect_derivative_families

def generate_vault_entries(n: int) -> list:
    bases = ["Summer2024!", "SecretPass99", "AlphaBravo1#", "Password1234", "FalconWing88"]
    entries = []
    for i in range(n):
        base = bases[i % len(bases)]
        pwd = f"{base}_{i % 10}" if (i % 3 == 0) else f"Rand_{i}_{base}"
        entries.append(Entry(
            id=str(i), site_name=f"site{i}.com", url=f"https://site{i}.com",
            username=f"user{i}", password=pwd, created_at="2024-01-01T00:00:00"
        ))
    return entries

def bench_op(func, repeats=3):
    latencies, mems = [], []
    for _ in range(repeats):
        tracemalloc.start()
        t0 = time.perf_counter()
        func()
        elapsed = (time.perf_counter() - t0) * 1000.0  # ms
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        latencies.append(elapsed)
        mems.append(peak / 1024.0)  # KB
    return {
        "median_ms": float(np.median(latencies)),
        "p95_ms": float(np.percentile(latencies, 95)),
        "p99_ms": float(np.percentile(latencies, 99)),
        "peak_mem_kb": float(np.max(mems)),
    }

def run_benchmarks(sizes=(10, 100, 500, 1000, 5000), out_csv="results/bench_perf.csv"):
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    profile = Profile(first_name="Alice", surname="Smith", city="Boston", birth_year=1988, theme="football")
    results = []
    
    print(f"{'Size':<6} | {'Component/Mode':<24} | {'Median(ms)':<10} | {'P95(ms)':<10} | {'P99(ms)':<10} | {'Peak(KB)':<10}")
    print("-" * 80)

    # Mock evaluate_syntactic_strength and HIBP to benchmark vault audit overhead and derivative clustering cleanly
    dummy_syntax = {"score": 3, "guesses_log10": 10.0, "warning": "", "suggestions": []}
    with patch("vault.audit.evaluate_syntactic_strength", return_value=dummy_syntax), \
         patch("vault.audit.check_hibp_k_anonymity", return_value=0):
        for n in sizes:
            entries = generate_vault_entries(n)
            repeats = 3 if n <= 1000 else 1

            # 1. Full Audit (Chain mode)
            cfg_chain = AuditConfig(cluster_mode="chain")
            res_chain = bench_op(lambda: audit_vault(entries, profile=profile, config=cfg_chain, max_hibp_threads=1), repeats=repeats)
            results.append({"size": n, "component": "full_audit_chain", **res_chain})
            print(f"{n:<6} | {'full_audit_chain':<24} | {res_chain['median_ms']:<10.2f} | {res_chain['p95_ms']:<10.2f} | {res_chain['p99_ms']:<10.2f} | {res_chain['peak_mem_kb']:<10.1f}", flush=True)

            # 2. Derivative Clustering: Chain Mode
            res_dc_c = bench_op(lambda: detect_derivative_families(entries, cluster_mode="chain"), repeats=repeats)
            results.append({"size": n, "component": "deriv_cluster_chain", **res_dc_c})
            print(f"{n:<6} | {'deriv_cluster_chain':<24} | {res_dc_c['median_ms']:<10.2f} | {res_dc_c['p95_ms']:<10.2f} | {res_dc_c['p99_ms']:<10.2f} | {res_dc_c['peak_mem_kb']:<10.1f}", flush=True)

            # 3. Derivative Clustering: Pairwise Mode
            res_dc_p = bench_op(lambda: detect_derivative_families(entries, cluster_mode="pairwise"), repeats=repeats)
            results.append({"size": n, "component": "deriv_cluster_pairwise", **res_dc_p})
            print(f"{n:<6} | {'deriv_cluster_pairwise':<24} | {res_dc_p['median_ms']:<10.2f} | {res_dc_p['p95_ms']:<10.2f} | {res_dc_p['p99_ms']:<10.2f} | {res_dc_p['peak_mem_kb']:<10.1f}", flush=True)

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["size", "component", "median_ms", "p95_ms", "p99_ms", "peak_mem_kb"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved performance benchmark results to {out_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit Performance Benchmark")
    parser.add_argument("--sizes", nargs="+", type=int, default=[10, 100, 500, 1000, 5000])
    parser.add_argument("--out", type=str, default="results/bench_perf.csv")
    args = parser.parse_args()
    run_benchmarks(sizes=args.sizes, out_csv=args.out)
