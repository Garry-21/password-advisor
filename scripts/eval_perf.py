"""
scripts/eval_perf.py
--------------------
Performance & Throughput Evaluation Harness (Section 9):
- Benchmarks cryptographic latency:
  1. Argon2id KDF derivation time (p50, p95)
  2. AES-256-GCM record encryption / decryption throughput (ops/sec, MB/sec)
- Benchmarks audit engine computational scaling across vault sizes:
  N = 10, 50, 100, 250, 500 entries (offline local pipeline)
- Profiles peak memory footprint using tracemalloc
- Outputs clean Markdown tables
"""

import sys
import time
import secrets
import statistics
import tracemalloc
from pathlib import Path
from typing import List

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.models import Entry, Profile
from vault.crypto import (
    generate_dek,
    derive_k_pw,
    derive_kek,
    encrypt_entry,
    decrypt_entry,
    SALT_LEN_BYTES
)
from vault.audit import audit_vault


def benchmark_argon2id(iterations: int = 10):
    print("Benchmarking Argon2id KDF latency...")
    latencies = []
    dummy_password = "BenchmarkMasterPassword#2026!"
    salt = secrets.token_bytes(SALT_LEN_BYTES)

    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = derive_k_pw(dummy_password, salt)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    p50 = statistics.median(latencies)
    mean = statistics.mean(latencies)
    std = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    sorted_lats = sorted(latencies)
    p95_idx = int(0.95 * len(sorted_lats))
    p95 = sorted_lats[min(p95_idx, len(sorted_lats) - 1)]

    return {
        "p50_ms": round(p50, 1),
        "mean_ms": round(mean, 1),
        "std_ms": round(std, 1),
        "p95_ms": round(p95, 1),
        "min_ms": round(min(latencies), 1),
        "max_ms": round(max(latencies), 1),
    }


def benchmark_aes_gcm(record_count: int = 5000):
    print(f"Benchmarking AES-256-GCM record encryption & decryption ({record_count:,} cycles)...")
    dek = generate_dek()
    entry = Entry(
        id="perf-record-001",
        site_name="PerformanceTestingSite",
        url="https://benchmark.internal/login",
        username="perf_tester@corp.local",
        password="CryptographicBenchmarkToken#999!",
        notes="Benchmarking payload with realistic field lengths and metadata."
    )

    raw_bytes_len = len(entry.to_json_bytes())
    total_bytes = raw_bytes_len * record_count

    # 1. Encryption throughput
    t0 = time.perf_counter()
    enc_results = []
    for _ in range(record_count):
        nonce, ct = encrypt_entry(entry, dek)
        enc_results.append((nonce, ct))
    enc_duration = time.perf_counter() - t0

    enc_ops_sec = record_count / enc_duration
    enc_mb_sec = (total_bytes / (1024 * 1024)) / enc_duration

    # 2. Decryption throughput
    t0 = time.perf_counter()
    for nonce, ct in enc_results:
        _ = decrypt_entry("perf-record-001", nonce, ct, dek)
    dec_duration = time.perf_counter() - t0

    dec_ops_sec = record_count / dec_duration
    dec_mb_sec = (total_bytes / (1024 * 1024)) / dec_duration

    return {
        "record_count": record_count,
        "entry_size_bytes": raw_bytes_len,
        "enc_ops_sec": round(enc_ops_sec, 0),
        "enc_mb_sec": round(enc_mb_sec, 2),
        "dec_ops_sec": round(dec_ops_sec, 0),
        "dec_mb_sec": round(dec_mb_sec, 2),
    }


def benchmark_audit_scaling(sizes: List[int] = [10, 50, 100, 250, 500]):
    print("Benchmarking local audit engine computational scaling...")
    profile = Profile(
        first_name="Alexander",
        surname="Hamilton",
        city="Albany",
        birth_year=1995,
        theme="scifi"
    )

    results = []
    
    # Pre-generate sample entries
    passwords = [
        "Summer2024!", "Summer2025!", "WinterBreak99", "Alexander1995!",
        "AlbanySummer95!", "UniqueSharedTokenAlpha#2026", "CleanCorrectHorse2026!#",
        "QuantumNebulaWarp888$", "SimplePass123", "password"
    ]

    for n in sizes:
        entries = []
        for i in range(n):
            pw = passwords[i % len(passwords)]
            e = Entry(
                id=f"e_{i}",
                site_name=f"Site_{i}",
                url=f"https://site{i}.com",
                username=f"user_{i}",
                password=pw
            )
            entries.append(e)

        # Run audit (offline mode: 0 threads for HIBP to measure purely local algorithms)
        t0 = time.perf_counter()
        report = audit_vault(entries, profile=profile, max_hibp_threads=1)
        duration = time.perf_counter() - t0

        ms_per_entry = (duration / n) * 1000.0
        results.append({
            "size": n,
            "total_time_ms": round(duration * 1000.0, 1),
            "ms_per_entry": round(ms_per_entry, 2),
            "vhs": round(report.vhs_score, 1)
        })

    return results


def run_performance_suite():
    print("=" * 70)
    print("CONTEXT-AWARE VAULT (CAV) PERFORMANCE & SCALABILITY EVALUATION")
    print("=" * 70)

    tracemalloc.start()

    # 1. Argon2id KDF
    kdf_stats = benchmark_argon2id(iterations=5)

    # 2. AES-256-GCM Throughput
    aes_stats = benchmark_aes_gcm(record_count=5000)

    # 3. Audit Scaling
    audit_scaling = benchmark_audit_scaling([10, 50, 100, 200])

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n" + "=" * 70)
    print("### 1. Cryptographic Latency (Argon2id KDF)")
    print("Parameters: m=64 MiB, t=3 passes, p=4 lanes\n")
    print(f"| Metric | Latency (ms) |")
    print(f"| :--- | :---: |")
    print(f"| Median (p50) | {kdf_stats['p50_ms']} ms |")
    print(f"| 95th Percentile (p95) | {kdf_stats['p95_ms']} ms |")
    print(f"| Mean ± Std | {kdf_stats['mean_ms']} ± {kdf_stats['std_ms']} ms |")
    print(f"| Min / Max | {kdf_stats['min_ms']} / {kdf_stats['max_ms']} ms |")

    print("\n### 2. Envelope Encryption Throughput (AES-256-GCM)")
    print(f"Payload size: {aes_stats['entry_size_bytes']} bytes/record\n")
    print(f"| Operation | Throughput (records/sec) | Bandwidth (MB/sec) |")
    print(f"| :--- | :---: | :---: |")
    print(f"| Encrypt Record | {aes_stats['enc_ops_sec']:,.0f} ops/s | {aes_stats['enc_mb_sec']} MB/s |")
    print(f"| Decrypt Record | {aes_stats['dec_ops_sec']:,.0f} ops/s | {aes_stats['dec_mb_sec']} MB/s |")

    print("\n### 3. Context-Aware Audit Computational Scaling")
    print("| Vault Size (N) | Total Latency (ms) | Latency per Entry (ms) | Resulting VHS |")
    print("| :---: | :---: | :---: | :---: |")
    for row in audit_scaling:
        print(f"| {row['size']} entries | {row['total_time_ms']} ms | {row['ms_per_entry']} ms | {row['vhs']} / 100 |")

    print(f"\n- **Peak Memory Footprint**: {peak_mem / (1024 * 1024):.2f} MB")
    print("=" * 70)


if __name__ == "__main__":
    run_performance_suite()
