"""
eval_vault_crypto.py
--------------------
Benchmarks Argon2id KDF parameter sets to calibrate unlock latency between 300-600 ms on the host.
Measures execution time across various memory (m), iteration (t), and parallelism (p) settings.
"""

import os
import sys
import time
import secrets

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault.crypto import derive_k_pw

CANDIDATES = [
    {"m": 32768, "t": 2, "p": 2, "desc": "32 MiB, 2 iterations, 2 threads (Low)"},
    {"m": 65536, "t": 2, "p": 4, "desc": "64 MiB, 2 iterations, 4 threads (Moderate)"},
    {"m": 65536, "t": 3, "p": 4, "desc": "64 MiB, 3 iterations, 4 threads (Default Standard)"},
    {"m": 65536, "t": 4, "p": 4, "desc": "64 MiB, 4 iterations, 4 threads (High)"},
    {"m": 131072, "t": 2, "p": 4, "desc": "128 MiB, 2 iterations, 4 threads (High Memory)"},
]

def benchmark():
    print("=" * 65)
    print("ARGON2ID CALIBRATION BENCHMARK (Target: 300 - 600 ms)")
    print("=" * 65)
    
    salt = secrets.token_bytes(16)
    test_password = "CorrectHorseBatteryStaple2026!"
    
    best_candidate = None
    best_diff = float("inf")
    target_ms = 450.0

    print(f"{'Parameters':<40} | {'Time (ms)':<10} | {'Status'}")
    print("-" * 65)

    for cfg in CANDIDATES:
        m, t, p = cfg["m"], cfg["t"], cfg["p"]
        
        # Warmup
        _ = derive_k_pw(test_password, salt, m=m, t=t, p=p)
        
        # Timed runs
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            _ = derive_k_pw(test_password, salt, m=m, t=t, p=p)
            times.append((time.perf_counter() - t0) * 1000.0)

        avg_ms = sum(times) / len(times)
        
        if 300.0 <= avg_ms <= 600.0:
            status = "[RECOMMENDED]"
        elif avg_ms < 300.0:
            status = "[FAST]"
        else:
            status = "[SLOW]"

        diff = abs(avg_ms - target_ms)
        if diff < best_diff:
            best_diff = diff
            best_candidate = (cfg, avg_ms)

        print(f"{cfg['desc']:<40} | {avg_ms:8.2f} ms | {status}")

    print("-" * 65)
    if best_candidate:
        cfg, dur = best_candidate
        print(f"\nOptimal Host Parameter: m={cfg['m']} KiB, t={cfg['t']}, p={cfg['p']} (~{dur:.1f} ms)")

if __name__ == "__main__":
    benchmark()
