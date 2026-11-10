"""E6 local CPU measurements; HIBP is explicitly stubbed, real zxcvbn is timed."""
import argparse
import json
import platform
import random
import statistics
import string
import sys
import time
import tracemalloc
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
from vault.audit import audit_vault, detect_derivative_families
from vault.gate import evaluate_save_gate
from vault.models import Entry,Profile
from modules.syntactic import BreachStatus


def measure(fn,repeats):
    times=[]
    for _ in range(repeats):
        start=time.perf_counter();fn();times.append((time.perf_counter()-start)*1000)
    tracemalloc.start();fn();_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    return dict(repeats=repeats,median_ms=statistics.median(times),p95_ms=float(np.percentile(times,95)),p99_ms=float(np.percentile(times,99)),peak_python_bytes=peak,raw_ms=times)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes',nargs='+',type=int,default=[10,100,500,1000,5000])
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--out',type=Path,default=Path('results/review1/performance.json'))
    args=parser.parse_args()
    if args.repeats<2:raise ValueError('Repeated trials required')
    rng=random.Random(42);profile=Profile('Maya','Carter','Denver',1998);records=[]
    with patch('vault.audit.check_hibp_k_anonymity',return_value=0),patch('vault.gate.check_hibp_status',return_value=(BreachStatus.NOT_BREACHED,0)):
        for n in args.sizes:
            entries=[Entry(str(i),f'site{i}','','fictional',''.join(rng.choices(string.ascii_letters+string.digits,k=16))) for i in range(n)]
            operations={'full_local_audit':lambda:audit_vault(entries,profile),
                        'save_gate':lambda:evaluate_save_gate('Candidate-Passphrase-For-Study!','test',entries,profile),
                        'derivative_chain':lambda:detect_derivative_families(entries)}
            for name,fn in operations.items():
                record=dict(size=n,component=name,**measure(fn,args.repeats));records.append(record)
                print(f'{n} {name}: {record["median_ms"]:.1f} ms',flush=True)
            # Disable exactly one component while preserving the rest of the real audit.
            for name,target,value in [('without_derivatives','vault.audit.detect_derivative_families',({},{})),
                                       ('without_semantic','vault.audit.calculate_thematic_coverage',{'score':0.,'matched_fields':[]}),
                                       ('without_syntax','vault.audit.evaluate_syntactic_strength',{'score':4})]:
                with patch(target,return_value=value):
                    records.append(dict(size=n,component=name,**measure(lambda:audit_vault(entries,profile),args.repeats)))
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text(json.dumps(dict(platform=platform.platform(),python=sys.version,processor=platform.processor(),
                  caveats=['HIBP stubbed: excludes network latency','Peak memory is traced Python allocation, not process RSS',
                           'Small repeat counts give descriptive tail quantiles, not stable p99 estimates',
                           'One host and random fictional vaults only'],results=records),indent=2))
if __name__=='__main__':main()
