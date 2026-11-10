"""Fictional-task study logging. Passwords and password hashes are never persisted."""
import csv
import hashlib
import os
import time
from pathlib import Path
CONDITIONS = ['G1','G2','G3','G4']
DEFAULT_STUDY_LOG = 'data/private/study_events.csv'

def is_study_mode():
    return os.environ.get('STUDY_MODE') == '1'

def assign_condition(participant_id):
    """Reproducible allocation; conceal the study seed during recruitment.

    This is hash allocation, not a claim of balanced randomized assignment.
    """
    if not participant_id.strip():
        raise ValueError('Participant ID required')
    seed=os.environ.get('STUDY_SEED','demo-allocation-not-for-recruitment')
    h=hashlib.sha256(f'{seed}:{participant_id.strip().upper()}'.encode()).digest()
    return CONDITIONS[int.from_bytes(h[:8],'big')%4]

def log_study_event(participant_id, condition, task_id, final_password, warning_shown,
                    overridden, accepted_alternative, time_ms, log_path=DEFAULT_STUDY_LOG,
                    *, vulnerable=None, source='demo', protocol_id='review1-v1'):
    """Store outcomes only. `final_password` is accepted for API compatibility and discarded.

    Primary outcome is nullable until independently evaluated. Do not infer it from warnings.
    """
    if condition not in CONDITIONS or not participant_id.strip() or not task_id.strip():
        raise ValueError('Valid participant, task and condition required')
    if time_ms < 0 or source not in ('demo','synthetic','human'):
        raise ValueError('Invalid event metadata')
    path=Path(log_path);path.parent.mkdir(parents=True,exist_ok=True)
    fields=['participant_id','condition','task_id','warning_shown','overridden',
            'accepted_alternative','time_ms','vulnerable','source','protocol_id','recorded_at']
    if path.exists() and path.stat().st_size:
        with path.open(newline='') as f:
            if next(csv.reader(f)) != fields:
                raise ValueError('Incompatible legacy study log; choose a new output path')
    with path.open('a',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields)
        if f.tell()==0:writer.writeheader()
        writer.writerow(dict(participant_id=participant_id,condition=condition,task_id=task_id,
                             warning_shown=int(warning_shown),overridden=int(overridden),
                             accepted_alternative=int(accepted_alternative),time_ms=round(time_ms,1),
                             vulnerable='' if vulnerable is None else int(vulnerable),source=source,
                             protocol_id=protocol_id,recorded_at=int(time.time())))
    os.chmod(path,0o600)
