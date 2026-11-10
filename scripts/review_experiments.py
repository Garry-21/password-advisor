"""Review 1 E1–E3: reproducible synthetic smoke evaluation or supplied JSONL benchmark.

Synthetic output is engineering validation, not independent publication evidence.
No network calls, real vault access, or deployment of fitted models occurs here.
"""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import random
import string
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (confusion_matrix, balanced_accuracy_score, average_precision_score,
                             roc_auc_score, brier_score_loss, adjusted_rand_score)
from vault.research import FEATURES, features, fixed_score, guesses
from vault.audit import detect_derivative_families
from vault.models import Entry


def synthetic_rows(profiles=90, seed=42):
    rng = random.Random(seed)
    rows = []
    # User/family/template groups are disjoint across splits. This remains synthetic.
    for i in range(profiles):
        split = ('train', 'validation', 'test')[i % 3]
        token = ''.join(rng.choices(string.ascii_lowercase, k=9)).capitalize()
        city = ''.join(rng.choices(string.ascii_lowercase, k=10)).capitalize()
        profile = dict(first_name=token, surname=token[::-1], city=city, birth_year=1970+i%35)
        old = token + 'Orbit2024!'
        year = str(profile['birth_year'])
        # Distinct construction templates for each split; common weak vocabulary
        # stays within one split so identical targets never cross partitions.
        sep = {'train':'', 'validation':'_', 'test':'-'}[split]
        examples = [
            ('direct', token+sep+year+'!', 1),
            ('leetspeak', token.replace('a','@').replace('e','3')+sep+year, 1),
            ('partial', token[:4]+sep+year[-2:]+'!', 1),
            ('reordered', year+sep+token+'!', 1),
            ('multi_attribute', token+sep+city+'!', 1),
            ('history_derived', old.replace('2024','2025'), 1),
            ('exact_reuse', old, 1),
            ('unrelated_weak', {'train':'password123!', 'validation':'welcome123!', 'test':'dragon123!'}[split], 0),
            ('random', ''.join(rng.choices(string.ascii_letters+string.digits+'!#',k=20)), 0),
            ('hard_negative', 'Unrelated'+token[:3]+'#'+str(i), 0),
            ('unseen_transformation', token[::-1][::2]+sep+city[::2]+'!', 1),
        ]
        for category, password, label in examples:
            rows.append(dict(id=f'{i}:{category}', profile_id=f'P{i}', family_id=f'F{i}',
                             template_id=f'{split}:{category}', split=split, profile=profile,
                             password=password, previous_password=old, other_passwords=[old],
                             category=category, label_personal=label,
                             breach_count=int(category=='unrelated_weak'),
                             age_days=30 if i%2 else 400, criticality=1+i%3,
                             provenance='synthetic_smoke_not_independent'))
    return rows


def validate_rows(rows):
    if not rows:
        raise ValueError('Empty benchmark')
    splits = {'train','validation','test'}
    if {r['split'] for r in rows} != splits:
        raise ValueError('Explicit train, validation and test partitions required')
    for key in ('profile_id','family_id','template_id','password'):
        seen = {}
        for r in rows:
            value = r[key]
            if not value:
                raise ValueError(f'Missing {key}')
            if value in seen and seen[value] != r['split']:
                raise ValueError(f'{key} leaks across partitions')
            seen[value] = r['split']
    if len({r['id'] for r in rows}) != len(rows):
        raise ValueError('Duplicate sample IDs')
    for r in rows:
        if r['label_personal'] not in (0,1) or r['breach_count'] < 0:
            raise ValueError('Binary personal labels and known breach counts required')
        if not r.get('provenance'):
            raise ValueError('Dataset provenance required')


def metrics(y, scores, threshold):
    y, scores = np.asarray(y), np.asarray(scores)
    pred = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel()
    two = len(set(y.tolist())) == 2
    precision = tp/(tp+fp) if tp+fp else 0.
    recall = tp/(tp+fn) if tp+fn else 0.
    return dict(n=len(y), tp=int(tp),fp=int(fp),tn=int(tn),fn=int(fn),
                precision=float(precision), recall=float(recall),
                f1=float(2*precision*recall/(precision+recall)) if precision+recall else 0.,
                fpr=float(fp/(fp+tn)) if fp+tn else None,
                balanced_accuracy=float(balanced_accuracy_score(y,pred)) if two else None,
                pr_auc=float(average_precision_score(y,scores)) if any(y) else None,
                roc_auc=float(roc_auc_score(y,scores)) if two else None,
                brier=float(brier_score_loss(y,scores)), threshold=float(threshold))


def threshold_at_fpr(y, scores, max_fpr=.05):
    if len(set(y)) != 2:
        raise ValueError('Validation requires both outcome classes')
    candidates = [float(np.nextafter(max(scores), np.inf))] + sorted(set(scores), reverse=True)
    acceptable = [(metrics(y,scores,t)['recall'],t) for t in candidates if metrics(y,scores,t)['fpr'] <= max_fpr]
    return max(acceptable)[1]


def bootstrap(y, scores_a, scores_b, groups, threshold_a, threshold_b, repetitions=300):
    rng = np.random.default_rng(42)
    unique = np.unique(groups)
    differences = []
    for _ in range(repetitions):
        idx = np.concatenate([np.flatnonzero(groups == g) for g in rng.choice(unique,len(unique),replace=True)])
        if not np.any(y[idx]):
            continue
        a = metrics(y[idx], scores_a[idx],threshold_a)['recall']
        b = metrics(y[idx], scores_b[idx],threshold_b)['recall']
        differences.append(a-b)
    return np.percentile(differences,[2.5,97.5]).tolist() if differences else None


def evaluate(rows, out, budgets=(100,1000), bootstrap_repetitions=300):
    validate_rows(rows)
    out.mkdir(parents=True, exist_ok=True)
    x = np.asarray([features(r) for r in rows])
    partitions = {s:np.array([i for i,r in enumerate(rows) if r['split']==s]) for s in ('train','validation','test')}
    tr, va, te = [partitions[s] for s in ('train','validation','test')]
    personal = np.array([r['label_personal'] for r in rows])
    e1_threshold = threshold_at_fpr(personal[va], x[va,1])
    e1 = {'threshold_source':'validation, FPR <= 0.05', 'overall':metrics(personal[te],x[te,1],e1_threshold), 'categories':{}}
    for category in sorted({r['category'] for r in rows}):
        idx = np.array([i for i in te if rows[i]['category']==category])
        if len(idx): e1['categories'][category] = metrics(personal[idx],x[idx,1],e1_threshold)
    (out/'e1.json').write_text(json.dumps(e1,indent=2))
    # Each scenario gets its own outcome, measured independently of detector rules.
    outcomes, attack_records = {}, []
    for scenario in ('S1','S2','S3','S4','S5'):
        ranks = []
        for r in rows:
            candidates = list(guesses(r['profile'],r['previous_password'],scenario,max(budgets)))
            rank = candidates.index(r['password'])+1 if r['password'] in candidates else None
            ranks.append(rank)
            attack_records.append(dict(id=r['id'],scenario=scenario,rank=rank,distinct_guesses=len(candidates)))
        for budget in budgets:
            outcomes[f'{scenario}@{budget}'] = np.array([int(rank is not None and rank<=budget) for rank in ranks])
    (out/'attack_outcomes.json').write_text(json.dumps(attack_records,indent=2))
    y = outcomes[f'S5@{max(budgets)}']
    if len(set(y[tr])) != 2:
        raise ValueError('Training attack outcome needs both classes')
    models = {
        'B1_syntax':x[:,2], 'B2_breach_fixture':x[:,0],
        'B3_syntax_breach':np.maximum(x[:,0],x[:,2]), 'B4_personal':x[:,1],
        'B5_history':np.maximum(x[:,3],x[:,4]),
        'B6_submitted_weights':np.array([fixed_score(v,True) for v in x]),
        'CAV_current':np.array([fixed_score(v) for v in x])}
    trained = LogisticRegression(random_state=42,max_iter=1000).fit(x[tr],y[tr])
    models['B7_logistic'] = trained.predict_proba(x)[:,1]
    for j,name in enumerate(FEATURES):
        masked=x.copy();masked[:,j]=0
        models[f'fixed_without_{name}'] = np.array([fixed_score(v,True) for v in masked])
        keep=[k for k in range(6) if k!=j]
        fit=LogisticRegression(random_state=42,max_iter=1000).fit(x[tr][:,keep],y[tr])
        models[f'refit_without_{name}']=fit.predict_proba(x[:,keep])[:,1]
    thresholds={name:threshold_at_fpr(y[va],score[va]) for name,score in models.items()}
    report={name:metrics(y[te],score[te],thresholds[name]) for name,score in models.items()}
    groups=np.array([rows[i]['profile_id'] for i in te])
    for name in ('CAV_current','B7_logistic'):
        report[name]['recall_difference_vs_syntax_ci95']=bootstrap(y[te],models[name][te],models['B1_syntax'][te],groups,thresholds[name],thresholds['B1_syntax'],bootstrap_repetitions)
    (out/'e2.json').write_text(json.dumps(report,indent=2))
    model = dict(intercept=float(trained.intercept_[0]),coefficients=dict(zip(FEATURES,trained.coef_[0].tolist())),
                 outcome=f'S5@{max(budgets)}', provenance='research_only_not_deployed',feature_names=FEATURES)
    (out/'research_scorer.json').write_text(json.dumps(model,indent=2))
    e3={}
    for scenario,labels in outcomes.items():
        e3[scenario]={name:metrics(labels[te],models[name][te],thresholds[name]) for name in ('B1_syntax','B6_submitted_weights','CAV_current','B7_logistic')}
    (out/'e3.json').write_text(json.dumps(e3,indent=2))
    bands={}
    for name in ('B6_submitted_weights','CAV_current','B7_logistic'):
        scores=models[name][te];band_rows=[]
        for low in np.arange(0,1,.2):
            mask=(scores>=low)&(scores<low+.2 if low<.8 else scores<=1)
            band_rows.append(dict(lower=float(low),n=int(mask.sum()),mean_score=float(scores[mask].mean()) if any(mask) else None,
                                  observed_attack_success=float(y[te][mask].mean()) if any(mask) else None))
        bands[name]=band_rows
    (out/'calibration.json').write_text(json.dumps(bands,indent=2))
    # Criticality ablation is a vault aggregation/ranking comparison, not a new password label.
    aggregation=[]
    for pid in sorted(set(groups)):
        idx=np.array([i for i in te if rows[i]['profile_id']==pid]);w=np.array([rows[i]['criticality'] for i in idx])
        aggregation.append(dict(profile_id=pid,weighted_priority=float(np.average(models['CAV_current'][idx],weights=w)),
                                unweighted_priority=float(models['CAV_current'][idx].mean()),
                                weighted_attack_rate=float(np.average(y[idx],weights=w))))
    (out/'criticality_ablation.json').write_text(json.dumps(aggregation,indent=2))
    errors=[dict(id=rows[i]['id'],category=rows[i]['category'],personal_label=int(personal[i]),personal_prediction=int(x[i,1]>=e1_threshold),
                 attack_label=int(y[i]),cav_prediction=int(models['CAV_current'][i]>=thresholds['CAV_current'])) for i in te]
    (out/'heldout_predictions.json').write_text(json.dumps(errors,indent=2))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,help='Authorized independently labelled JSONL benchmark')
    parser.add_argument('--out',type=Path,default=Path('results/review1'))
    parser.add_argument('--profiles',type=int,default=90)
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--budgets',nargs='+',type=int,default=[100,1000])
    args=parser.parse_args()
    rows=[json.loads(line) for line in args.input.read_text().splitlines() if line.strip()] if args.input else synthetic_rows(args.profiles,args.seed)
    report=evaluate(rows,args.out,tuple(args.budgets))
    manifest=dict(dataset_sha256=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest(),samples=len(rows),
                  profiles=len({r['profile_id'] for r in rows}),seed=args.seed,budgets=args.budgets,
                  dataset_type='supplied_unverified_provenance' if args.input else 'synthetic_smoke_not_independent',
                  python=sys.version,platform=platform.platform(),processor=platform.processor(),
                  dependencies={p:importlib.metadata.version(p) for p in ('numpy','scikit-learn','zxcvbn-python','rapidfuzz')},
                  limitations=['Toy attacker v1, not MDIGuess or PII-Pass2Path reproduction',
                  'Breach input is supplied evidence; synthetic fixture is not live HIBP',
                  'Heuristic scores are not compromise probabilities',
                  'Matched FPR is selected on validation; held-out FPR may differ',
                  'B8 unavailable; no state-of-the-art superiority claim',
                  'Synthetic benchmark cannot establish external validity'])
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps({'out':str(args.out),'samples':len(rows),'heldout':report['CAV_current']},indent=2))
if __name__=='__main__':main()
