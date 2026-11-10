"""Independent planted-family fixture for pair and cluster metrics; synthetic only."""
import json, random, string, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sklearn.metrics import adjusted_rand_score
from vault.models import Entry
from vault.audit import detect_derivative_families
from vault.research import attack_rank
from scripts.review_experiments import metrics

def run(out=Path('results/review1/clusters.json')):
    rng=random.Random(72);entries=[];truth=[]
    for family in range(30):
        base=''.join(rng.choices(string.ascii_letters,k=12))
        for year in (2023,2024,2025):
            entries.append(Entry(str(len(entries)),str(len(entries)),'','fictional',base+str(year)+'!'))
            truth.append(family)
    for i in range(30):
        entries.append(Entry(str(len(entries)),str(len(entries)),'','fictional',''.join(rng.choices(string.ascii_letters+string.digits,k=20))))
        truth.append(30+i)
    report={}
    for mode in ('chain','pairwise'):
        assigned,_=detect_derivative_families(entries,mode)
        pred=[assigned.get(e.id,-i-1) for i,e in enumerate(entries)]
        yt=[];yp=[];guessed=0;known=0
        for i in range(len(entries)):
            for j in range(i+1,len(entries)):
                yt.append(int(truth[i]==truth[j]));yp.append(int(pred[i]==pred[j]))
                if truth[i]==truth[j]:
                    known+=1
                    guessed+=attack_rank(entries[j].password,{},entries[i].password,'S3',1000) is not None
        precisions=[];recalls=[]
        for i in range(len(entries)):
            actual={j for j in range(len(entries)) if truth[i]==truth[j]}
            predicted={j for j in range(len(entries)) if pred[i]==pred[j]}
            overlap=len(actual&predicted)
            precisions.append(overlap/len(predicted));recalls.append(overlap/len(actual))
        report[mode]=dict(pairwise=metrics(yt,yp,.5),adjusted_rand=float(adjusted_rand_score(truth,pred)),
                          bcubed_precision=sum(precisions)/len(entries),bcubed_recall=sum(recalls)/len(entries),
                          known_family_pairs=known,history_guessed_pairs=guessed)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps({'provenance':'synthetic planted families; not population accuracy','results':report},indent=2))
if __name__=='__main__':run()
