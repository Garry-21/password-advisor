import json
import pytest
from scripts.export_study_logs import export_study_summary
from vault.study import log_study_event

def test_study_analysis_keeps_provenance_separate(tmp_path):
    path=tmp_path/'study.csv';out=tmp_path/'summary.json'
    log_study_event('D1','G1','T1','unused',True,True,False,100,str(path),source='demo',vulnerable=True)
    with pytest.raises(ValueError,match='No human'):export_study_summary(str(path),str(out))
    for participant,condition,vulnerable in [('P1','G2',True),('P2','G3',False)]:
        for task in ('T1','T2'):
            log_study_event(participant,condition,task,'unused',True,True,False,100,str(path),source='human',vulnerable=vulnerable)
    result=export_study_summary(str(path),str(out))
    assert result['groups']['G1']['participants']==0
    assert result['groups']['G2']['participants']==1
    assert result['contrasts']['G3_minus_G2']['difference']==-1
    log_study_event('P1','G2','T1','unused',True,True,False,100,str(path),source='human',vulnerable=True)
    with pytest.raises(ValueError,match='Duplicate'):export_study_summary(str(path),str(out))
