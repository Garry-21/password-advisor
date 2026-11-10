import json
import pytest
from vault.models import Profile, Entry, AuthError
from vault.store import VaultStore
from vault.crypto import generate_dek, create_vault_header
from vault.audit import audit_vault, AuditConfig, calculate_risk_score
from vault.backup import create_encrypted_backup, restore_encrypted_backup
from vault.session import SessionManager
from modules.semantic import calculate_thematic_coverage
from modules.syntactic import check_hibp_status, BreachStatus
from vault.study import log_study_event


def test_unknown_is_interval_not_imputed_probability(monkeypatch):
    monkeypatch.setattr('vault.audit.check_hibp_k_anonymity',lambda _: -1)
    e=Entry('1','site','','u','Unique-Xylophone-Planet-Butterfly!')
    report=audit_vault([e])
    result=report.entry_results[0]
    assert result.b_i is None and result.breach_count==-1
    assert result.breach_status=='unknown'
    assert result.risk_upper_bound>result.risk_score
    assert report.vhs_lower_bound<report.vhs_score


def test_age_opt_out_honored_with_custom_nonzero_weight():
    cfg=AuditConfig(weights={'breach':0,'semantic':0,'syntax':0,'reuse':0,'derivative':0,'age':1})
    assert calculate_risk_score(a_i=1,config=cfg)==0
    cfg.enable_age_score=True
    assert calculate_risk_score(a_i=1,config=cfg)==1


def test_reuse_same_site_different_accounts():
    entries=[Entry(str(i),'SameService','','user'+str(i),'Unique-Xylophone-Planet-Butterfly!') for i in range(2)]
    assert audit_vault(entries).reused_count==2


def test_birth_year_must_exist():
    result=calculate_thematic_coverage('Alexander!SuperLong',{'first_name':'Alexander','birth_year':1998})
    assert 'birth year' not in result['matched_fields']


def test_plaintext_profile_write_rejected(tmp_path):
    store=VaultStore(str(tmp_path/'v.db'))
    with pytest.raises(AuthError):store.save_profile(Profile('a','b','c',2000))


def test_backup_preserves_profile_and_atomic_failure(tmp_path):
    source=VaultStore(str(tmp_path/'s.db'));header,dek,_=create_vault_header('MasterPass#fixture123')
    source.save_header(header);source.save_profile(Profile('SecretName','Family','City',1998),dek)
    source.put_entry(Entry('one','site','','u','fixture'),dek)
    path=tmp_path/'backup.spvault';create_encrypted_backup(source,str(path))
    target=VaultStore(str(tmp_path/'t.db'))
    restore_encrypted_backup(str(path),target,master_password='MasterPass#fixture123')
    assert target.get_profile(dek).first_name=='SecretName'
    data=json.loads(path.read_text());data['records'][0]['ct']='00'*16;path.write_text(json.dumps(data))
    with pytest.raises(AuthError):restore_encrypted_backup(str(path),target,master_password='MasterPass#fixture123')
    assert target.get_entry('one',dek).password=='fixture'


def test_lock_clears_plaintext_and_widgets():
    state={'_cav_dek':bytearray(generate_dek()),'_cav_unlocked':True,'cand_pw_input':'secret','_pending_entry_data':{'password':'secret'},'_cached_audit_report':object()}
    SessionManager.lock_vault(state)
    assert 'cand_pw_input' not in state and '_pending_entry_data' not in state
    assert '_cached_audit_report' not in state


def test_malformed_breach_response_is_unknown(monkeypatch):
    import requests
    response=requests.Response();response.status_code=200;response._content=b'<html>unavailable</html>'
    monkeypatch.setattr(requests,'get',lambda *a,**k:response)
    assert check_hibp_status('fixture')[0]==BreachStatus.UNKNOWN


def test_study_no_password_or_verifier(tmp_path):
    path=tmp_path/'events.csv'
    log_study_event('P1','G4','T1','DoNotLogThisSecret',True,False,True,100,str(path),vulnerable=False)
    text=path.read_text()
    assert 'DoNotLogThisSecret' not in text and 'hash' not in text
    assert 'vulnerable' in text and 'demo' in text


def test_split_leakage_rejected():
    from scripts.review_experiments import synthetic_rows, validate_rows
    rows=synthetic_rows(9)
    validate_rows(rows)
    rows[-1]['password']=rows[0]['password']
    with pytest.raises(ValueError,match='leaks'):validate_rows(rows)


def test_attack_prefixes_nested_and_no_target_input():
    from vault.research import guesses
    profile=dict(first_name='Maya',surname='Carter',city='Denver',birth_year=1998)
    for scenario in ('S1','S2','S3','S4','S5'):
        small=list(guesses(profile,'Summer2024!',scenario,100))
        large=list(guesses(profile,'Summer2024!',scenario,1000))
        assert len(small)==100 and small==large[:100] and len(set(large))==1000
