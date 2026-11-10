"""Isolated fictional-task E4 feasibility interface; never accesses the real vault."""
import os
import time
import streamlit as st
from vault.models import Profile
from vault.study import assign_condition, log_study_event
from vault.gate import GateEvaluation
from vault.generator import generate_passphrase
from modules.syntactic import evaluate_syntactic_strength, BreachStatus
from modules.semantic import calculate_thematic_coverage
from vault.research import attack_rank, FEATURES, features

PROFILE = dict(first_name='Maya',surname='Carter',city='Denver',birth_year=1998)
PREVIOUS = 'Summer2024!'


def findings(password, condition):
    row=dict(password=password,profile=PROFILE,other_passwords=[PREVIOUS],breach_count=int(password in {'password123!','welcome123!'}))
    f=features(row)
    messages=[]
    if f[2]:messages.append('Low structural strength (zxcvbn score below 3).')
    if condition!='G1':
        for index,message in [(0,'Found in the fictional study blocklist.'),(1,'Contains personal-context patterns.'),(3,'Reuses the fictional previous password.'),(4,'Related to the fictional previous password.')]:
            if f[index]>0:messages.append(message)
    return messages


def render():
    st.title('Controlled fictional credential study')
    st.caption('Feasibility interface for G1–G4. No real account passwords. Outcomes use a limited offline attacker, not the warning rules.')
    human=os.environ.get('STUDY_MODE')=='1'
    if human and (not os.environ.get('STUDY_ETHICS_REFERENCE') or not os.environ.get('STUDY_SEED')):
        st.error('Human collection requires the institutional ethics reference and a prespecified allocation seed. Demo is available with STUDY_MODE unset.')
        st.stop()
    pid=st.text_input('Pseudonymous participant ID',key='study_participant')
    consent=st.checkbox('I consent to recording fictional-task decisions and will not enter real credentials.',key='study_consent')
    if not pid.strip() or not consent:st.stop()
    trial=st.session_state.get('study_trial',0)
    if trial>=3:
        st.success('Three fictional tasks completed. No real passwords were changed.')
        return
    condition=assign_condition(pid)
    st.write(f'Task {trial+1}: create a fictional credential for '+['a shop','an email service','a social account'][trial]+'.')
    st.info(f'Fictional profile: Maya Carter, Denver, 1998. Fictional previous password: {PREVIOUS}')
    st.session_state.setdefault('study_started',time.monotonic())
    pending=st.session_state.get('study_pending')
    if pending and (pending['pid']!=pid or pending['trial']!=trial):
        st.error('Finish the current participant task before changing the identifier.')
        st.stop()
    def finish(password,warning,override=False,adopt=False):
        vulnerable=attack_rank(password,PROFILE,PREVIOUS,'S5',1000) is not None
        log_study_event(pid,condition,f'T{trial+1}',password,warning,override,adopt,
                        (time.monotonic()-st.session_state.study_started)*1000,
                        vulnerable=vulnerable,source='human' if human else 'demo')
        for key in ('study_pending','study_started','study_password','study_saved','study_warned'):
            st.session_state.pop(key,None)
        st.session_state.study_trial=trial+1
        st.rerun()
    if not pending:
        with st.form('study_candidate'):
            password=st.text_input('Fictional password',type='password',key='study_password')
            submit=st.form_submit_button('Save fictional credential')
        if submit and password:
            reasons=findings(password,condition)
            if not reasons:
                finish(password,st.session_state.get('study_warned',False))
            st.session_state.study_warned=True
            st.session_state.study_pending=dict(password=password,reasons=reasons,pid=pid,trial=trial,
                                                 alternative=generate_passphrase(num_words=4).password if condition=='G4' else None)
            if condition=='G2':st.session_state.study_saved=password
            st.rerun()
    else:
        st.warning('Credential saved in the temporary study session. Review it before finishing.' if condition=='G2' else 'Review these findings before saving.')
        for reason in pending['reasons']:st.write(reason)
        if pending['alternative']:
            st.code(pending['alternative'])
            if st.button('Use suggested alternative'):
                finish(pending['alternative'],True,adopt=True)
        if st.button('Edit password'):
            st.session_state.pop('study_pending',None)
            st.rerun()
        if st.button('Keep saved credential' if condition=='G2' else 'Save anyway'):
            finish(pending['password'],True,override=True)

render()
