import os
import json
import pytest
from vault.models import Entry
from vault.audit import (
    AuditConfig,
    audit_vault,
    detect_derivative_families,
    calculate_calibrated_risk
)

def test_age_off_by_default():
    # Passwords older than 90 days should have a_i = 0.0 when enable_age_score is False
    old_entry = Entry(
        id="old-1",
        site_name="LegacyBank",
        url="https://bank.com",
        username="user1",
        password="ValidPassword#2020!",
        created_at="2020-01-01T00:00:00Z",
        modified_at="2020-01-01T00:00:00Z"
    )

    # 1. Default config: age off
    cfg_default = AuditConfig(enable_age_score=False)
    rep1 = audit_vault([old_entry], config=cfg_default)
    res1 = rep1.entry_results[0]
    assert res1.a_i == 0.0
    assert rep1.old_count == 0

    # 2. Config with age enabled
    cfg_age = AuditConfig(enable_age_score=True, weights={"breach": 0.35, "semantic": 0.25, "syntax": 0.15, "reuse": 0.10, "derivative": 0.05, "age": 0.10})
    rep2 = audit_vault([old_entry], config=cfg_age)
    res2 = rep2.entry_results[0]
    assert res2.a_i > 0.0
    assert rep2.old_count == 1


def test_correlated_signals_cap():
    # Entry with high semantic coverage, reuse, and derivative
    e1 = Entry(id="e1", site_name="SiteA", url="https://a.com", username="u1", password="Alexander1995Unique#$99")
    e2 = Entry(id="e2", site_name="SiteB", url="https://b.com", username="u1", password="Alexander1995Unique#$99")

    from vault.models import Profile
    profile = Profile(first_name="Alexander", surname="Hamilton", city="Albany", birth_year=1995, theme="scifi")

    # Max correlated cap = 0.20
    cfg = AuditConfig(max_correlated_contribution=0.20, weights={"breach": 0.40, "semantic": 0.30, "syntax": 0.15, "reuse": 0.25, "derivative": 0.15, "age": 0.00})
    rep = audit_vault([e1, e2], profile=profile, config=cfg)
    
    # Both semantic (0.30) + reuse (0.25) would sum to 0.55 without cap, but should be bounded by 0.20
    for res in rep.entry_results:
        # Correlated portion is capped at 0.20. Even with syntax (0.15), risk <= 0.35
        assert res.risk_score <= 0.35


def test_calibrated_logistic_scorer(tmp_path):
    model_path = str(tmp_path / "test_model.json")
    model_data = {
        "intercept": -1.5,
        "coefficients": {
            "breach": 2.5,
            "semantic": 1.8,
            "syntax": 1.2,
            "reuse": 1.0,
            "derivative": 0.8,
            "age": 0.2
        }
    }
    with open(model_path, "w", encoding="utf-8") as f:
        json.dump(model_data, f)

    features = {"breach": 1.0, "semantic": 0.5, "syntax": 1.0, "reuse": 0.0, "derivative": 0.0, "age": 0.0}
    risk = calculate_calibrated_risk(features, model_data)
    # z = -1.5 + 2.5 + 0.9 + 1.2 = 3.1 -> sigmoid(3.1) ~ 0.957
    assert 0.90 < risk < 0.98

    # Integration with audit_vault
    cfg = AuditConfig(calibrated_model_path=model_path)
    entry = Entry(id="t1", site_name="Test", url="https://test.com", username="u", password="password")
    rep = audit_vault([entry], config=cfg)
    assert 0.0 <= rep.entry_results[0].risk_score <= 1.0


def test_derivative_clustering_pairwise_vs_chain():
    p1 = Entry(id="1", site_name="Site1", url="https://1.com", username="u", password="Passcode1AA!")
    p2 = Entry(id="2", site_name="Site2", url="https://2.com", username="u", password="Passcode1AB!")
    p3 = Entry(id="3", site_name="Site3", url="https://3.com", username="u", password="Passcode2CB!")

    entries = [p1, p2, p3]

    # In 'chain' mode: P1~P2 and P2~P3 forms one connected component {1, 2, 3}
    fam_chain, members_chain = detect_derivative_families(entries, cluster_mode="chain")
    assert len(members_chain) == 1
    assert set(members_chain[1]) == {"Site1", "Site2", "Site3"}

    # In 'pairwise' mode: P1!~P3 (dist=3), so P1, P2, P3 cannot form a mutual 3-clique
    fam_pairwise, members_pairwise = detect_derivative_families(entries, cluster_mode="pairwise")
    assert len(members_pairwise) == 1
    # Only a 2-element clique (P1 & P2, or P2 & P3) is formed, not all 3 together
    assert len(list(members_pairwise.values())[0]) == 2
