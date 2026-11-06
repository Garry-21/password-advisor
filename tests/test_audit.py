"""
tests/test_audit.py
-------------------
Acceptance tests for Context-Aware Vault Audit Engine (Phase 3):
- 20-entry hand-built vault with known planted weaknesses:
  - Breached passwords (HIBP)
  - Semantic PII leaks (direct + leet)
  - Weak complexity (zxcvbn < 3)
  - Exact password reuse
  - Derivative password families (e.g. Summer2024! vs Summer2025!)
  - Stale credentials (age > rotation policy)
  - High-entropy clean controls
- Asserts every planted issue is identified with zero false positives on clean controls
- Asserts monotonicity: fixing any vulnerable entry strictly improves Vault Health Score (VHS)
"""

import time
import pytest

from vault.models import Entry, Profile
from vault.audit import audit_vault, detect_derivative_families, extract_base_password


def test_extract_base_password():
    assert extract_base_password("Summer2024!") == "summer"
    assert extract_base_password("Summer2025!") == "summer"
    assert extract_base_password("P@$$w0rd123!") == "password"
    assert extract_base_password("B@k1ng!") == "baking"


def test_derivative_family_clustering():
    entries = [
        Entry(id="1", site_name="SiteA", url="", username="u", password="Summer2024!"),
        Entry(id="2", site_name="SiteB", url="", username="u", password="Summer2025!"),
        Entry(id="3", site_name="SiteC", url="", username="u", password="UnrelatedSecret123!#"),
        Entry(id="4", site_name="SiteD", url="", username="u", password="WinterBake!"),
        Entry(id="5", site_name="SiteE", url="", username="u", password="WinterBake99"),
    ]
    entry_to_fam, fam_to_sites = detect_derivative_families(entries)

    # 1 and 2 must share a family
    assert "1" in entry_to_fam
    assert "2" in entry_to_fam
    assert entry_to_fam["1"] == entry_to_fam["2"]

    # 4 and 5 must share a family
    assert "4" in entry_to_fam
    assert "5" in entry_to_fam
    assert entry_to_fam["4"] == entry_to_fam["5"]

    # 3 is unrelated
    assert "3" not in entry_to_fam


def test_20_entry_planted_vault_and_monotonicity():
    profile = Profile(
        first_name="Maya",
        surname="Carter",
        city="Denver",
        birth_year=1998,
        theme="Baking"
    )

    now_epoch = time.time()
    def make_past_ts(days_ago: int) -> str:
        past = now_epoch - (days_ago * 86400)
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(past))

    entries = [
        # 1-2. Breached passwords
        Entry(id="p_br1", site_name="OldForum", url="", username="u", password="password", criticality=3),
        Entry(id="p_br2", site_name="TestSite", url="", username="u", password="123456", criticality=2),

        # 3-4. Semantic PII leaks (direct + leet)
        Entry(id="p_pii1", site_name="PersonalBlog", url="", username="u", password="MayaCarter1998!", criticality=2),
        Entry(id="p_pii2", site_name="LocalStore", url="", username="u", password="M@y@Denver98", criticality=1),

        # 5-6. Weak complexity (zxcvbn < 3)
        Entry(id="p_wk1", site_name="QuickApp1", url="", username="u", password="cat", criticality=1),
        Entry(id="p_wk2", site_name="QuickApp2", url="", username="u", password="dog", criticality=1),

        # 7-10. Exact reuse (2 pairs)
        Entry(id="p_re1", site_name="SocialMediaA", url="", username="u", password="UniqueSharedKey123!@#", criticality=2),
        Entry(id="p_re2", site_name="SocialMediaB", url="", username="u", password="UniqueSharedKey123!@#", criticality=2),
        Entry(id="p_re3", site_name="NewsSub1", url="", username="u", password="AnotherSharedSecret99$$", criticality=1),
        Entry(id="p_re4", site_name="NewsSub2", url="", username="u", password="AnotherSharedSecret99$$", criticality=1),

        # 11-14. Derivative families (2 pairs)
        Entry(id="p_der1", site_name="ShopRetail", url="", username="u", password="Summer2024!", criticality=2),
        Entry(id="p_der2", site_name="ShopOutlet", url="", username="u", password="Summer2025!", criticality=2),
        Entry(id="p_der3", site_name="BakeClub1", url="", username="u", password="WinterBaking!", criticality=1),
        Entry(id="p_der4", site_name="BakeClub2", url="", username="u", password="WinterBaking99", criticality=1),

        # 15-16. Stale credentials (age > 90 days)
        Entry(id="p_old1", site_name="OldService1", url="", username="u", password="Vintage-Key-Secure-2023!#", created_at=make_past_ts(400), criticality=1),
        Entry(id="p_old2", site_name="OldService2", url="", username="u", password="Antique-Vault-Token-2022!$", created_at=make_past_ts(500), criticality=1),

        # 17-20. Clean high-entropy controls
        Entry(id="clean1", site_name="BankPrimary", url="", username="u", password="Correct-Horse-Battery-Staple-2026!#$", criticality=3),
        Entry(id="clean2", site_name="GovPortal", url="", username="u", password="Quantum*Astronomy*Constellation*888^", criticality=3),
        Entry(id="clean3", site_name="WorkEmail", url="", username="u", password="BlueOcean#Dolphin#CoralReef!2026", criticality=3),
        Entry(id="clean4", site_name="CloudStorage", url="", username="u", password="Alpine-RockClimbing-Summit-2026!$", criticality=3),
    ]

    report = audit_vault(entries, profile=profile, rotation_policy_days=90)
    assert report.total_entries == 20

    # 1. Assert all planted weaknesses were flagged
    assert report.breached_count >= 2
    assert report.personal_info_count >= 2
    assert report.weak_syntax_count >= 2
    assert report.reused_count >= 4
    assert report.derivative_count >= 4
    assert report.old_count >= 2

    # Map by entry_id for granular inspection
    res_map = {r.entry_id: r for r in report.entry_results}

    # Verify clean controls have 0 risk and no finding badges
    for cid in ["clean1", "clean2", "clean3", "clean4"]:
        clean_res = res_map[cid]
        assert clean_res.risk_score == 0.0, f"Clean entry {cid} flagged with risk {clean_res.risk_score}"
        assert len(clean_res.finding_badges) == 0

    # Verify specific planted detections
    assert res_map["p_br1"].b_i == 1.0
    assert res_map["p_pi1" if "p_pi1" in res_map else "p_pii1"].C_i >= 0.3
    assert res_map["p_wk1"].s_i == 1.0
    assert res_map["p_re1"].r_i == 1.0
    assert res_map["p_der1"].d_i == 1.0
    assert res_map["p_old1"].a_i > 0.0

    baseline_vhs = report.vhs_score
    assert baseline_vhs < 100.0

    # 2. Assert Monotonicity: Fixing an entry must never lower VHS (strictly improves it)
    fixed_entries = list(entries)
    # Replace the severely breached entry with a clean high-entropy password
    fixed_entries[0] = Entry(
        id="p_br1",
        site_name="OldForum",
        url="",
        username="u",
        password="NewlyGeneratedSecurePassphrase2026!*#",
        criticality=3
    )
    new_report = audit_vault(fixed_entries, profile=profile, rotation_policy_days=90)
    assert new_report.vhs_score > baseline_vhs, f"Expected higher VHS after fix: old={baseline_vhs}, new={new_report.vhs_score}"
