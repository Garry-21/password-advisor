import pytest
from modules.semantic import calculate_thematic_coverage, reverse_leet_translation

PROFILE = {
    "first_name": "Alexander",
    "surname": "Hamilton",
    "city": "Albany",
    "birth_year": 1995
}

def test_reverse_leet_translation():
    assert reverse_leet_translation("4l3x") == "alex"
    assert reverse_leet_translation("h@m1lt0n") == "hamilton"
    assert reverse_leet_translation("p@$$w0rd") == "password"


def test_partial_attribute_matching():
    # First 4 chars of Alexander -> "Alex"
    res1 = calculate_thematic_coverage("Alex95!", PROFILE)
    assert res1["score"] >= 0.30
    assert "name" in res1["matched_fields"]

    # First 4 chars of Hamilton -> "Hami"
    res2 = calculate_thematic_coverage("Hami95#Denver", PROFILE)
    assert "surname" in res2["matched_fields"]


def test_reordered_and_multi_attributes():
    # Reordered: Surname + City + Year
    res = calculate_thematic_coverage("HamiltonAlbany95!", PROFILE)
    assert res["score"] >= 0.70
    assert "surname" in res["matched_fields"]
    assert "hometown" in res["matched_fields"]
    assert "birth year" in res["matched_fields"]
    assert "multi_attribute" in res["matched_fields"]


def test_leetspeak_and_separator_normalization():
    # Separator: dash and underscore, leetspeak
    res = calculate_thematic_coverage("4l3x-4lb4ny_1995!", PROFILE)
    assert res["score"] >= 0.50
    assert "name" in res["matched_fields"]
    assert "hometown" in res["matched_fields"]


def test_hard_negatives_do_not_flag():
    # Random words/fragments that should NOT falsely flag
    hard_negatives = [
        "quantum-nebula-voyager-42",
        "BakingFreshBreadInTheOven!",
        "DragonFlyFlyingOverThePond99$",
        "BlueberryPancakesMorning2024!",
        "StarlitSkyDancingGalaxies#",
        "redcatdogsunskycarsea"
    ]
    for pw in hard_negatives:
        res = calculate_thematic_coverage(pw, PROFILE)
        assert res["score"] < 0.30, f"False positive on hard-negative '{pw}' (score={res['score']}, fields={res['matched_fields']})"

