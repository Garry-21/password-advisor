import pytest
from modules.semantic import reverse_leet_translation, calculate_thematic_coverage

def test_reverse_leet_translation():
    assert reverse_leet_translation("p@$$w0rd") == "password"
    assert reverse_leet_translation("c@rt3r") == "carter"
    assert reverse_leet_translation("d3nv3r") == "denver"
    assert reverse_leet_translation("NormalText") == "normaltext"

def test_calculate_thematic_coverage_empty():
    assert calculate_thematic_coverage("", {}) == {"score": 0.0, "matched_fields": []}
    assert calculate_thematic_coverage("password", {}) == {"score": 0.0, "matched_fields": []}
    assert calculate_thematic_coverage("", {"first_name": "Maya"}) == {"score": 0.0, "matched_fields": []}

def test_calculate_thematic_coverage_direct_match():
    metadata = {
        "first_name": "Maya",
        "surname": "Carter",
        "city": "Denver",
        "birth_year": 1998
    }
    # Direct match on name and birth year
    res = calculate_thematic_coverage("Maya1998!", metadata)
    assert res["score"] > 0.5
    assert "name" in res["matched_fields"]
    assert "birth year" in res["matched_fields"]

def test_calculate_thematic_coverage_leet_match():
    metadata = {
        "first_name": "Maya",
        "surname": "Carter",
        "city": "Denver",
        "birth_year": 1998
    }
    # Leet match on M@y@
    res = calculate_thematic_coverage("M@y@Carter98", metadata)
    assert "name" in res["matched_fields"]
    assert "surname" in res["matched_fields"]
    assert "birth year" in res["matched_fields"]
    assert res["score"] >= 0.3

def test_calculate_thematic_coverage_no_match():
    metadata = {
        "first_name": "Maya",
        "surname": "Carter",
        "city": "Denver",
        "birth_year": 1998
    }
    res = calculate_thematic_coverage("Xk9#pL!qZ11", metadata)
    assert res["score"] == 0.0
    assert len(res["matched_fields"]) == 0
