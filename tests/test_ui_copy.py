import pytest
from modules.ui_copy import build_nudge

def test_build_nudge_empty():
    assert build_nudge("A", []) == ""
    assert build_nudge("B", []) == ""

def test_build_nudge_variant_a_loss_framed():
    findings = [
        {"type": "breach", "n": 42},
        {"type": "semantic", "detail": "your birth year"},
        {"type": "syntax"}
    ]
    nudge = build_nudge("A", findings)
    assert "42 known data breaches" in nudge
    assert "attackers use these lists first" in nudge
    assert "anyone who knows you" in nudge
    assert "automated cracking tools could break it in minutes" in nudge

def test_build_nudge_variant_b_neutral():
    findings = [
        {"type": "breach", "n": 42},
        {"type": "semantic", "detail": "your birth year"},
        {"type": "syntax"}
    ]
    nudge = build_nudge("B", findings)
    assert "This password appears in 42 known data breaches." in nudge
    assert "This password contains your birth year." in nudge
    assert "This password does not meet the recommended complexity level." in nudge

def test_build_nudge_unknown_type_ignored():
    findings = [
        {"type": "unknown_future_signal"},
        {"type": "syntax"}
    ]
    nudge = build_nudge("B", findings)
    assert "This password does not meet the recommended complexity level." in nudge

def test_build_nudge_flexible_calling():
    findings = [{"type": "breach", "n": 5}]
    # Keyword arguments
    assert "5 known data breaches" in build_nudge(variant="A", findings=findings)
    # Reversed positional / keyword
    assert "5 known data breaches" in build_nudge(findings, variant="A")
