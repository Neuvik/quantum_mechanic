"""Tests for the CA-policy CIDR-comma parsing bug fix (B3).

The bug: named location strings like
    "SOC Secure Browser IPs (54.211.72.106/32, 13.251.2.79/32)"
were being split on commas inside the parentheses, producing three
bogus entries instead of one.

The fix: the technique now emits a structured `_list` field alongside
the joined string. `get_list_from_policy()` prefers the structured field
so multi-CIDR entries survive intact.
"""
from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
    get_list,
    get_list_from_policy,
)


def test_get_list_still_splits_plain_comma_string():
    """OUTCOME: Legacy string path still splits on comma — unchanged."""
    out = get_list("a, b, c")
    assert out == ["a", "b", "c"]


def test_get_list_from_policy_prefers_structured_list():
    """OUTCOME: When `<key>_list` is present, it wins over the joined string.

    ANTI-GAMIFICATION: this is the whole point of B3 — if someone reverts
    the `_list` preference, the multi-CIDR name gets split again.
    """
    policy = {
        "excluded_locations": "SOC IPs (10.0.0.1/32, 10.0.0.2/32), Corporate HQ",
        "excluded_locations_list": [
            "SOC IPs (10.0.0.1/32, 10.0.0.2/32)",
            "Corporate HQ",
        ],
    }
    out = get_list_from_policy(policy, "excluded_locations")
    assert out == ["SOC IPs (10.0.0.1/32, 10.0.0.2/32)", "Corporate HQ"], (
        f"Multi-CIDR entry must survive as ONE item, got: {out}"
    )


def test_get_list_from_policy_falls_back_when_no_list_field():
    """OUTCOME: When `_list` is absent, fall back to legacy string split.

    Backward compat: old evidence rows without `_list` still parse.
    """
    policy = {"excluded_locations": "Trusted Office, Home Network"}
    out = get_list_from_policy(policy, "excluded_locations")
    assert out == ["Trusted Office", "Home Network"]


def test_single_cidr_multi_entry_survives():
    """OUTCOME: A single-CIDR named location renders as one item too."""
    policy = {
        "excluded_locations": "One Loc (10.0.0.1/32)",
        "excluded_locations_list": ["One Loc (10.0.0.1/32)"],
    }
    out = get_list_from_policy(policy, "excluded_locations")
    assert out == ["One Loc (10.0.0.1/32)"]
    assert len(out) == 1
