import pytest
from quantum_mechanic.shell.ca_bypass_detectors import (
    run_all_detectors,
    detect_legacy_auth_allowed,
    detect_device_code_not_blocked,
    detect_foci_exclusion_blast,
    detect_grant_or_weakness
)

def test_detect_legacy_auth_allowed():
    policies = [{
        "display_name": "Legacy Allowed",
        "state": "enabled",
        "client_app_types": ["exchangeActiveSync"],
        "grant_controls": ["mfa"]
    }]
    findings = detect_legacy_auth_allowed(policies)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "Legacy Authentication Allowed" in findings[0].title

def test_detect_device_code_not_blocked():
    policies = [{
        "display_name": "MFA All",
        "state": "enabled",
        "auth_flows": "normal",
        "grant_controls": ["mfa"]
    }]
    findings = detect_device_code_not_blocked(policies)
    assert len(findings) == 1
    assert "Device Code Flow Not Blocked" in findings[0].title

def test_detect_grant_or_weakness():
    policies = [{
        "display_name": "Weak OR",
        "state": "enabled",
        "grant_operator": "OR",
        "grant_controls": ["mfa", "compliantDevice"]
    }]
    findings = detect_grant_or_weakness(policies)
    assert len(findings) == 1
    assert "Vulnerable 'OR' Grant Operator" in findings[0].title

def test_run_all_detectors():
    policies = [{
        "display_name": "Weak OR",
        "state": "enabled",
        "grant_operator": "OR",
        "grant_controls": ["mfa", "compliantDevice"],
        "client_app_types": ["browser"]
    }]
    findings = run_all_detectors(policies)
    assert len(findings) > 0 # At least OR weakness + device code not blocked + no token protection etc
