"""
Unit tests for the CIS v8 rule engine and scoring logic.
Run with: pytest tests/
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.checks.cis_v8_rules import run_all_checks, control_count, RULES
from app.scoring import score_device

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "simulator", "sample_configs")


def _load(filename):
    with open(os.path.join(SAMPLE_DIR, filename)) as f:
        return f.read()


def test_control_count_is_25_plus():
    assert control_count() >= 25, "Prototype scope requires 25+ CIS v8 controls"


def test_all_rules_have_unique_ids():
    ids = [r.control_id for r in RULES]
    assert len(ids) == len(set(ids)), "Duplicate control_id found"


def test_legacy_switch_fails_most_controls():
    config = _load("sw-legacy-01.cfg")
    results = run_all_checks(config)
    failed = [r for r in results if not r.passed]
    assert len(failed) >= 20, "Legacy sample should fail the large majority of controls"


def test_hardened_switch_passes_most_controls():
    config = _load("sw-hardened-02.cfg")
    results = run_all_checks(config)
    passed = [r for r in results if r.passed]
    assert len(passed) >= 28, "Hardened sample should pass nearly all controls"


def test_telnet_detection_catches_transport_all():
    config = _load("sw-legacy-01.cfg")
    results = run_all_checks(config)
    telnet_check = next(r for r in results if r.control_id == "CIS-4.3")
    assert telnet_check.passed is False


def test_telnet_detection_passes_when_ssh_only():
    config = _load("sw-hardened-02.cfg")
    results = run_all_checks(config)
    telnet_check = next(r for r in results if r.control_id == "CIS-4.3")
    assert telnet_check.passed is True


def test_default_snmp_community_detected():
    config = _load("sw-legacy-01.cfg")
    results = run_all_checks(config)
    snmp_check = next(r for r in results if r.control_id == "CIS-4.8")
    assert snmp_check.passed is False
    assert "public" in snmp_check.evidence or "private" in snmp_check.evidence


def test_scoring_weighted_score_between_0_and_100():
    for fname in ("sw-legacy-01.cfg", "sw-hardened-02.cfg", "sw-partial-03.cfg"):
        config = _load(fname)
        report = score_device("1.2.3.4", fname, "test-site", config)
        assert 0 <= report.weighted_score_pct <= 100
        assert report.total_controls == control_count()
        assert report.passed + report.failed == report.total_controls


def test_hardened_scores_higher_than_legacy():
    legacy = score_device("1.1.1.1", "legacy", "site", _load("sw-legacy-01.cfg"))
    hardened = score_device("1.1.1.2", "hardened", "site", _load("sw-hardened-02.cfg"))
    assert hardened.weighted_score_pct > legacy.weighted_score_pct


def test_every_failed_high_severity_control_has_remediation():
    config = _load("sw-legacy-01.cfg")
    results = run_all_checks(config)
    for r in results:
        if not r.passed and r.severity == "high":
            assert r.remediation, f"{r.control_id} is a failed high-severity control with no remediation text"
