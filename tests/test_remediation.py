"""
Tests for the auto-remediation fix engine and orchestration.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import device_client, remediation, servicenow_client
from app.checks.cis_v8_rules import run_all_checks
from app.checks.cis_v8_fixes import FIXES, AUTO_REMEDIABLE, MANUAL_REVIEW_REASON

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "simulator", "sample_configs")


def _load(filename):
    with open(os.path.join(SAMPLE_DIR, filename)) as f:
        return f.read()


def test_every_auto_remediable_control_has_a_fix_function():
    for control_id in AUTO_REMEDIABLE:
        assert control_id in FIXES


def test_manual_review_reasons_do_not_overlap_auto_remediable():
    assert set(MANUAL_REVIEW_REASON) & AUTO_REMEDIABLE == set()


def test_auto_fixes_resolve_the_hardened_baseline_cleanly():
    # The fully-hardened sample should already be clean; fixers should be
    # no-ops (or at worst leave it clean) on a config that's already correct.
    config = _load("sw-hardened-02.cfg")
    failed = [r for r in run_all_checks(config) if not r.passed]
    fixed = config
    for r in failed:
        fn = FIXES.get(r.control_id)
        if fn:
            fixed = fn(fixed)
    # No control that had a fix applied should still fail after.
    attempted = {r.control_id for r in failed if r.control_id in FIXES}
    new_results = {r.control_id: r for r in run_all_checks(fixed)}
    for cid in attempted:
        assert new_results[cid].passed, f"{cid} still fails after its own auto-fix on the hardened baseline"


def test_legacy_switch_auto_fix_resolves_most_findings():
    config = _load("sw-legacy-01.cfg")
    failed = [r for r in run_all_checks(config) if not r.passed]
    fixed = config
    attempted = []
    for r in failed:
        fn = FIXES.get(r.control_id)
        if fn:
            fixed = fn(fixed)
            attempted.append(r.control_id)

    post = {r.control_id: r for r in run_all_checks(fixed)}
    resolved = [cid for cid in attempted if post[cid].passed]
    # Almost everything with a fix function should resolve; the one known
    # exception is CIS-4.2 on this sample (both local accounts are
    # default/weak and get removed by CIS-5.1, leaving zero local accounts,
    # which is itself a separate finding routed to manual review).
    assert len(resolved) >= len(attempted) - 1


def test_remediate_device_opens_service_now_tickets_and_logs_records():
    host, name = "10.1.1.11", "sw-legacy-01"
    config = device_client.fetch_running_config(host)
    failed = [r.__dict__ for r in run_all_checks(config) if not r.passed]

    out = remediation.remediate_device(host, name, config, failed)

    assert out["records"], "expected at least one remediation record"
    assert any(r["action"] == "auto_applied" for r in out["records"])
    assert any(r["action"] in ("manual_pending", "attempt_failed") for r in out["records"])
    assert len(servicenow_client.list_change_requests()) >= 2  # one auto batch + at least one manual

    # The device's live config should now score better than before.
    new_failed = [r for r in run_all_checks(out["new_config"]) if not r.passed]
    assert len(new_failed) < len(failed)


def test_remediate_device_does_not_duplicate_manual_tickets_on_rescan():
    host, name = "10.1.1.11", "sw-legacy-01"
    config = device_client.fetch_running_config(host)
    failed = [r.__dict__ for r in run_all_checks(config) if not r.passed]
    remediation.remediate_device(host, name, config, failed)
    tickets_after_run1 = len(servicenow_client.list_change_requests())

    still_failing = [r.__dict__ for r in run_all_checks(device_client.fetch_running_config(host)) if not r.passed]
    remediation.remediate_device(host, name, device_client.fetch_running_config(host), still_failing)
    tickets_after_run2 = len(servicenow_client.list_change_requests())

    # At most one brand-new finding should surface as a side effect of the
    # first pass (e.g. enabling DHCP snooping exposes a DAI gap); it should
    # never re-file tickets for findings already open from run 1.
    assert tickets_after_run2 - tickets_after_run1 <= 1


def test_auto_applied_findings_only_reported_when_actually_passing():
    host, name = "10.1.1.13", "sw-partial-03"
    config = device_client.fetch_running_config(host)
    failed = [r.__dict__ for r in run_all_checks(config) if not r.passed]
    out = remediation.remediate_device(host, name, config, failed)

    post_results = {r.control_id: r.passed for r in run_all_checks(out["new_config"])}
    for r in out["records"]:
        if r["action"] == "auto_applied":
            assert post_results[r["control_id"]] is True
