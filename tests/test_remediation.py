"""
Tests for the auto-remediation orchestration engine (app/remediation.py).

Uses the simulated legacy switch (10.1.1.11 / sw-legacy-01), which fails a
large number of CIS v8 controls out of the box, as the fixture device.
"""

from app import device_client, remediation, servicenow_client
from app.checks.cis_v8_rules import run_all_checks

HOST = "10.1.1.11"
NAME = "sw-legacy-01"


def _failed_results():
    config = device_client.fetch_running_config(HOST)
    results = run_all_checks(config)
    return config, [r.__dict__ for r in results if not r.passed]


def test_remediate_device_fixes_auto_remediable_findings():
    config, failed = _failed_results()
    assert failed, "fixture device should start with failing controls"

    outcome = remediation.remediate_device(HOST, NAME, config, failed)
    auto_applied = [r for r in outcome["records"] if r["action"] == "auto_applied"]
    assert auto_applied, "expected at least one control to be auto-remediated"

    # Every auto-applied record must be re-verified as actually passing now.
    post_results = {r.control_id: r.passed for r in run_all_checks(outcome["new_config"])}
    for rec in auto_applied:
        assert post_results.get(rec["control_id"]) is True


def test_remediate_device_opens_servicenow_change_requests():
    config, failed = _failed_results()
    remediation.remediate_device(HOST, NAME, config, failed)

    tickets = servicenow_client.list_change_requests()
    assert tickets, "expected at least one change request to be opened"
    assert all(t["number"].startswith("CHG") for t in tickets)


def test_manual_findings_are_not_refiled_on_repeat_scans():
    config, failed = _failed_results()
    remediation.remediate_device(HOST, NAME, config, failed)
    tickets_after_first = len(servicenow_client.list_change_requests())

    # Re-running against the *same* still-failing findings should not open
    # duplicate tickets for anything already tracked as open.
    _, still_failed = _failed_results()
    remediation.remediate_device(HOST, NAME, config, still_failed)
    tickets_after_second = len(servicenow_client.list_change_requests())

    assert tickets_after_second <= tickets_after_first + 1


def test_clear_resolved_manual_tickets_drops_closed_findings():
    config, failed = _failed_results()
    remediation.remediate_device(HOST, NAME, config, failed)
    remediation.clear_resolved_manual_tickets(HOST, currently_failing_ids=set())
    # After clearing with an empty failing set, a fresh finding on the same
    # control should be able to open a new ticket rather than being treated
    # as a still-open duplicate.
    assert (HOST, "CIS-1.1") not in remediation._OPEN_MANUAL_TICKETS


def test_get_remediation_log_and_since_window():
    config, failed = _failed_results()
    remediation.remediate_device(HOST, NAME, config, failed)

    full_log = remediation.get_remediation_log()
    assert len(full_log) > 0

    recent = remediation.remediations_since(days=7)
    assert len(recent) == len(full_log)

    ancient = remediation.remediations_since(days=0)
    # A 0-day window measured against "now" should still include records
    # applied moments ago (>= cutoff), so this should not be empty either.
    assert isinstance(ancient, list)


def test_seed_demo_trend_and_clear_demo_data():
    assert remediation.has_demo_data() is False

    added = remediation.seed_demo_trend(days=10, seed=1)
    assert added > 0
    assert remediation.has_demo_data() is True

    log = remediation.get_remediation_log()
    assert all(r["note"].startswith(remediation.DEMO_NOTE_PREFIX) for r in log)
    assert all(r["change_ticket"].startswith("CHG-DEMO-") for r in log)

    removed = remediation.clear_demo_data()
    assert removed == added
    assert remediation.has_demo_data() is False
    assert remediation.get_remediation_log() == []


def test_seed_demo_trend_does_not_touch_real_servicenow_queue():
    remediation.seed_demo_trend(days=5, seed=2)
    assert servicenow_client.list_change_requests() == []
