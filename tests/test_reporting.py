"""
Tests for app/reporting.py -- the weekly report aggregation and the
dashboard chart data feeds.
"""

from app import device_client, remediation, reporting
from app.checks.cis_v8_rules import run_all_checks

HOST = "10.1.1.11"
NAME = "sw-legacy-01"


def _remediate_fixture_device():
    config = device_client.fetch_running_config(HOST)
    failed = [r.__dict__ for r in run_all_checks(config) if not r.passed]
    return remediation.remediate_device(HOST, NAME, config, failed)


def test_weekly_report_aggregates_by_host():
    _remediate_fixture_device()
    report = reporting.weekly_report(days=7)

    assert report["total_actions"] > 0
    assert report["devices"], "expected at least one device rollup"
    dev = next(d for d in report["devices"] if d["host"] == HOST)
    assert dev["name"] == NAME
    assert dev["auto_applied"] + dev["manual_pending"] > 0


def test_weekly_report_empty_window_has_no_devices():
    report = reporting.weekly_report(days=7)
    assert report["total_actions"] == 0
    assert report["devices"] == []


def test_remediation_trend_reflects_todays_activity():
    _remediate_fixture_device()
    trend = reporting.remediation_trend(days=30)

    assert len(trend["labels"]) == 30
    assert sum(trend["auto_applied"]) + sum(trend["manual_pending"]) > 0
    # Today (last label) should carry at least some of the activity we just
    # generated, since remediate_device() timestamps "now".
    assert trend["auto_applied"][-1] + trend["manual_pending"][-1] > 0


def test_remediation_status_breakdown_counts_all_actions():
    _remediate_fixture_device()
    breakdown = reporting.remediation_status_breakdown()

    assert set(breakdown.keys()) >= {"auto_applied", "manual_pending", "attempt_failed"}
    total = sum(breakdown.values())
    assert total == len(remediation.get_remediation_log())


def test_render_email_body_produces_html_and_text():
    _remediate_fixture_device()
    report = reporting.weekly_report(days=7)
    html, text = reporting.render_email_body(report)

    assert "<html>" in html
    assert NAME in html
    assert "CIS v8 Weekly Remediation Report" in text
    assert NAME in text


def test_render_email_body_handles_empty_report():
    report = reporting.weekly_report(days=7)
    html, text = reporting.render_email_body(report)
    assert "No remediation activity" in html
    assert "No remediation activity" in text
