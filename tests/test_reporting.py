"""
Tests for weekly report aggregation and chart data (app/reporting.py).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import device_client, remediation, reporting
from app.checks.cis_v8_rules import run_all_checks


def _remediate(host, name):
    config = device_client.fetch_running_config(host)
    failed = [r.__dict__ for r in run_all_checks(config) if not r.passed]
    return remediation.remediate_device(host, name, config, failed)


def test_weekly_report_aggregates_by_host():
    _remediate("10.1.1.11", "sw-legacy-01")
    _remediate("10.1.1.13", "sw-partial-03")

    report = reporting.weekly_report(days=7)
    assert report["total_actions"] > 0
    assert len(report["devices"]) == 2
    hosts = {d["host"] for d in report["devices"]}
    assert hosts == {"10.1.1.11", "10.1.1.13"}
    for d in report["devices"]:
        assert d["auto_applied"] + d["manual_pending"] == len(d["controls_fixed"]) + len(d["controls_pending"])


def test_weekly_report_empty_window_has_zero_actions():
    report = reporting.weekly_report(days=7)
    assert report["total_actions"] == 0
    assert report["devices"] == []


def test_remediation_trend_labels_span_requested_days():
    trend = reporting.remediation_trend(days=14)
    assert len(trend["labels"]) == 14
    assert len(trend["auto_applied"]) == 14
    assert len(trend["manual_pending"]) == 14


def test_remediation_trend_reflects_todays_activity():
    _remediate("10.1.1.11", "sw-legacy-01")
    trend = reporting.remediation_trend(days=7)
    assert sum(trend["auto_applied"]) > 0


def test_status_breakdown_matches_log_counts():
    _remediate("10.1.1.11", "sw-legacy-01")
    breakdown = reporting.remediation_status_breakdown()
    log = remediation.get_remediation_log()
    assert sum(breakdown.values()) == len(log)


def test_render_email_body_contains_device_names():
    _remediate("10.1.1.11", "sw-legacy-01")
    report = reporting.weekly_report(days=7)
    html, text = reporting.render_email_body(report)
    assert "sw-legacy-01" in html
    assert "sw-legacy-01" in text
