"""
Tests for the weekly-report email delivery seam (app/email_client.py).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import email_client, reporting


def _sample_report():
    return reporting.weekly_report(days=7)


def test_send_without_recipients_is_skipped():
    os.environ.pop("EMAIL_DISTRIBUTION_LIST", None)
    report = _sample_report()
    html, text = reporting.render_email_body(report)
    record = email_client.send_weekly_report(report, html, text)
    assert record["mode"] == "skipped_no_recipients"
    assert email_client.get_sent_log() == [record]


def test_send_without_smtp_config_is_simulated_but_logged():
    for var in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
        os.environ.pop(var, None)
    report = _sample_report()
    html, text = reporting.render_email_body(report)
    record = email_client.send_weekly_report(report, html, text, recipients=["netops@example.com"])
    assert record["mode"] == "simulated"
    assert record["to"] == ["netops@example.com"]
    assert not email_client.is_configured()


def test_distribution_list_parses_comma_separated_env_var():
    os.environ["EMAIL_DISTRIBUTION_LIST"] = "a@example.com, b@example.com,c@example.com"
    try:
        assert email_client.distribution_list() == ["a@example.com", "b@example.com", "c@example.com"]
    finally:
        os.environ.pop("EMAIL_DISTRIBUTION_LIST", None)
