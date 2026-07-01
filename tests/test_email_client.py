"""Tests for weekly report email delivery (app/email_client.py)."""

from app import email_client, reporting


def _sample_report():
    return reporting.weekly_report(days=7)


def test_send_with_no_recipients_is_skipped(monkeypatch):
    monkeypatch.delenv("EMAIL_DISTRIBUTION_LIST", raising=False)
    report = _sample_report()
    html, text = reporting.render_email_body(report)
    record = email_client.send_weekly_report(report, html, text)
    assert record["mode"] == "skipped_no_recipients"
    assert record["to"] == []


def test_send_without_smtp_configured_simulates(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    report = _sample_report()
    html, text = reporting.render_email_body(report)
    record = email_client.send_weekly_report(report, html, text, recipients=["netops@example.com"])
    assert record["mode"] == "simulated"
    assert record["to"] == ["netops@example.com"]
    assert record in email_client.get_sent_log()


def test_distribution_list_parses_comma_separated_env(monkeypatch):
    monkeypatch.setenv("EMAIL_DISTRIBUTION_LIST", "a@example.com, b@example.com,c@example.com")
    assert email_client.distribution_list() == ["a@example.com", "b@example.com", "c@example.com"]


def test_is_configured_reflects_smtp_env(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert email_client.is_configured() is False

    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "pass")
    assert email_client.is_configured() is True


def test_subject_includes_action_count():
    report = _sample_report()
    html, text = reporting.render_email_body(report)
    record = email_client.send_weekly_report(report, html, text, recipients=["netops@example.com"])
    assert str(report["total_actions"]) in record["subject"]
