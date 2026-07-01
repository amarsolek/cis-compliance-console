"""
Weekly report email delivery.

Same simulator/real seam as the rest of the app: without SMTP_HOST /
SMTP_USERNAME / SMTP_PASSWORD / EMAIL_DISTRIBUTION_LIST set, the email is
rendered and logged in-memory instead of actually sent, so the weekly
report pipeline is demonstrable without a real mail server or a live
distribution list. Set the SMTP_* and EMAIL_* env vars (see README) to
send for real.
"""

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

_SENT_LOG: list = []


class EmailDeliveryError(Exception):
    pass


def _smtp_configured() -> bool:
    return all(os.environ.get(v) for v in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"))


def _distribution_list() -> list:
    raw = os.environ.get("EMAIL_DISTRIBUTION_LIST", "")
    return [a.strip() for a in raw.split(",") if a.strip()]


def send_weekly_report(report: dict, html_body: str, text_body: str, recipients=None) -> dict:
    """
    Send (or simulate sending) the weekly remediation report email.
    Returns a delivery record: {subject, to, sent_at, mode}, where mode is
    one of "smtp" (really sent), "simulated" (SMTP not configured), or
    "skipped_no_recipients".
    """
    to = recipients if recipients is not None else _distribution_list()
    subject = (f"CIS v8 Weekly Remediation Report -- {report['total_actions']} action(s) -- "
               f"{datetime.now(timezone.utc).date().isoformat()}")
    record = {
        "subject": subject,
        "to": to,
        "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": "smtp" if _smtp_configured() else "simulated",
    }

    if not to:
        record["mode"] = "skipped_no_recipients"
        _SENT_LOG.append(record)
        return record

    if not _smtp_configured():
        _SENT_LOG.append(record)
        return record

    sender = os.environ.get("EMAIL_FROM", "cis-compliance-console@localhost")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"

    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            if use_tls:
                server.starttls(context=ssl.create_default_context())
            server.login(username, password)
            server.sendmail(sender, to, msg.as_string())
    except (smtplib.SMTPException, OSError) as e:
        raise EmailDeliveryError(f"Failed to send weekly report email: {e}") from e

    _SENT_LOG.append(record)
    return record


def is_configured() -> bool:
    """Public accessor for whether real SMTP delivery is configured."""
    return _smtp_configured()


def distribution_list() -> list:
    """Public accessor for the configured weekly-report recipient list."""
    return _distribution_list()


def get_sent_log() -> list:
    return list(_SENT_LOG)


def reset():
    """Testing/demo helper."""
    _SENT_LOG.clear()
