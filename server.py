"""
CIS v8 Network Compliance Dashboard -- Flask application entrypoint.

Run with: python server.py   (see README for full instructions)
"""

import os
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import device_client, remediation, reporting, email_client, meraki_client
from app.scoring import score_device, error_device_report, fleet_summary
from app.checks.cis_v8_rules import RULES, control_count

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "static"),
)

# Simple in-memory cache of the last scan so the dashboard has data on first
# load without forcing a scan-on-every-request. A real deployment would swap
# this for a database / scheduled job (see README "Going to production").
_LAST_SCAN = {"reports": [], "summary": {}, "scanned_at": None}

# Auto-fix non-compliant configs immediately on every scan, opening a
# ServiceNow change request for the audit trail (and for anything that
# needs a human). Set AUTO_REMEDIATE=false to score-only, matching the
# tool's original read-only behavior.
AUTO_REMEDIATE = os.environ.get("AUTO_REMEDIATE", "true").lower() != "false"


def _run_full_scan():
    inventory = device_client.list_inventory()
    reports = []
    for device in inventory:
        host = device["host"]
        name = device.get("name", host)
        site = device.get("site", "unspecified")
        try:
            config_text = device_client.fetch_running_config(host)
            report = score_device(host, name, site, config_text)

            if AUTO_REMEDIATE and report.failed:
                failed_results = [r for r in report.results if not r["passed"]]
                remediation.remediate_device(host, name, config_text, failed_results)
                # Re-fetch + re-score so the dashboard reflects what's
                # actually true post-remediation, not the pre-fix scan.
                config_text = device_client.fetch_running_config(host)
                report = score_device(host, name, site, config_text)

            still_failing = {r["control_id"] for r in report.results if not r["passed"]}
            remediation.clear_resolved_manual_tickets(host, still_failing)
        except device_client.DeviceConnectionError as e:
            report = error_device_report(host, name, site, str(e))
        reports.append(report)

    summary = fleet_summary(reports)
    _LAST_SCAN["reports"] = [r.to_dict() for r in reports]
    _LAST_SCAN["summary"] = summary
    _LAST_SCAN["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return _LAST_SCAN


@app.route("/")
def dashboard():
    if not _LAST_SCAN["scanned_at"]:
        _run_full_scan()
    try:
        meraki_summary = meraki_client.compliance_summary()
    except meraki_client.MerakiAPIError as e:
        meraki_summary = {"error": str(e), "total": 0, "compliant": 0, "non_compliant": 0, "devices": []}

    return render_template(
        "dashboard.html",
        reports=_LAST_SCAN["reports"],
        summary=_LAST_SCAN["summary"],
        scanned_at=_LAST_SCAN["scanned_at"],
        total_controls=control_count(),
        simulator_mode=device_client.USE_SIMULATOR,
        auto_remediate=AUTO_REMEDIATE,
        remediation_breakdown=reporting.remediation_status_breakdown(),
        remediation_trend=reporting.remediation_trend(days=30),
        has_demo_data=remediation.has_demo_data(),
        meraki=meraki_summary,
        meraki_simulator_mode=meraki_client.USE_SIMULATOR,
    )


@app.route("/device/<host>")
def device_detail(host):
    if not _LAST_SCAN["scanned_at"]:
        _run_full_scan()
    report = next((r for r in _LAST_SCAN["reports"] if r["host"] == host), None)
    if not report:
        return render_template("error.html", message=f"No scan data for {host}"), 404
    device_remediations = [r for r in remediation.get_remediation_log() if r["host"] == host]
    return render_template("device_detail.html", report=report, simulator_mode=device_client.USE_SIMULATOR,
                            device_remediations=device_remediations)


@app.route("/reports/weekly")
def reports_weekly():
    days = int(request.args.get("days", 7))
    report = reporting.weekly_report(days=days)
    return render_template("weekly_report.html", report=report, simulator_mode=device_client.USE_SIMULATOR,
                            email_configured=email_client.is_configured(),
                            distribution_list=email_client.distribution_list())


@app.route("/api/scan", methods=["POST"])
def api_rescan():
    """Trigger a fresh pull + re-score (+ auto-remediation) of every device in the fleet."""
    data = _run_full_scan()
    return jsonify(data)


@app.route("/api/reports")
def api_reports():
    if not _LAST_SCAN["scanned_at"]:
        _run_full_scan()
    return jsonify(_LAST_SCAN)


@app.route("/api/controls")
def api_controls():
    """List every CIS v8 control this tool checks, for documentation/audit purposes."""
    return jsonify([
        {
            "control_id": r.control_id,
            "title": r.title,
            "cis_safeguard": r.cis_safeguard,
            "severity": r.severity,
            "description": r.description,
        }
        for r in RULES
    ])


@app.route("/api/remediations")
def api_remediations():
    """Full remediation audit log: what changed, on which device, when, and
    which ServiceNow change request covers it."""
    host = request.args.get("host")
    log = remediation.get_remediation_log()
    if host:
        log = [r for r in log if r["host"] == host]
    return jsonify(log)


@app.route("/api/remediation-summary")
def api_remediation_summary():
    """Pie (status breakdown) + line (30-day trend) data for the dashboard charts."""
    return jsonify({
        "breakdown": reporting.remediation_status_breakdown(),
        "trend": reporting.remediation_trend(days=30),
        "has_demo_data": remediation.has_demo_data(),
    })


@app.route("/api/seed-demo-data", methods=["POST"])
def api_seed_demo_data():
    """
    Backfill 30 days of clearly-labeled synthetic remediation history so
    the dashboard's pie/line charts have something to show immediately --
    handy right after a fresh deploy, or on Render's free tier where a
    cold start wipes the in-memory remediation log. Simulator-only: this
    is a display aid, not something that should ever run against a real
    fleet's history.
    """
    if not device_client.USE_SIMULATOR:
        return jsonify({"error": "Demo data seeding is only available in simulator mode (USE_SIMULATOR=true)."}), 403
    days = int(request.args.get("days", 30))
    added = remediation.seed_demo_trend(days=days)
    return jsonify({
        "added": added,
        "breakdown": reporting.remediation_status_breakdown(),
        "trend": reporting.remediation_trend(days=30),
    })


@app.route("/api/clear-demo-data", methods=["POST"])
def api_clear_demo_data():
    """Remove only the synthetic demo records seeded above, leaving any real
    remediation history untouched."""
    removed = remediation.clear_demo_data()
    return jsonify({
        "removed": removed,
        "breakdown": reporting.remediation_status_breakdown(),
        "trend": reporting.remediation_trend(days=30),
    })


@app.route("/api/weekly-report", methods=["GET", "POST"])
def api_weekly_report():
    """
    GET returns the current weekly report as JSON. POST computes it and
    sends the weekly email immediately -- this is the endpoint an external
    scheduler (Render Cron Job, GitHub Actions cron, cron-job.org, etc.)
    should call weekly; see README for why that's recommended over the
    in-process scheduler on a free/spin-down hosting tier.
    """
    days = int(request.args.get("days", 7))
    report = reporting.weekly_report(days=days)
    if request.method == "POST":
        html, text = reporting.render_email_body(report)
        try:
            delivery = email_client.send_weekly_report(report, html, text)
        except email_client.EmailDeliveryError as e:
            return jsonify({"report": report, "email_error": str(e)}), 502
        return jsonify({"report": report, "email": delivery})
    return jsonify(report)


@app.route("/api/meraki-compliance")
def api_meraki_compliance():
    """Cisco Meraki switch fleet: current vs. latest-available firmware."""
    try:
        return jsonify(meraki_client.compliance_summary())
    except meraki_client.MerakiAPIError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "simulator_mode": device_client.USE_SIMULATOR})


# ---------------------------------------------------------------------------
# Weekly report scheduler (optional, in-process)
# ---------------------------------------------------------------------------
# Off by default: with multiple gunicorn workers (see Procfile/Dockerfile),
# an in-process scheduler running in every worker would send the weekly
# email once per worker. Set ENABLE_SCHEDULER=true only for a single-process
# deployment (e.g. `python server.py`, or gunicorn with --workers 1).
# For multi-worker or spin-down-capable hosts (e.g. Render's free tier),
# use an external scheduler hitting POST /api/weekly-report instead -- see
# README "Weekly reports & email".
if os.environ.get("ENABLE_SCHEDULER", "false").lower() == "true":
    from apscheduler.schedulers.background import BackgroundScheduler

    def _weekly_report_job():
        report = reporting.weekly_report(days=7)
        html, text = reporting.render_email_body(report)
        try:
            email_client.send_weekly_report(report, html, text)
        except email_client.EmailDeliveryError:
            pass  # best-effort; a failed send shouldn't crash the scheduler thread

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_weekly_report_job, "cron", day_of_week="mon", hour=6, minute=0, id="weekly_report")
    _scheduler.start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
