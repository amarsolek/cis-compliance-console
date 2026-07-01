"""
Weekly remediation reporting.

Aggregates app/remediation.py's in-memory audit log (same in-memory-cache
pattern as server.py's _LAST_SCAN and simulator/mock_device.py's
_LIVE_CONFIG -- see README "Going to production" for the note about
swapping this for a real datastore) into:

  * a per-device weekly summary (what changed, by hostname) for the
    scheduled email report
  * a daily trend series and a status breakdown for the dashboard's line
    and pie charts
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta

from app import remediation


def _parse_ts(value: str):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def weekly_report(days: int = 7) -> dict:
    """Per-device rollup of what was changed/flagged in the trailing window,
    for the weekly email and the /reports/weekly page."""
    records = remediation.remediations_since(days)
    by_host = defaultdict(list)
    for r in records:
        by_host[r["host"]].append(r)

    devices = []
    for host, recs in by_host.items():
        auto = [r for r in recs if r["action"] == "auto_applied"]
        pending = [r for r in recs if r["action"] in ("manual_pending", "attempt_failed")]
        devices.append({
            "host": host,
            "name": recs[0]["name"],
            "auto_applied": len(auto),
            "manual_pending": len(pending),
            "controls_fixed": sorted({r["control_id"] for r in auto}),
            "controls_pending": sorted({r["control_id"] for r in pending}),
            "change_tickets": sorted({r["change_ticket"] for r in recs if r["change_ticket"]}),
        })
    devices.sort(key=lambda d: (-d["auto_applied"], d["host"]))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window_days": days,
        "total_actions": len(records),
        "total_auto_applied": sum(d["auto_applied"] for d in devices),
        "total_manual_pending": sum(d["manual_pending"] for d in devices),
        "devices": devices,
    }


def remediation_trend(days: int = 30) -> dict:
    """Daily auto-applied vs manual-pending counts for the dashboard line
    chart, oldest to newest."""
    records = remediation.remediations_since(days)
    by_day = defaultdict(lambda: {"auto_applied": 0, "manual_pending": 0})
    for r in records:
        ts = _parse_ts(r["applied_at"])
        if not ts:
            continue
        day = ts.date().isoformat()
        if r["action"] == "auto_applied":
            by_day[day]["auto_applied"] += 1
        else:
            by_day[day]["manual_pending"] += 1

    today = datetime.now(timezone.utc).date()
    ordered_days = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    return {
        "labels": ordered_days,
        "auto_applied": [by_day[d]["auto_applied"] for d in ordered_days],
        "manual_pending": [by_day[d]["manual_pending"] for d in ordered_days],
    }


def remediation_status_breakdown() -> dict:
    """All-time action-type counts for the dashboard pie chart."""
    records = remediation.get_remediation_log()
    counts = {"auto_applied": 0, "manual_pending": 0, "attempt_failed": 0}
    for r in records:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
    return counts


def render_email_body(report: dict):
    """Return (html, text) bodies for the weekly report email."""
    lines_text = [
        f"CIS v8 Weekly Remediation Report -- {report['generated_at']}",
        f"Window: trailing {report['window_days']} day(s)",
        f"Total actions: {report['total_actions']}  "
        f"(auto-applied: {report['total_auto_applied']}, needs engineer action: {report['total_manual_pending']})",
        "",
    ]
    if not report["devices"]:
        lines_text.append("No remediation activity in this window.")
    for d in report["devices"]:
        lines_text.append(f"- {d['name']} ({d['host']}): {d['auto_applied']} auto-fixed, "
                           f"{d['manual_pending']} pending engineer action")
        if d["controls_fixed"]:
            lines_text.append(f"    fixed: {', '.join(d['controls_fixed'])}")
        if d["controls_pending"]:
            lines_text.append(f"    pending: {', '.join(d['controls_pending'])}")
        if d["change_tickets"]:
            lines_text.append(f"    change tickets: {', '.join(d['change_tickets'])}")
    text = "\n".join(lines_text)

    rows_html = "".join(
        f"<tr><td>{d['name']}</td><td>{d['host']}</td>"
        f"<td>{d['auto_applied']}</td><td>{d['manual_pending']}</td>"
        f"<td>{', '.join(d['controls_fixed']) or '&mdash;'}</td>"
        f"<td>{', '.join(d['controls_pending']) or '&mdash;'}</td>"
        f"<td>{', '.join(d['change_tickets']) or '&mdash;'}</td></tr>"
        for d in report["devices"]
    ) or "<tr><td colspan='7'>No remediation activity in this window.</td></tr>"

    html = f"""<html><body style="font-family: monospace; font-size: 13px; color: #1a1a1a;">
<h2>CIS v8 Weekly Remediation Report</h2>
<p>Generated: {report['generated_at']} &middot; Window: trailing {report['window_days']} day(s)</p>
<p><b>Total actions:</b> {report['total_actions']} &middot;
<b>Auto-applied:</b> {report['total_auto_applied']} &middot;
<b>Needs engineer action:</b> {report['total_manual_pending']}</p>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
<tr style="background:#eee;">
  <th>Device</th><th>Host</th><th>Auto-Fixed</th><th>Pending</th>
  <th>Controls Fixed</th><th>Controls Pending</th><th>Change Tickets</th>
</tr>
{rows_html}
</table>
</body></html>"""
    return html, text
