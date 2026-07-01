"""
Auto-remediation orchestration.

For every failed control on a device:
  1. If app/checks/cis_v8_fixes.py has a known, safe, fully-determined fix
     for it, push that fix to the device immediately (via device_client's
     simulator/real seam) and re-check afterward -- only report it as
     "auto-remediated" if the control actually passes now.
  2. Otherwise (no safe fix, or the fix was attempted but didn't resolve
     the finding), open a ServiceNow change request asking a network
     engineer to make the change, and record it as pending.

Every remediation action -- auto or manual -- is logged in-memory here for
the weekly report and the dashboard charts (app/reporting.py). Manual
findings are deduplicated per (host, control_id) so a still-unresolved
issue doesn't open a fresh ServiceNow ticket on every scan.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta

from app import device_client, servicenow_client
from app.checks.cis_v8_rules import run_all_checks
from app.checks.cis_v8_fixes import is_auto_remediable, manual_review_reason

_REMEDIATION_LOG: list = []          # append-only audit log, all runs
_OPEN_MANUAL_TICKETS: dict = {}      # (host, control_id) -> change_ticket number


@dataclass
class RemediationRecord:
    host: str
    name: str
    control_id: str
    title: str
    severity: str
    cis_safeguard: str
    evidence_before: str
    action: str            # auto_applied | manual_pending | attempt_failed
    remediation_text: str
    applied_at: str
    change_ticket: str = ""
    note: str = ""

    def to_dict(self):
        return asdict(self)


def remediate_device(host: str, name: str, config_text: str, failed_results: list) -> dict:
    """
    Attempt to fix every failed control on one device.

    failed_results: list of CheckResult.__dict__-style dicts (control_id,
    title, severity, cis_safeguard, evidence, remediation, passed=False).

    Returns {"new_config": str, "records": [RemediationRecord dicts]}.
    The caller (server.py) should re-fetch/re-score the device after this
    to reflect the post-remediation state.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    attempted_ids = []

    for r in failed_results:
        if is_auto_remediable(r["control_id"]):
            try:
                applied = device_client.push_remediation(host, r["control_id"], r.get("remediation", ""))
            except device_client.DeviceConnectionError:
                applied = False
            if applied:
                attempted_ids.append(r["control_id"])

    new_config = device_client.fetch_running_config(host)
    post_results = {res.control_id: res for res in run_all_checks(new_config)}

    # A control counts as resolved if it passes now, whether that's because
    # we fixed it directly or because fixing something else had a side
    # effect on it (e.g. removing the default SNMP community strings for
    # CIS-4.8/4.10 can also satisfy CIS-4.9's "SNMP not configured" pass
    # case). attempted_ids only distinguishes *why* an unresolved finding
    # is unresolved, for the ServiceNow note text.
    auto_applied, still_needs_action = [], []
    for r in failed_results:
        cid = r["control_id"]
        if post_results.get(cid) and post_results[cid].passed:
            auto_applied.append(r)
        else:
            still_needs_action.append(r)

    records = []

    if auto_applied:
        ticket = servicenow_client.create_change_request(
            host=host, device_name=name,
            summary=f"Automated CIS v8 remediation applied: {len(auto_applied)} control(s) on {name}",
            description="Auto-remediated by the CIS v8 Compliance Console (audit record; already applied):\n\n"
            + "\n\n".join(f"{r['control_id']} - {r['title']}\nBefore: {r['evidence']}\nApplied:\n{r['remediation']}"
                           for r in auto_applied),
            risk="Low",
        )
        for r in auto_applied:
            records.append(RemediationRecord(
                host=host, name=name, control_id=r["control_id"], title=r["title"],
                severity=r["severity"], cis_safeguard=r["cis_safeguard"],
                evidence_before=r["evidence"], action="auto_applied",
                remediation_text=r["remediation"], applied_at=now, change_ticket=ticket,
            ).to_dict())

    for r in still_needs_action:
        cid = r["control_id"]
        key = (host, cid)
        attempted_but_failed = cid in attempted_ids
        reason = ("Auto-fix was attempted but the finding is still present after re-check "
                  "(needs an engineer to verify) -- see evidence." if attempted_but_failed
                  else manual_review_reason(cid))

        if key in _OPEN_MANUAL_TICKETS:
            ticket = _OPEN_MANUAL_TICKETS[key]
            action = "attempt_failed" if attempted_but_failed else "manual_pending"
            records.append(RemediationRecord(
                host=host, name=name, control_id=cid, title=r["title"],
                severity=r["severity"], cis_safeguard=r["cis_safeguard"],
                evidence_before=r["evidence"], action=action,
                remediation_text=r["remediation"], applied_at=now, change_ticket=ticket,
                note="Still open from a prior scan; not re-filed.",
            ).to_dict())
            continue

        ticket = servicenow_client.create_change_request(
            host=host, device_name=name,
            summary=f"CIS v8 finding needs engineer action: {r['title']} on {name}",
            description=f"{cid} - {r['title']} ({r['severity']})\n"
                        f"Evidence: {r['evidence']}\n"
                        f"Suggested remediation:\n{r['remediation']}\n\n"
                        f"Why this needs a human: {reason}",
            risk="Medium" if r["severity"] == "high" else "Low",
        )
        _OPEN_MANUAL_TICKETS[key] = ticket
        action = "attempt_failed" if attempted_but_failed else "manual_pending"
        records.append(RemediationRecord(
            host=host, name=name, control_id=cid, title=r["title"],
            severity=r["severity"], cis_safeguard=r["cis_safeguard"],
            evidence_before=r["evidence"], action=action,
            remediation_text=r["remediation"], applied_at=now, change_ticket=ticket,
            note=reason,
        ).to_dict())

    _REMEDIATION_LOG.extend(records)
    return {"new_config": new_config, "records": records}


def clear_resolved_manual_tickets(host: str, currently_failing_ids: set):
    """Call after a device re-scans clean on a control: drop it from the
    open-ticket dedup table so a future regression opens a fresh ticket
    instead of silently reusing a closed one."""
    for key in [k for k in _OPEN_MANUAL_TICKETS if k[0] == host and k[1] not in currently_failing_ids]:
        del _OPEN_MANUAL_TICKETS[key]


def get_remediation_log() -> list:
    return list(_REMEDIATION_LOG)


def remediations_since(days: int = 7) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for r in _REMEDIATION_LOG:
        try:
            ts = datetime.fromisoformat(r["applied_at"])
        except ValueError:
            continue
        if ts >= cutoff:
            out.append(r)
    return out


def reset():
    """Testing/demo helper."""
    _REMEDIATION_LOG.clear()
    _OPEN_MANUAL_TICKETS.clear()
