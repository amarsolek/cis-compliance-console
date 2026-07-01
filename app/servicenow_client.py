"""
ServiceNow change-management integration.

Same simulator/real seam as app/device_client.py: without real ServiceNow
credentials, change requests are logged to an in-memory simulated queue
instead of calling out to a real instance, so the remediation -> change
record pipeline is demonstrable without a ServiceNow developer instance.
Set SERVICENOW_INSTANCE / SERVICENOW_USERNAME / SERVICENOW_PASSWORD (see
README) to open real Change Request records via the Table API instead.

Every auto-remediated batch AND every manual-review finding gets a change
request: auto-applied fixes get one as an *audit record of what already
happened* (so there's a change trail even though nothing was gated on
approval); manual-review findings get one that requests a human make the
change, since this tool deliberately won't guess at values like a real
management subnet or NTP server IP.
"""

import os
import uuid
from datetime import datetime, timezone

USE_SIMULATOR = os.environ.get("USE_SERVICENOW_SIMULATOR", "true").lower() != "false"

_TICKET_SEQ = 1000
_SIMULATED_TICKETS: list = []


class ChangeManagementError(Exception):
    pass


def create_change_request(host: str, device_name: str, summary: str, description: str,
                           risk: str = "Low", change_type: str = "Standard") -> str:
    """
    Open a change request documenting a remediation action (already applied
    or still pending a human). Returns the change request number
    (e.g. "CHG0001007").
    """
    if USE_SIMULATOR:
        return _create_simulated(host, device_name, summary, description, risk, change_type)
    return _create_via_rest_api(host, device_name, summary, description, risk, change_type)


def list_change_requests() -> list:
    """Return every change request opened this run (simulator) -- used by
    the dashboard and weekly report. Real mode queries the Table API."""
    if USE_SIMULATOR:
        return list(_SIMULATED_TICKETS)
    return _list_via_rest_api()


def _create_simulated(host, device_name, summary, description, risk, change_type) -> str:
    global _TICKET_SEQ
    _TICKET_SEQ += 1
    number = f"CHG{_TICKET_SEQ:07d}"
    _SIMULATED_TICKETS.append({
        "number": number,
        "sys_id": str(uuid.uuid4()),
        "host": host,
        "cmdb_ci": device_name,
        "short_description": summary,
        "description": description,
        "risk": risk,
        "type": change_type,
        "category": "Network",
        "state": "Implement" if "Automated" in summary else "New",
        "opened_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    return number


def _create_via_rest_api(host, device_name, summary, description, risk, change_type) -> str:
    try:
        import requests
    except ImportError as e:
        raise ChangeManagementError(
            "requests is required for real ServiceNow mode. Install with: pip install requests"
        ) from e

    instance = os.environ.get("SERVICENOW_INSTANCE")  # e.g. https://yourinstance.service-now.com
    username = os.environ.get("SERVICENOW_USERNAME")
    password = os.environ.get("SERVICENOW_PASSWORD")
    if not instance or not username or not password:
        raise ChangeManagementError(
            "SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD must be set "
            "in the environment for real ServiceNow mode."
        )

    url = f"{instance.rstrip('/')}/api/now/table/change_request"
    payload = {
        "short_description": summary,
        "description": description,
        "category": "Network",
        "risk": risk,
        "type": change_type,
        "cmdb_ci": device_name,
    }
    resp = requests.post(
        url, auth=(username, password), json=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=15,
    )
    if resp.status_code >= 400:
        raise ChangeManagementError(f"ServiceNow API error {resp.status_code}: {resp.text[:300]}")
    return resp.json()["result"]["number"]


def _list_via_rest_api() -> list:
    try:
        import requests
    except ImportError as e:
        raise ChangeManagementError(
            "requests is required for real ServiceNow mode. Install with: pip install requests"
        ) from e

    instance = os.environ.get("SERVICENOW_INSTANCE")
    username = os.environ.get("SERVICENOW_USERNAME")
    password = os.environ.get("SERVICENOW_PASSWORD")
    if not instance or not username or not password:
        raise ChangeManagementError(
            "SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD must be set "
            "in the environment for real ServiceNow mode."
        )
    url = f"{instance.rstrip('/')}/api/now/table/change_request?sysparm_query=category=Network&sysparm_limit=200"
    resp = requests.get(url, auth=(username, password), headers={"Accept": "application/json"}, timeout=15)
    if resp.status_code >= 400:
        raise ChangeManagementError(f"ServiceNow API error {resp.status_code}: {resp.text[:300]}")
    return resp.json().get("result", [])


def reset():
    """Testing/demo helper: clear the simulated ticket queue."""
    global _TICKET_SEQ
    _SIMULATED_TICKETS.clear()
    _TICKET_SEQ = 1000
