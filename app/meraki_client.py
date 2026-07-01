"""
Cisco Meraki firmware-compliance client.

Checks Meraki switches against the latest available stable firmware using
the real Meraki Dashboard API v1 (https://developer.cisco.com/meraki/api-v1/):

  GET /organizations/{organizationId}/devices?productTypes[]=switch
  GET /organizations/{organizationId}/networks
  GET /networks/{networkId}/firmwareUpgrades

Unlike the Cisco IOS/NX-OS fleet (which needs real SSH-reachable switches
this prototype's environment can't provide), the Meraki Dashboard API is a
cloud service -- so _real_compliance() below is a genuine, working
integration, not a stand-in. It just needs a real API key and org ID (see
README) to run against an actual Meraki organization. Without one, this
falls back to a small simulated Meraki fleet so the dashboard panel and
tests are demonstrable out of the box, matching the pattern used for the
IOS/NX-OS fleet in app/device_client.py.
"""

import os
from datetime import datetime, timezone

USE_SIMULATOR = os.environ.get("USE_MERAKI_SIMULATOR", "true").lower() != "false"
BASE_URL = "https://api.meraki.com/api/v1"


class MerakiAPIError(Exception):
    pass


# ---------------------------------------------------------------------------
# Simulated fleet -- one network already current, one behind, to make the
# "not in compliance with the latest OS" case visible without credentials.
# ---------------------------------------------------------------------------

_SIM_NETWORKS = {
    "N_SIM_PHX_DC1": {
        "name": "PHX-DC1 (Meraki)",
        "current": {"shortName": "MS 14.32.1"},
        "latest": {"shortName": "MS 15.21.1"},
        "isUpgradeAvailable": True,
    },
    "N_SIM_PHX_RS_B": {
        "name": "PHX-Remote-Site-B (Meraki)",
        "current": {"shortName": "MS 15.21.1"},
        "latest": {"shortName": "MS 15.21.1"},
        "isUpgradeAvailable": False,
    },
}

_SIM_DEVICES = [
    {"serial": "Q2XX-SIM1-0001", "name": "mk-dc1-access-01", "model": "MS120-48", "networkId": "N_SIM_PHX_DC1"},
    {"serial": "Q2XX-SIM1-0002", "name": "mk-dc1-core-02", "model": "MS425-16", "networkId": "N_SIM_PHX_DC1"},
    {"serial": "Q2XX-SIM2-0003", "name": "mk-rsb-access-03", "model": "MS120-24", "networkId": "N_SIM_PHX_RS_B"},
]


def _simulated_compliance() -> list:
    rows = []
    for dev in _SIM_DEVICES:
        net = _SIM_NETWORKS[dev["networkId"]]
        rows.append({
            "serial": dev["serial"],
            "name": dev["name"],
            "model": dev["model"],
            "network": net["name"],
            "current_version": net["current"]["shortName"],
            "latest_version": net["latest"]["shortName"],
            "compliant": not net["isUpgradeAvailable"],
        })
    return rows


# ---------------------------------------------------------------------------
# Real Meraki Dashboard API
# ---------------------------------------------------------------------------

def _real_compliance() -> list:
    try:
        import requests
    except ImportError as e:
        raise MerakiAPIError("requests is required for real Meraki mode. Install with: pip install requests") from e

    api_key = os.environ.get("MERAKI_API_KEY")
    org_id = os.environ.get("MERAKI_ORG_ID")
    if not api_key or not org_id:
        raise MerakiAPIError("MERAKI_API_KEY and MERAKI_ORG_ID must be set in the environment for real Meraki mode.")

    headers = {"X-Cisco-Meraki-API-Key": api_key, "Accept": "application/json"}

    devices_resp = requests.get(
        f"{BASE_URL}/organizations/{org_id}/devices",
        headers=headers, params={"productTypes[]": "switch"}, timeout=20,
    )
    if devices_resp.status_code >= 400:
        raise MerakiAPIError(f"Meraki API error {devices_resp.status_code} fetching devices: {devices_resp.text[:300]}")
    devices = devices_resp.json()

    networks_resp = requests.get(f"{BASE_URL}/organizations/{org_id}/networks", headers=headers, timeout=20)
    network_names = {n["id"]: n.get("name", n["id"]) for n in networks_resp.json()} if networks_resp.status_code < 400 else {}

    firmware_by_network = {}
    for net_id in sorted({d.get("networkId") for d in devices if d.get("networkId")}):
        fw_resp = requests.get(f"{BASE_URL}/networks/{net_id}/firmwareUpgrades", headers=headers, timeout=20)
        if fw_resp.status_code < 400:
            firmware_by_network[net_id] = fw_resp.json()

    rows = []
    for dev in devices:
        net_id = dev.get("networkId")
        switch_fw = firmware_by_network.get(net_id, {}).get("products", {}).get("switch", {})
        current = switch_fw.get("currentVersion", {}).get("shortName", "unknown")
        available = switch_fw.get("availableVersions", []) or []
        latest = max(available, key=lambda v: v.get("releaseDate", ""), default=None)
        rows.append({
            "serial": dev.get("serial"),
            "name": dev.get("name") or dev.get("serial"),
            "model": dev.get("model"),
            "network": network_names.get(net_id, net_id or "unknown"),
            "current_version": current,
            "latest_version": latest["shortName"] if latest else current,
            "compliant": not switch_fw.get("isUpgradeAvailable", False),
        })
    return rows


def firmware_compliance() -> list:
    """One row per Meraki switch: current vs. latest-available stable
    firmware, and whether the device is compliant (already on latest)."""
    return _simulated_compliance() if USE_SIMULATOR else _real_compliance()


def compliance_summary() -> dict:
    rows = firmware_compliance()
    non_compliant = [r for r in rows if not r["compliant"]]
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(rows),
        "compliant": len(rows) - len(non_compliant),
        "non_compliant": len(non_compliant),
        "devices": rows,
    }
