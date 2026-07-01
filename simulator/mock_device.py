"""
Mock Cisco device layer.

In a real deployment, app/device_client.py connects to switches over SSH
using Netmiko and runs `show running-config`. Standing up real reachable
SSH switches isn't possible in this prototype's environment, so this
module simulates that boundary: it exposes the same function signature
(`get_running_config(host) -> str`) but returns canned config text for a
small fleet of virtual devices instead of opening a socket.

It also simulates *pushing* config back to a device (apply_remediation),
which is what makes auto-remediation demonstrable end to end in the
prototype: applying a fix mutates this module's in-memory "live" config
for that host, and the next scan reads the mutated text back -- exactly
like a real device reflecting a config change made over SSH.

Swapping to real hardware later means changing ONLY device_client.py;
nothing in checks/ or server.py needs to change. See README "Going to
production" section.
"""

import os
import sys
import time
import random

_SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_configs")

# Make app/ importable regardless of working directory (needed so
# apply_remediation can reach app.checks.cis_v8_fixes).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# host -> (display name, config filename, simulated site)
FLEET = {
    "10.1.1.11": {"name": "sw-legacy-01", "file": "sw-legacy-01.cfg", "site": "PHX - Remote Closet A"},
    "10.1.1.12": {"name": "sw-hardened-02", "file": "sw-hardened-02.cfg", "site": "PHX - DC1 Core"},
    "10.1.1.13": {"name": "sw-partial-03", "file": "sw-partial-03.cfg", "site": "PHX - Remote Site B"},
}

# In-memory "live" config per host, seeded lazily from the sample file on
# first read. This is intentionally process-lifetime-only, same as
# server.py's _LAST_SCAN cache -- see README "Going to production" for the
# note about persisting this to a real datastore.
_LIVE_CONFIG: dict = {}


class DeviceUnreachableError(Exception):
    pass


def _load_from_disk(host: str) -> str:
    path = os.path.join(_SAMPLE_DIR, FLEET[host]["file"])
    with open(path, "r") as f:
        return f.read()


def list_fleet():
    """Return the simulated inventory, e.g. for populating a dropdown/table."""
    return [{"host": host, **meta} for host, meta in FLEET.items()]


def get_running_config(host: str, simulate_latency: bool = True) -> str:
    """
    Simulated equivalent of an SSH session running `show running-config`.

    Raises DeviceUnreachableError for unknown hosts, mirroring how a real
    Netmiko connection would raise NetmikoTimeoutException/AuthenticationException.
    """
    if host not in FLEET:
        raise DeviceUnreachableError(f"No route to host {host} (simulated)")

    if simulate_latency:
        time.sleep(random.uniform(0.15, 0.5))  # mimic real SSH round-trip

    if host not in _LIVE_CONFIG:
        _LIVE_CONFIG[host] = _load_from_disk(host)
    return _LIVE_CONFIG[host]


def apply_remediation(host: str, control_id: str) -> bool:
    """
    Simulated equivalent of pushing a remediation's CLI to a real device
    over SSH: runs the matching config-patch function (see
    app/checks/cis_v8_fixes.py) against this device's current live config
    and stores the result as the device's new running-config.

    Returns True if a known auto-fix exists and was applied, False if
    there's no automated fix for this control_id (caller should route
    that finding to manual review / a ServiceNow change request instead).
    """
    if host not in FLEET:
        raise DeviceUnreachableError(f"No route to host {host} (simulated)")

    from app.checks.cis_v8_fixes import get_fix_fn
    fix_fn = get_fix_fn(control_id)
    if not fix_fn:
        return False

    current = get_running_config(host, simulate_latency=False)
    _LIVE_CONFIG[host] = fix_fn(current)
    return True


def reset_fleet():
    """Testing/demo helper: discard any applied remediations and reload
    every device's config fresh from the sample files on disk."""
    _LIVE_CONFIG.clear()
