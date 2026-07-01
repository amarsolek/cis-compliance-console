"""
Device connection layer.

This module is the single seam between "talk to a real switch" and
"talk to the simulator." Set USE_SIMULATOR=false (env var) and provide
real credentials to point this at actual Cisco IOS/NX-OS devices via
Netmiko -- no other file in the app needs to change.
"""

import os

USE_SIMULATOR = os.environ.get("USE_SIMULATOR", "true").lower() != "false"

# Import the simulator via its full package path (app.device_client ->
# project root -> simulator.mock_device) rather than adding simulator/ to
# sys.path and importing "mock_device" as a bare top-level module. The
# latter used to create two separate module objects (this one, and
# whatever imported it as simulator.mock_device elsewhere -- e.g. tests),
# each with its own independent copy of mock_device's in-memory live
# config, which silently broke test isolation and would just as silently
# break the real app if anything else ever imported the simulator package
# directly.


class DeviceConnectionError(Exception):
    pass


def list_inventory():
    """Return the list of devices this app knows how to reach."""
    if USE_SIMULATOR:
        from simulator.mock_device import list_fleet
        return list_fleet()
    return _real_inventory_from_env()


def fetch_running_config(host: str, device_type: str = "cisco_ios") -> str:
    """
    Fetch `show running-config` from a device.

    device_type follows Netmiko's naming convention (e.g. 'cisco_ios',
    'cisco_nxos') and is only used in the real-device branch.
    """
    if USE_SIMULATOR:
        from simulator.mock_device import get_running_config, DeviceUnreachableError
        try:
            return get_running_config(host)
        except DeviceUnreachableError as e:
            raise DeviceConnectionError(str(e)) from e

    return _fetch_via_netmiko(host, device_type)


def push_remediation(host: str, control_id: str, remediation_cli: str, device_type: str = "cisco_ios") -> bool:
    """
    Apply one control's fix to a device -- the push-side counterpart to
    fetch_running_config(). Same simulator/real split:

      * simulator mode runs the matching patch function in
        app/checks/cis_v8_fixes.py against the device's in-memory config
      * real-device mode sends the rule's literal remediation CLI to the
        device over SSH via Netmiko (send_config_set)

    Returns True if the fix was actually applied, False if there's no
    automated fix for this control (the caller should route that finding
    to manual review / a ServiceNow change request instead of assuming
    something happened).
    """
    if USE_SIMULATOR:
        from simulator.mock_device import apply_remediation, DeviceUnreachableError
        try:
            return apply_remediation(host, control_id)
        except DeviceUnreachableError as e:
            raise DeviceConnectionError(str(e)) from e

    return _push_via_netmiko(host, remediation_cli, device_type)


# ---------------------------------------------------------------------------
# Real-device path (Netmiko). Not exercised in the simulated prototype, but
# kept here, fully wired, as the documented path to production.
# ---------------------------------------------------------------------------

def _real_inventory_from_env():
    """
    Real deployments should replace this with a CMDB/NetBox/database lookup.
    For a minimal real-device test, set DEVICE_HOSTS as a comma-separated
    list of IPs/hostnames in the environment.
    """
    hosts = os.environ.get("DEVICE_HOSTS", "")
    return [{"host": h.strip(), "name": h.strip(), "site": "unspecified"}
            for h in hosts.split(",") if h.strip()]


def _fetch_via_netmiko(host: str, device_type: str) -> str:
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    except ImportError as e:
        raise DeviceConnectionError(
            "netmiko is required for real-device mode. Install with: pip install netmiko"
        ) from e

    username = os.environ.get("DEVICE_USERNAME")
    password = os.environ.get("DEVICE_PASSWORD")
    secret = os.environ.get("DEVICE_ENABLE_SECRET", password)

    if not username or not password:
        raise DeviceConnectionError(
            "DEVICE_USERNAME and DEVICE_PASSWORD must be set in the environment for real-device mode."
        )

    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 15,
    }

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            return conn.send_command("show running-config")
    except NetmikoTimeoutException as e:
        raise DeviceConnectionError(f"Timed out connecting to {host}") from e
    except NetmikoAuthenticationException as e:
        raise DeviceConnectionError(f"Authentication failed for {host}") from e


def _push_via_netmiko(host: str, remediation_cli: str, device_type: str) -> bool:
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    except ImportError as e:
        raise DeviceConnectionError(
            "netmiko is required for real-device mode. Install with: pip install netmiko"
        ) from e

    username = os.environ.get("DEVICE_USERNAME")
    password = os.environ.get("DEVICE_PASSWORD")
    secret = os.environ.get("DEVICE_ENABLE_SECRET", password)

    if not username or not password:
        raise DeviceConnectionError(
            "DEVICE_USERNAME and DEVICE_PASSWORD must be set in the environment for real-device mode."
        )

    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 15,
    }

    commands = [l for l in remediation_cli.splitlines() if l.strip()]
    if not commands:
        return False

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            conn.send_config_set(commands)
            conn.save_config()
        return True
    except NetmikoTimeoutException as e:
        raise DeviceConnectionError(f"Timed out connecting to {host}") from e
    except NetmikoAuthenticationException as e:
        raise DeviceConnectionError(f"Authentication failed for {host}") from e
