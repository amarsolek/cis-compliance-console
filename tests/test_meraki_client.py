"""
Tests for the Cisco Meraki firmware-compliance client (simulator mode).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import meraki_client


def test_firmware_compliance_returns_rows_for_every_simulated_device():
    rows = meraki_client.firmware_compliance()
    assert len(rows) == len(meraki_client._SIM_DEVICES)
    for row in rows:
        assert set(row) >= {"serial", "name", "model", "network", "current_version", "latest_version", "compliant"}


def test_simulated_fleet_includes_a_noncompliant_device():
    rows = meraki_client.firmware_compliance()
    assert any(not r["compliant"] for r in rows), "expected at least one device behind on firmware"
    assert any(r["compliant"] for r in rows), "expected at least one device already current"


def test_compliance_summary_counts_are_consistent():
    summary = meraki_client.compliance_summary()
    assert summary["total"] == len(summary["devices"])
    assert summary["compliant"] + summary["non_compliant"] == summary["total"]


def test_real_mode_requires_credentials():
    original = meraki_client.USE_SIMULATOR
    meraki_client.USE_SIMULATOR = False
    try:
        os.environ.pop("MERAKI_API_KEY", None)
        os.environ.pop("MERAKI_ORG_ID", None)
        try:
            meraki_client.firmware_compliance()
            assert False, "expected MerakiAPIError without credentials"
        except meraki_client.MerakiAPIError:
            pass
    finally:
        meraki_client.USE_SIMULATOR = original
