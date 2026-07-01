"""Tests for the Cisco Meraki firmware-compliance client (simulated mode)."""

import pytest

from app import meraki_client


def test_firmware_compliance_returns_simulated_fleet():
    rows = meraki_client.firmware_compliance()
    assert len(rows) == 3
    assert all({"serial", "name", "model", "network", "current_version",
                "latest_version", "compliant"} <= row.keys() for row in rows)


def test_compliance_summary_counts_match_rows():
    summary = meraki_client.compliance_summary()
    assert summary["total"] == 3
    assert summary["compliant"] + summary["non_compliant"] == summary["total"]
    assert len(summary["devices"]) == summary["total"]


def test_at_least_one_simulated_device_is_out_of_date():
    summary = meraki_client.compliance_summary()
    assert summary["non_compliant"] >= 1
    non_compliant = [d for d in summary["devices"] if not d["compliant"]]
    assert any(d["current_version"] != d["latest_version"] for d in non_compliant)


def test_real_mode_requires_api_credentials(monkeypatch):
    monkeypatch.setattr(meraki_client, "USE_SIMULATOR", False)
    monkeypatch.delenv("MERAKI_API_KEY", raising=False)
    monkeypatch.delenv("MERAKI_ORG_ID", raising=False)
    with pytest.raises(meraki_client.MerakiAPIError):
        meraki_client.firmware_compliance()
