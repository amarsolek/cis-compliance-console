"""Tests for the simulated ServiceNow change-management client."""

import pytest

from app import servicenow_client


def test_create_change_request_returns_ticket_number():
    number = servicenow_client.create_change_request(
        host="10.1.1.11", device_name="sw-legacy-01",
        summary="Test change", description="Test description",
    )
    assert number.startswith("CHG")


def test_ticket_numbers_are_sequential_and_unique():
    n1 = servicenow_client.create_change_request(
        host="10.1.1.11", device_name="sw-legacy-01", summary="A", description="A",
    )
    n2 = servicenow_client.create_change_request(
        host="10.1.1.11", device_name="sw-legacy-01", summary="B", description="B",
    )
    assert n1 != n2


def test_list_change_requests_returns_created_tickets():
    servicenow_client.create_change_request(
        host="10.1.1.12", device_name="sw-hardened-02", summary="C", description="C",
    )
    tickets = servicenow_client.list_change_requests()
    assert len(tickets) == 1
    assert tickets[0]["cmdb_ci"] == "sw-hardened-02"
    assert tickets[0]["category"] == "Network"


def test_automated_summary_marks_state_implement():
    number = servicenow_client.create_change_request(
        host="10.1.1.11", device_name="sw-legacy-01",
        summary="Automated CIS v8 remediation applied: 3 control(s) on sw-legacy-01",
        description="...",
    )
    ticket = next(t for t in servicenow_client.list_change_requests() if t["number"] == number)
    assert ticket["state"] == "Implement"


def test_real_mode_requires_credentials(monkeypatch):
    monkeypatch.setattr(servicenow_client, "USE_SIMULATOR", False)
    monkeypatch.delenv("SERVICENOW_INSTANCE", raising=False)
    monkeypatch.delenv("SERVICENOW_USERNAME", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
    with pytest.raises(servicenow_client.ChangeManagementError):
        servicenow_client.create_change_request(
            host="10.1.1.11", device_name="sw-legacy-01", summary="X", description="X",
        )
