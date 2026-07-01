"""
Tests for the ServiceNow change-management client (simulator mode).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import servicenow_client


def test_create_change_request_returns_unique_ticket_numbers():
    t1 = servicenow_client.create_change_request("10.1.1.11", "sw-legacy-01", "summary one", "desc one")
    t2 = servicenow_client.create_change_request("10.1.1.11", "sw-legacy-01", "summary two", "desc two")
    assert t1 != t2
    assert t1.startswith("CHG")
    assert t2.startswith("CHG")


def test_list_change_requests_reflects_created_tickets():
    servicenow_client.create_change_request("10.1.1.12", "sw-hardened-02", "summary", "desc")
    tickets = servicenow_client.list_change_requests()
    assert len(tickets) == 1
    assert tickets[0]["host"] == "10.1.1.12"
    assert tickets[0]["cmdb_ci"] == "sw-hardened-02"


def test_real_mode_requires_credentials():
    original = servicenow_client.USE_SIMULATOR
    servicenow_client.USE_SIMULATOR = False
    try:
        for var in ("SERVICENOW_INSTANCE", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD"):
            os.environ.pop(var, None)
        try:
            servicenow_client.create_change_request("h", "n", "s", "d")
            assert False, "expected ChangeManagementError without credentials"
        except servicenow_client.ChangeManagementError:
            pass
    finally:
        servicenow_client.USE_SIMULATOR = original
