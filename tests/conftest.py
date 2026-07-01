"""
Shared pytest fixtures.

Every module in this app that carries in-memory state (the simulated
device fleet, the remediation audit log, the simulated ServiceNow ticket
queue, the simulated email send log) needs to be reset between tests --
otherwise a record created by one test bleeds into the next test's
assertions. This autouse fixture does that reset before every test runs,
so individual test files don't have to remember to do it themselves.
"""

import pytest

from app import remediation, servicenow_client, email_client
from simulator import mock_device


@pytest.fixture(autouse=True)
def _reset_all_state():
    remediation.reset()
    servicenow_client.reset()
    email_client.reset()
    mock_device.reset_fleet()
    yield
    remediation.reset()
    servicenow_client.reset()
    email_client.reset()
    mock_device.reset_fleet()
