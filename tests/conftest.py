"""
Shared pytest fixtures.

The new modules (remediation, servicenow_client, email_client, and the
simulator's live per-host config) all use module-level in-memory state --
the same pattern server.py's _LAST_SCAN cache already used. That's fine at
runtime but means tests must reset it between cases, or one test's
remediation actions (ServiceNow tickets, mutated simulated configs) leak
into the next.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("USE_SIMULATOR", "true")
os.environ.setdefault("USE_SERVICENOW_SIMULATOR", "true")
os.environ.setdefault("USE_MERAKI_SIMULATOR", "true")

import pytest  # noqa: E402

from app import remediation, servicenow_client, email_client  # noqa: E402
from simulator import mock_device  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_module_state():
    remediation.reset()
    servicenow_client.reset()
    email_client.reset()
    mock_device.reset_fleet()
    yield
    remediation.reset()
    servicenow_client.reset()
    email_client.reset()
    mock_device.reset_fleet()
