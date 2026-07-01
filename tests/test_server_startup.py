"""
Tests for server.py's startup-time behavior -- specifically AUTO_SEED_DEMO_DATA,
which is what actually keeps the dashboard's remediation charts from looking
empty on a real deployment (see server.py's comment above that flag for why
the manual /api/seed-demo-data button alone isn't enough on multi-worker or
spin-down-capable hosts like Render).

server.py has import-time side effects (it seeds on module load), and it's
the entrypoint for a multi-worker Gunicorn process in production, so the
most faithful way to test "does a freshly booted worker process have
remediation data" is to actually boot a fresh Python process and ask it --
importing server.py in-process here would share pytest's own already-primed
app.remediation module state and wouldn't prove anything about a cold start.
"""

import json
import subprocess
import sys
import os


def _run_in_fresh_process(code: str, env_overrides: dict) -> str:
    env = os.environ.copy()
    env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"subprocess failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout.strip()


def test_fresh_worker_process_has_seeded_demo_data_by_default():
    """The core regression guard for 'charts show nothing on Render': a
    brand-new process importing server.py, with no prior scan and no manual
    seed click, should already have a non-empty remediation log."""
    out = _run_in_fresh_process(
        "import server\n"
        "from app import remediation\n"
        "print(len(remediation.get_remediation_log()))\n"
        "print(remediation.has_demo_data())\n",
        {"USE_SIMULATOR": "true", "AUTO_SEED_DEMO_DATA": "true", "FLASK_DEBUG": "false"},
    )
    lines = out.splitlines()
    count = int(lines[0])
    has_demo = lines[1] == "True"
    assert count > 0, "expected a freshly booted worker to already have remediation history"
    assert has_demo is True


def test_auto_seed_can_be_disabled():
    out = _run_in_fresh_process(
        "import server\n"
        "from app import remediation\n"
        "print(len(remediation.get_remediation_log()))\n",
        {"USE_SIMULATOR": "true", "AUTO_SEED_DEMO_DATA": "false", "FLASK_DEBUG": "false"},
    )
    assert int(out.strip()) == 0


def test_remediation_summary_endpoint_is_non_empty_immediately_after_boot():
    """End-to-end version of the same guarantee, through the actual
    /api/remediation-summary payload the dashboard's charts read from."""
    out = _run_in_fresh_process(
        "import server\n"
        "client = server.app.test_client()\n"
        "resp = client.get('/api/remediation-summary')\n"
        "import json\n"
        "print(json.dumps(resp.get_json()))\n",
        {"USE_SIMULATOR": "true", "AUTO_SEED_DEMO_DATA": "true", "FLASK_DEBUG": "false"},
    )
    data = json.loads(out.strip().splitlines()[-1])
    total = sum(data["breakdown"].values())
    assert total > 0
    assert data["has_demo_data"] is True
