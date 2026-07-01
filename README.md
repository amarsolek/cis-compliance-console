# CIS v8 Network Compliance Console

A fleet-wide dashboard that pulls Cisco IOS / NX-OS switch configurations and scores them against **33 controls** mapped to **CIS Controls v8**, auto-remediates the findings it can safely fix, opens ServiceNow change requests for everything else, emails a weekly remediation report, and checks a Cisco Meraki switch fleet's firmware against the latest available release.

![status](https://img.shields.io/badge/status-prototype-blue) ![python](https://img.shields.io/badge/python-3.12-blue) ![flask](https://img.shields.io/badge/flask-3.0-black)
[![CI](https://github.com/<your-org>/<your-repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-org>/<your-repo>/actions/workflows/ci.yml)

---

## What this is

A working prototype of a configuration-compliance tool: it connects to a fleet of switches, retrieves `show running-config`, runs it through a rule engine covering 8 CIS v8 control families (Account Management, Access Control Management, AAA, Audit Log Management, Network Infrastructure, Network Monitoring, Malware/segmentation-adjacent hardening, and Security Awareness banners), and renders a NOC-style dashboard with a fleet summary and per-control evidence/remediation.

Beyond scoring, it now closes the loop:

- **Auto-remediation.** Findings with a safe, fully-determined fix (see [Automated remediation](#automated-remediation--change-management) below) are corrected immediately on every scan. Everything else -- findings that need a real management-subnet, a real TACACS+/syslog/NTP IP, real SNMPv3 credentials, or human judgment -- opens a ServiceNow change request asking a network engineer to act, instead of guessing.
- **Weekly reporting.** A per-device rollup of what was auto-fixed and what's still pending, emailed to a distribution list (or computed on demand via API/UI).
- **Dashboard charts.** A remediation-status pie chart and a 30-day remediation-activity line chart, alongside the existing fleet table.
- **Cisco Meraki firmware compliance.** A second panel checking a Meraki switch fleet's current firmware against the latest available stable release, via the real Meraki Dashboard API.

**Important -- read before testing:** the Cisco IOS/NX-OS side of this prototype ships with a **built-in device simulator** instead of live switches, because this build environment has no network path to real or virtual Cisco hardware. Three simulated switches (legacy/non-compliant, partially-hardened, fully-hardened) are included so the full pipeline -- connect -> retrieve config -> score -> auto-remediate -> re-score -> report -- is real and demonstrable end to end. ServiceNow and the weekly email are simulated the same way (logged in-memory) without real credentials. **The Meraki integration is a real, working API client** -- it only falls back to a simulated fleet because this environment doesn't have a Meraki organization API key; point it at a real one (see below) and it calls the actual Meraki Dashboard API. The architecture is deliberately split so that pointing any of these at the real thing is a config-only change (see [Going to production](#going-to-production)) -- nothing in the scoring engine, routes, or UI needs to change.

---

## Quick start (local)

Requires Python 3.10+.

```bash
git clone <this-repo-url>
cd cis-compliance
pip install -r requirements.txt
python server.py
```

Open **http://localhost:5000**. The dashboard auto-runs an initial scan of the 3 simulated switches on first load -- this also auto-remediates whatever it safely can and opens simulated ServiceNow tickets for the rest. Click any device row to see its full 33-control breakdown, remediation snippets, and remediation history. Use **"Re-scan & remediate fleet now"** to re-pull, re-score, and re-remediate on demand. Use **"Weekly remediation report"** in the top bar to see the per-device rollup that also goes out by email.

> **Why `server.py` and not `app.py`?** The Flask entrypoint is named `server.py` deliberately, not `app.py`, because this project also has a folder named `app/` (containing `device_client.py`, `scoring.py`, `checks/`, etc.). Naming the entrypoint `app.py` creates a name collision with the `app/` package -- `python app.py` happens to work locally, but `gunicorn app:app` (used in Docker/Render deploys) resolves the import to the *folder* instead of the file and fails with `Failed to find attribute 'app' in 'app'`. Keeping the entrypoint as `server.py` avoids the collision everywhere, including in Docker-based deploys.

Run the test suite:

```bash
pip install pytest
pytest tests/ -v
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | Port Flask/Gunicorn binds to |
| `USE_SIMULATOR` | `true` | `false` switches the IOS/NX-OS fleet to real-device mode via Netmiko |
| `FLASK_DEBUG` | `true` | Set `false` in any shared/deployed environment |
| `DEVICE_HOSTS` | _(unset)_ | Comma-separated IPs/hostnames, real-device mode only |
| `DEVICE_USERNAME` / `DEVICE_PASSWORD` / `DEVICE_ENABLE_SECRET` | _(unset)_ | SSH credentials, real-device mode only |
| `AUTO_REMEDIATE` | `true` | `false` reverts to score-only (original read-only) behavior |
| `USE_SERVICENOW_SIMULATOR` | `true` | `false` opens real Change Request records via the ServiceNow Table API |
| `SERVICENOW_INSTANCE` / `SERVICENOW_USERNAME` / `SERVICENOW_PASSWORD` | _(unset)_ | Real ServiceNow instance URL + credentials, real mode only |
| `EMAIL_DISTRIBUTION_LIST` | _(unset)_ | Comma-separated recipient addresses for the weekly report |
| `EMAIL_FROM` | `cis-compliance-console@localhost` | From address for the weekly report |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_USE_TLS` | _(unset)_ / `587` / _(unset)_ / _(unset)_ / `true` | Real SMTP delivery; without these the weekly email is simulated (logged, not sent) |
| `ENABLE_SCHEDULER` | `false` | `true` runs the weekly report automatically every Monday 06:00 UTC, in-process (see caveat below) |
| `USE_MERAKI_SIMULATOR` | `true` | `false` calls the real Meraki Dashboard API |
| `MERAKI_API_KEY` / `MERAKI_ORG_ID` | _(unset)_ | Real Meraki API key + organization ID, real mode only |

---

## Automated remediation & change management

Every scan (initial load or "Re-scan & remediate fleet now") runs each device's failed controls through `app/checks/cis_v8_fixes.py`, which only auto-fixes findings whose correct fix is **fully determined by the config itself** -- no guessing at a real management subnet, syslog/NTP/TACACS+ IP, or SNMPv3 credentials. About two-thirds of the 33 controls qualify (removing default accounts and weak password lines, disabling Telnet/HTTP/legacy services, enabling AAA/logging/BPDU-guard/DHCP-snooping baselines, etc.); the rest -- and anything auto-fixed but not actually resolved on re-check -- get routed to a human.

For every scan, `app/remediation.py`:

1. Pushes each safe fix through `app/device_client.py`'s existing simulator/real seam (`push_remediation()`), the same split used for reading config.
2. Re-runs the rule engine and only counts a fix as applied if the control **actually passes now** -- it never just trusts the fix function blindly.
3. Opens a ServiceNow change request via `app/servicenow_client.py`: one audit-trail CR per device summarizing everything auto-applied that run, and one CR per still-failing finding asking an engineer to act (deduplicated per host+control so an unresolved finding doesn't re-file a ticket on every scan).

`app/servicenow_client.py` follows the same pattern as `app/device_client.py`: `USE_SERVICENOW_SIMULATOR=false` plus `SERVICENOW_INSTANCE`/`SERVICENOW_USERNAME`/`SERVICENOW_PASSWORD` opens real Change Request records via the [Table API](https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI) instead of logging to the in-memory simulated queue.

## Weekly reports & email

`app/reporting.py` aggregates the remediation audit log by device hostname for a trailing window (`GET /reports/weekly` in the UI, `GET /api/weekly-report?days=N` as JSON) -- what was auto-fixed, what's still pending, and which ServiceNow tickets cover each. `app/email_client.py` sends that report to `EMAIL_DISTRIBUTION_LIST` as both HTML and plain text.

Without `SMTP_HOST`/`SMTP_USERNAME`/`SMTP_PASSWORD` set, sends are simulated (logged, not delivered) so the pipeline is demonstrable without a mail server.

**Two ways to run it weekly:**

- **In-process scheduler** (`ENABLE_SCHEDULER=true`): runs every Monday 06:00 UTC via APScheduler. Only safe for a **single-process** deployment (`python server.py`, or gunicorn with `--workers 1`) -- with multiple workers, each one would run its own scheduler and the email would go out once per worker.
- **External trigger** (recommended for Render and other multi-worker or spin-down-capable hosts): point any external scheduler -- a Render [Cron Job](https://render.com/docs/cronjobs), a GitHub Actions scheduled workflow, or a free service like cron-job.org -- at `POST https://<your-app>/api/weekly-report` once a week. This also sidesteps Render's free-tier "spins down when idle" behavior, since an in-process scheduler can't fire while the service is asleep.

## Compliance dashboard charts

The dashboard now includes a remediation-status pie chart (auto-remediated / needs engineer action / attempted-but-unresolved, all time) and a 30-day remediation-activity line chart, both rendered client-side with [Chart.js](https://www.chartjs.org/) from data embedded by the server (`remediation_status_breakdown()` / `remediation_trend()` in `app/reporting.py`, also exposed at `GET /api/remediation-summary`).

## Cisco Meraki firmware compliance

`app/meraki_client.py` checks a Meraki switch fleet's current firmware against the latest available stable release using the real [Meraki Dashboard API v1](https://developer.cisco.com/meraki/api-v1/):

- `GET /organizations/{organizationId}/devices?productTypes[]=switch` -- inventory
- `GET /organizations/{organizationId}/networks` -- network names
- `GET /networks/{networkId}/firmwareUpgrades` -- current version, available versions, and whether an upgrade is available, per network

This is a real, working client -- unlike the IOS/NX-OS fleet, the Meraki Dashboard API is a cloud service, so there's no SSH-reachability problem to simulate around. Set `USE_MERAKI_SIMULATOR=false` plus `MERAKI_API_KEY` and `MERAKI_ORG_ID` to point it at a real Meraki organization; without those it falls back to a small simulated Meraki fleet (one network current, one behind) so the dashboard panel and tests work out of the box.

---

## Deploying it so Treasury can access it

This is a standard Flask + Gunicorn app with no database, so it deploys cleanly to any container or PaaS host. Three options, easiest first:

### Option A -- Render / Railway (recommended for a quick reviewable link)
1. Push this repo to GitHub.
2. Create a new **Web Service** on [Render](https://render.com) (or Railway), pointing at the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn server:app --bind 0.0.0.0:$PORT`
5. Leave `USE_SIMULATOR=true` (default) so the demo works without any real device credentials. Deploy -- you'll get a public `https://*.onrender.com` URL to share.
6. If you want the weekly email running for real, add `EMAIL_DISTRIBUTION_LIST` and the `SMTP_*` env vars in Render's dashboard, and set up a Render Cron Job hitting `POST /api/weekly-report` weekly (see [Weekly reports & email](#weekly-reports--email) -- do **not** set `ENABLE_SCHEDULER=true` here).

### Option B -- Docker (any cloud: ECS, Cloud Run, Azure Container Apps, on-prem)
```bash
docker build -t cis-compliance .
docker run -p 5000:5000 cis-compliance
```
Push the image to your registry of choice and deploy to whatever container host Treasury's environment standardizes on.

### Option C -- Plain VM / on-prem server
```bash
pip install -r requirements.txt
gunicorn server:app --bind 0.0.0.0:8080 --workers 2 --daemon
```
Put it behind whatever reverse proxy / TLS termination your environment requires (nginx, an ALB, F5, etc.) -- the app itself doesn't terminate TLS.

A `Procfile` is included for any Heroku-style buildpack platform as well.

---

## Going to production

Four things separate this prototype from a production-ready internal tool, in priority order:

1. **Point at real IOS/NX-OS devices.** Set `USE_SIMULATOR=false` and provide `DEVICE_USERNAME` / `DEVICE_PASSWORD` (and ideally a TACACS+ service account instead of a shared password) plus a real inventory source. `app/device_client.py` already has working Netmiko paths for both reading (`_fetch_via_netmiko`) and pushing remediation (`_push_via_netmiko`) -- the only missing piece for a real fleet is wiring `_real_inventory_from_env()` to your actual CMDB/NetBox/Nucleus inventory instead of an env var list. No other file changes.
2. **Connect ServiceNow and SMTP for real.** Set `USE_SERVICENOW_SIMULATOR=false` / `SERVICENOW_*` and the `SMTP_*` / `EMAIL_*` vars (see table above). Both already have complete real-mode code paths; the simulators exist purely so the demo runs without those credentials.
3. **Persist scan and remediation history.** Results, the remediation audit log, and the simulated ServiceNow ticket queue currently live in in-memory structures (`_LAST_SCAN` in `server.py`, `_REMEDIATION_LOG`/`_OPEN_MANUAL_TICKETS` in `app/remediation.py`) and reset on restart. Swapping in Postgres/SQLite would take an afternoon and unlocks true historical trend reporting beyond the current process's uptime.
4. **Schedule scans instead of scanning on click/first-load**, and use the external-trigger pattern (not `ENABLE_SCHEDULER=true`) for the weekly email on any multi-worker or spin-down-capable host -- see [Weekly reports & email](#weekly-reports--email).

Smaller hardening items before any real-device use: store device/ServiceNow/SMTP/Meraki credentials in a secrets manager (not env vars) such as Cyberark, which is already in your stack per your resume; add read-only/non-enable SSH accounts dedicated to this tool; rate-limit the `/api/scan` and `/api/weekly-report` endpoints; add auth in front of the dashboard itself (it currently has none, by design, to keep the prototype trivial to demo); consider gating auto-remediation behind a ServiceNow approval step rather than applying-then-recording, if your change process requires pre-approval for network changes.

---

## Approach, tools, and assumptions

### Approach
- **Rule engine over a real config parser.** Each CIS v8 control is a small, independent Python function that regex/line-scans the raw `show running-config` text (`app/checks/cis_v8_rules.py`). This was chosen over a full Cisco config object model (e.g. via `ciscoconfparse`) for transparency: every rule is a few lines you can read top to bottom and audit yourself, which matters more for a compliance tool than parsing elegance. The tradeoff is that rules are closely coupled to common IOS/NX-OS syntax patterns and could be fooled by unusual formatting; see Assumptions below.
- **Simulated device layer with a clean swap point.** `app/device_client.py` is the single seam between simulated and real devices (for both reading config and pushing remediation), so the demo is honest about what's real (the rule engine, scoring, UI, and remediation logic) versus what's standing in for hardware access (the SSH connection itself). The same simulator/real seam pattern is used for ServiceNow (`app/servicenow_client.py`), email (`app/email_client.py`), and Meraki (`app/meraki_client.py` -- though Meraki's real path works without any hardware, since it's a cloud API).
- **Auto-fix only what's fully determined; escalate the rest.** `app/checks/cis_v8_fixes.py` deliberately does not auto-fix findings that need real site-specific values (a management subnet, a syslog/NTP/TACACS+ IP, SNMPv3 passphrases) or human judgment (which interfaces are "untrusted," whether to reduce local admin accounts). Guessing at those would either break connectivity or create a false sense of security -- worse outcomes than asking a human. Every fix is also re-verified against the rule engine after applying, so nothing is ever reported as fixed without actually re-checking.
- **Severity-weighted scoring**, not a flat pass-count percentage. A device failing one `high`-severity control (e.g. default SNMP community string) and passing 32 `low`-severity ones should not look "97% compliant" -- the weighted score (high=5, medium=3, low=1) reflects that.
- **CLI-native UI.** The dashboard is styled deliberately close to a terminal/NOC console (monospace control IDs, evidence rendered as raw config-text snippets, remediation shown as literal CLI you could paste into a device) rather than a generic SaaS dashboard look, since the audience is network engineers, not executives.

### Tools used
- **Python 3.12 / Flask 3** -- backend and server-rendered dashboard (Jinja2 templates, no SPA framework -- kept deliberately simple for a prototype with no complex client state).
- **Netmiko** -- the real-device SSH path (`app/device_client.py`), industry-standard for Cisco IOS/NX-OS automation, matching the Python/Cisco automation pattern already in your resume's GitHub-agent and IOS/NX-OS upgrade work.
- **Chart.js** (CDN) -- the dashboard's remediation pie/line charts.
- **requests** -- the real-mode ServiceNow Table API and Meraki Dashboard API clients.
- **APScheduler** -- optional in-process weekly-report scheduling (see caveats above).
- **Gunicorn** -- production WSGI server for deployment.
- **pytest** -- automated test suite (`tests/`) covering rule correctness, scoring math, auto-remediation logic, weekly reporting, and the ServiceNow/Meraki/email simulators, against three representative sample configs.
- **No external JS framework / no database** -- kept the prototype's dependency footprint minimal so it's auditable and trivially deployable; see [Going to production](#going-to-production) for what a non-prototype version would add.

### Assumptions
- **CIS v8 mapping is interpretive, not an official CIS publication.** CIS Controls v8 is platform-agnostic (covers people/process/technology broadly); the Cisco-specific implementation of each Safeguard here (e.g. "Safeguard 4.4 -> disable Telnet, enforce SSHv2, require an access-class ACL on VTY") reflects a reasonable, defensible reading of the control intent applied to switch configuration, consistent with how CIS's own benchmark documents (e.g. the CIS Cisco IOS Benchmark) operationalize the controls -- but it is this project's interpretation, not a verbatim CIS document.
- **Config text is plain, unencrypted `show running-config` output.** The rules assume standard IOS/NX-OS syntax conventions (e.g. `username <name> secret <type> <hash>`). Heavily customized config templates, third-party NAC overlays, or non-Cisco syntax (Aruba, HP H3C, also in your stack) are out of scope for this prototype's rule engine, though the same architecture (rules operating on text, behind a device-client seam) would extend to them with a separate rule set.
- **Auto-remediates what's safe; escalates the rest -- it doesn't invent site-specific values.** The tool pushes fixes immediately for findings it can resolve with no guesswork, and opens a ServiceNow change request for a human on everything else, including anything it attempted but that didn't actually resolve on re-check. It never pushes a placeholder management-subnet ACL, syslog/NTP/TACACS+ IP, or SNMPv3 credential -- those need real values only a human has. Given the same review pattern you already use for change-script approval, teams that require pre-approval (rather than apply-then-record) for network changes should gate the auto-apply step behind a ServiceNow approval instead, as noted in [Going to production](#going-to-production).
- **Simulated fleet of 3 (IOS/NX-OS) + 3 (Meraki) is a representative sample, not a complete demo of scale.** The scoring/rendering/remediation logic does not assume a fleet size and was sanity-checked conceptually against a fleet on the order of your resume's 4,200+ devices, but only a handful of simulated switches are included to keep the prototype's footprint small; `app/device_client.py`'s `list_inventory()` and `app/meraki_client.py`'s simulated fleet are the only places fleet size is determined.

---

## Continuous integration

Every push and pull request runs `.github/workflows/ci.yml`, which:

1. **Tests** the rule engine, scoring, auto-remediation, reporting, and the ServiceNow/Meraki/email simulators (`pytest tests/`) on Python 3.10, 3.11, and 3.12.
2. **Lints** for actual errors (undefined names, syntax issues) -- not style nitpicks, to keep the gate meaningful rather than noisy.
3. **Verifies control coverage** programmatically (fails the build if the rule count ever drops below 25, so a future refactor can't silently shrink coverage).
4. **Boots the app** in simulator mode and hits `/healthz`, `/`, `/api/controls`, `/api/reports`, `/api/remediations`, `/api/remediation-summary`, `/api/meraki-compliance`, `/api/weekly-report`, and `/reports/weekly` as a real smoke test -- catching template/route-wiring breaks that unit tests alone wouldn't.
5. **Builds the Docker image** to catch packaging issues before they reach a deploy.

Replace `<your-org>/<your-repo>` in the badge URL above once this is pushed to GitHub.

---

## Project structure

```
cis-compliance/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions: tests, lint, smoke test, Docker build
├── server.py                    # Flask entrypoint, routes, in-memory scan cache, optional scheduler
├── app/
│   ├── checks/
│   │   ├── cis_v8_rules.py     # 33 CIS v8 control checks (the core logic)
│   │   └── cis_v8_fixes.py     # Auto-remediation patch functions + auto/manual routing
│   ├── device_client.py        # Simulator <-> real-device (Netmiko) seam; read + push remediation
│   ├── remediation.py          # Orchestrates auto-fix -> re-check -> ServiceNow -> audit log
│   ├── servicenow_client.py    # Simulator <-> real ServiceNow Table API seam
│   ├── reporting.py            # Weekly report aggregation + dashboard chart data
│   ├── email_client.py         # Simulator <-> real SMTP seam for the weekly report
│   ├── meraki_client.py        # Real Meraki Dashboard API client (+ simulated fleet fallback)
│   ├── scoring.py              # Per-device + fleet-wide scoring/aggregation
│   ├── templates/               # Jinja2 dashboard, device-detail, and weekly-report views
│   └── static/css/style.css    # NOC-console design system
├── simulator/
│   ├── mock_device.py          # Simulated SSH/device interface + in-memory live config
│   └── sample_configs/         # 3 realistic IOS configs (legacy/partial/hardened)
├── tests/
│   ├── conftest.py              # Shared fixtures: reset in-memory state between tests
│   ├── test_cis_rules.py       # Rule engine + scoring tests
│   ├── test_remediation.py     # Auto-fix + orchestration tests
│   ├── test_reporting.py       # Weekly report / chart data tests
│   ├── test_servicenow_client.py
│   ├── test_meraki_client.py
│   └── test_email_client.py
├── requirements.txt
├── Procfile                     # Heroku/Railway-style deploy
├── Dockerfile                    # Container deploy
└── README.md
```

---

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard -- fleet summary, device table, remediation charts, Meraki panel |
| `/device/<host>` | GET | Per-device control breakdown + remediation history |
| `/reports/weekly` | GET | Weekly remediation report page (`?days=N`, default 7) |
| `/api/reports` | GET | JSON: full last-scan data (all devices, all controls) |
| `/api/controls` | GET | JSON: list of all 33 controls this tool checks, with CIS mapping |
| `/api/scan` | POST | Trigger a fresh pull, re-score, and auto-remediation pass of the entire fleet |
| `/api/remediations` | GET | JSON: full remediation audit log (`?host=<ip>` to filter) |
| `/api/remediation-summary` | GET | JSON: pie (status breakdown) + line (30-day trend) chart data |
| `/api/weekly-report` | GET / POST | GET returns the report as JSON; POST computes it and sends the email now |
| `/api/meraki-compliance` | GET | JSON: Meraki switch fleet firmware compliance |
| `/healthz` | GET | Liveness check |

---

## Control coverage summary

33 controls across 8 CIS v8 Safeguard families: Account Management (5), Access Control Management (8), AAA/Authentication (4), Network Monitoring/SNMP (3), Audit Log Management (4), Network Infrastructure Management (6), segmentation hardening adjacent to Malware Defense intent (2 -- DHCP snooping/DAI), and Security Awareness (1 -- login banner). Run `GET /api/controls` for the full machine-readable list with descriptions. Roughly two-thirds of these are auto-remediable out of the box; run `python -c "from app.checks.cis_v8_fixes import AUTO_REMEDIABLE; print(sorted(AUTO_REMEDIABLE))"` for the current list.
