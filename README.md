# CIS v8 Network Compliance Console

A fleet-wide dashboard that pulls Cisco IOS / NX-OS switch configurations, scores them against **33 controls** mapped to **CIS Controls v8**, **automatically remediates** what it safely can, opens **ServiceNow** change requests for the audit trail (and for anything that needs a human), emails a **weekly remediation report** to a distribution list, charts remediation progress, and checks a **Cisco Meraki** switch fleet against the latest available firmware.

![status](https://img.shields.io/badge/status-prototype-blue) ![python](https://img.shields.io/badge/python-3.12-blue) ![flask](https://img.shields.io/badge/flask-3.0-black)
[![CI](https://github.com/<your-org>/<your-repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-org>/<your-repo>/actions/workflows/ci.yml)

---

## What this is

A working prototype of a configuration-compliance-and-remediation tool: it connects to a fleet of switches, retrieves `show running-config`, runs it through a rule engine covering 8 CIS v8 control families, **fixes what it safely can immediately**, opens a ServiceNow change request either as an audit record of what was just fixed or as a request for an engineer to make a change this tool won't guess at, and renders a NOC-style dashboard with a fleet summary, per-control evidence/remediation, a remediation-status pie chart, a 30-day remediation-activity line chart, and a Meraki firmware-compliance panel.

**Important — read before testing:** this prototype ships with a **built-in device simulator** instead of live switches, because this build environment has no network path to real or virtual Cisco hardware. Three simulated switches (legacy/non-compliant, partially-hardened, fully-hardened) are included so the full pipeline — connect → retrieve config → score → remediate → open change request → render — is real and demonstrable end to end. The same simulator/real seam pattern is used for ServiceNow and email delivery, so the whole pipeline is demonstrable without a real ServiceNow instance, mail server, or distribution list. The architecture is deliberately split so that pointing this at **real devices, a real ServiceNow instance, and a real mail server is a config-only change** (see [Going to production](#going-to-production) below); nothing in the scoring, remediation, reporting, or UI logic needs to change.

---

## Quick start (local)

Requires Python 3.10+.

```bash
git clone <this-repo-url>
cd cis-compliance
pip install -r requirements.txt
python server.py
```

Open **http://localhost:5000**. The dashboard auto-runs an initial scan of the 3 simulated switches on first load, and — because `AUTO_REMEDIATE` defaults to `true` — immediately fixes whatever it safely can and opens simulated ServiceNow change requests for everything else. Click any device row to see its full 33-control breakdown, remediation snippets, and remediation history. Use **"Re-scan & remediate fleet now"** to re-pull, re-fix, and re-score on demand.

The **Remediation Overview** pie/line charts are populated automatically at startup (see [Demo data is seeded automatically at startup](#demo-data-is-seeded-automatically-at-startup)) — they should never look empty, including right after a fresh deploy or a Render free-tier cold start.

> **Why `server.py` and not `app.py`?** The Flask entrypoint is named `server.py` deliberately, not `app.py`, because this project also has a folder named `app/` (containing `device_client.py`, `scoring.py`, `checks/`, etc.). Naming the entrypoint `app.py` creates a name collision with the `app/` package — `python app.py` happens to work locally, but `gunicorn app:app` (used in Docker/Render deploys) resolves the import to the *folder* instead of the file and fails with `Failed to find attribute 'app' in 'app'`. Keeping the entrypoint as `server.py` avoids the collision everywhere, including in Docker-based deploys.

Run the test suite:

```bash
pip install pytest
pytest tests/ -v
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | Port Flask/Gunicorn binds to |
| `USE_SIMULATOR` | `true` | `false` switches the device fleet to real-device mode via Netmiko |
| `AUTO_REMEDIATE` | `true` | `false` reverts to score-only (read-only) behavior, no config pushes |
| `AUTO_SEED_DEMO_DATA` | `true` | `false` disables automatic demo-data seeding at startup (see below) |
| `FLASK_DEBUG` | `true` | Set `false` in any shared/deployed environment |
| `DEVICE_HOSTS` | _(unset)_ | Comma-separated IPs/hostnames, real-device mode only |
| `DEVICE_USERNAME` / `DEVICE_PASSWORD` / `DEVICE_ENABLE_SECRET` | _(unset)_ | SSH credentials, real-device mode only |
| `USE_SERVICENOW_SIMULATOR` | `true` | `false` opens real change requests via the ServiceNow Table API |
| `SERVICENOW_INSTANCE` / `SERVICENOW_USERNAME` / `SERVICENOW_PASSWORD` | _(unset)_ | ServiceNow REST credentials, real mode only |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_USE_TLS` | _(unset)_ | SMTP credentials for real weekly-report email delivery |
| `EMAIL_FROM` | `cis-compliance-console@localhost` | Sender address for the weekly report email |
| `EMAIL_DISTRIBUTION_LIST` | _(unset)_ | Comma-separated recipient list for the weekly report |
| `ENABLE_SCHEDULER` | `false` | `true` runs an in-process weekly-email scheduler (single-worker deployments only — see [Weekly reports & email](#weekly-reports--email)) |
| `USE_MERAKI_SIMULATOR` | `true` | `false` calls the real Meraki Dashboard API |
| `MERAKI_API_KEY` / `MERAKI_ORG_ID` | _(unset)_ | Meraki Dashboard API credentials, real mode only |

---

## Automated remediation & change management

Every scan (initial load, manual "Re-scan" click, or a scheduled `POST /api/scan`) does the following for each device, when `AUTO_REMEDIATE=true` (the default):

1. **Score** the current config against all 33 CIS v8 controls.
2. For every **failed** control, check whether `app/checks/cis_v8_fixes.py` has a safe, fully-determined fix — one that doesn't require guessing a real subnet, IP, or credential. If so, push it immediately (via the same simulator/real seam used for reading config) and **re-check the control afterward**. It's only ever reported as fixed if it actually passes now — a fix is never blindly trusted.
3. Open a **ServiceNow change request** for the outcome:
   - Auto-fixed findings get **one batch change request** per device scan, as an audit record of what was already applied (state `Implement`).
   - Findings with no safe automated fix — or where a fix was attempted but didn't resolve the issue — get **one change request each**, asking a network engineer to make the change. These are deduplicated per `(host, control_id)` so a still-open finding doesn't re-file a ticket on every scan; once it's resolved, the dedup entry is cleared so a future regression opens a fresh ticket.
4. Log the action (auto-fixed or pending) in an in-memory audit trail used by the weekly report and the dashboard charts.

**~22 of the 33 controls are auto-remediable** (e.g. enable secret, weak local passwords, default accounts, Telnet, SSHv1, exec-timeout, HTTP server, AAA new-model, default SNMP community strings, unused/native VLAN hygiene, BPDU guard, DHCP snooping, proxy ARP, source routing, small servers, password encryption service, login banner). The remaining ~11 (hostname naming, VTY management ACLs, centralized AAA/syslog/NTP server IPs, SNMPv3 credentials, real VLAN assignment, Dynamic ARP Inspection scoping, CDP trust boundaries) are **deliberately left to a human** — `app/checks/cis_v8_fixes.py`'s `MANUAL_REVIEW_REASON` dict explains why for each one, and that reason is shown on the change request and in the dashboard so "needs a human" never reads as "nothing happened."

Set `AUTO_REMEDIATE=false` to revert to the original score-only, read-only behavior.

---

## Weekly reports & email

`GET /reports/weekly` (or `?days=30` / `?days=90`) shows a per-device rollup of what was auto-fixed and what's still pending, with change request numbers, styled to match the dashboard.

`GET /api/weekly-report` returns the same data as JSON. `POST /api/weekly-report` computes it **and sends the email** to `EMAIL_DISTRIBUTION_LIST` — this is the endpoint an external scheduler should call weekly. This tool intentionally does **not** default to an in-process scheduler: with multiple Gunicorn workers (the Docker/Render default), each worker would send its own copy of the email. Two supported ways to run it on a schedule:

- **Recommended — external scheduler.** A Render Cron Job (or GitHub Actions scheduled workflow, or `cron-job.org`) hitting `POST https://<your-app>/api/weekly-report` once a week. This works correctly regardless of worker count and survives Render free-tier spin-down (the cron job itself wakes the service).
- **Single-process deployments only.** Set `ENABLE_SCHEDULER=true` *and* run with a single worker (`python server.py`, or `gunicorn server:app --workers 1`) to use the built-in APScheduler job (Mondays 06:00 UTC). Do **not** combine this with `--workers 2+` — see the warning in `server.py`.

Without `SMTP_HOST`/`SMTP_USERNAME`/`SMTP_PASSWORD` configured, sends are logged in-memory instead of actually delivered (`mode: "simulated"` in the response), so the pipeline is demonstrable without a real mailbox.

---

## Remediation charts & demo data seeding

The dashboard's **Remediation Overview** section shows:
- A **pie chart** of all-time remediation status (auto-fixed / needs engineer action / attempted-but-unresolved).
- A **30-day line chart** of daily auto-fixed vs. pending-action counts.

Both are fed by `GET /api/remediation-summary`, which reads an in-memory log that starts empty until either a real scan-and-remediate cycle runs, or demo data is seeded (see immediately below).

### Demo data is seeded automatically at startup

`AUTO_SEED_DEMO_DATA` (default `true`, simulator-only) backfills 30 days of clearly-labeled synthetic remediation history **the moment the app process boots**, so the charts are never empty — no button click required.

This matters more than it sounds like it should, for two reasons that both bit this exact feature in testing:

1. **Multiple Gunicorn workers.** The Dockerfile/Procfile run `--workers 2`, and this app's remediation log is a plain in-memory Python list — each worker process has its own separate copy. A single `POST /api/seed-demo-data` click only reaches whichever one worker handles that request; a page load that happens to land on the *other* worker still sees an empty log and an empty chart. This is the actual reason the charts could still look empty after clicking "Seed" on a real deployment.
2. **Render's free tier spins down** after inactivity, and the next request cold-starts a brand-new process with an empty log again.

Seeding at **import time** (i.e., once per worker process, as soon as it starts) means every worker has data from its very first request, regardless of which worker a given request lands on — verified by booting the app with `gunicorn --workers 2` (matching the Dockerfile exactly) and confirming `/api/remediation-summary` returns identical non-empty data across ten round-robined requests with no manual seeding step at all.

Real scan-and-remediate activity (from `AUTO_REMEDIATE`) is layered on top of the seeded data the same way it always was. Seeded rows stay clearly tagged `[DEMO]` in their note field and use `CHG-DEMO-####` ticket numbers everywhere in the UI, so they're never confused with a real remediation event or a real ServiceNow ticket, and never touch actual device config or the real ServiceNow ticket queue. A banner appears on the dashboard whenever demo data is present. If a real 7/30/90-day weekly report or email is generated while demo data is present, it will include the demo rows too (visible via their `CHG-DEMO-####` ticket numbers in that table) — clear demo data first if you want a weekly report that reflects only real activity.

You can still seed or top up manually:

```
POST /api/seed-demo-data?days=30
```

(also available as the **"Seed 30 days of demo history"** button on the dashboard, which appears when there's no data at all — e.g. if `AUTO_SEED_DEMO_DATA=false`). Remove all seeded data with:

```
POST /api/clear-demo-data
```

which strips only the `[DEMO]`-tagged records and leaves any real remediation history untouched. Both endpoints — and the startup auto-seed — are simulator-only (`USE_SIMULATOR=true`) and return `403` (or no-op) otherwise, since seeding fake history against a real fleet's audit trail would be actively misleading. Set `AUTO_SEED_DEMO_DATA=false` if you'd rather the charts start genuinely empty until a real scan runs.

---

## Cisco Meraki firmware compliance

The dashboard's **Cisco Meraki Fleet** panel and `GET /api/meraki-compliance` check a Meraki-managed switch fleet against the latest available stable firmware, using the real Meraki Dashboard API v1:

```
GET /organizations/{organizationId}/devices?productTypes[]=switch
GET /organizations/{organizationId}/networks
GET /networks/{networkId}/firmwareUpgrades
```

Unlike the IOS/NX-OS fleet (which needs real SSH-reachable switches this environment can't provide), the Meraki Dashboard API is a cloud service, so this is a **genuine, working integration** — set `USE_MERAKI_SIMULATOR=false` plus `MERAKI_API_KEY` and `MERAKI_ORG_ID` (a Dashboard API key with org read access) to run it against a real Meraki organization. Without those, it falls back to a small simulated Meraki fleet (2 networks, one already current, one with an upgrade available) so the panel and tests work out of the box.

---

## Deploying it so others can access it

This is a standard Flask + Gunicorn app with no database, so it deploys cleanly to any container or PaaS host. Three options, easiest first:

### Option A — Render / Railway (recommended for a quick reviewable link)
1. Push this repo to GitHub.
2. Create a new **Web Service** on [Render](https://render.com) (or Railway), pointing at the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn server:app --bind 0.0.0.0:$PORT`
5. Leave `USE_SIMULATOR=true`, `USE_SERVICENOW_SIMULATOR=true`, `USE_MERAKI_SIMULATOR=true` (defaults) so the demo works without any real credentials. Deploy — you'll get a public `https://*.onrender.com` URL to share.
6. Optional: add a Render **Cron Job** hitting `POST /api/weekly-report` weekly. The charts populate themselves automatically on every deploy/cold start (`AUTO_SEED_DEMO_DATA=true` by default) — no manual step needed.

### Option B — Docker (any cloud: ECS, Cloud Run, Azure Container Apps, on-prem)
```bash
docker build -t cis-compliance .
docker run -p 5000:5000 cis-compliance
```
Push the image to your registry of choice and deploy to whatever container host your environment standardizes on.

### Option C — Plain VM / on-prem server
```bash
pip install -r requirements.txt
gunicorn server:app --bind 0.0.0.0:8080 --workers 2 --daemon
```
Put it behind whatever reverse proxy / TLS termination your environment requires (nginx, an ALB, F5, etc.) — the app itself doesn't terminate TLS.

A `Procfile` is included for any Heroku-style buildpack platform as well.

---

## Going to production

Four things separate this prototype from a production-ready internal tool, in priority order:

1. **Point at real devices.** Set `USE_SIMULATOR=false` and provide `DEVICE_USERNAME` / `DEVICE_PASSWORD` (and ideally a TACACS+ service account instead of a shared password) plus a real inventory source. `app/device_client.py` already has working Netmiko paths for both reading config (`_fetch_via_netmiko`) and pushing remediation (`_push_via_netmiko`) — the only missing piece for a real fleet is wiring `_real_inventory_from_env()` to your actual CMDB/NetBox inventory instead of an env var list. No other file changes.
2. **Point at a real ServiceNow instance and real SMTP.** Set `USE_SERVICENOW_SIMULATOR=false` with `SERVICENOW_INSTANCE`/`SERVICENOW_USERNAME`/`SERVICENOW_PASSWORD`, and set the `SMTP_*` variables plus `EMAIL_DISTRIBUTION_LIST`. Both already have working REST/SMTP paths; only credentials are missing.
3. **Persist scan and remediation history.** Results and the remediation audit log currently live in in-memory structures (`_LAST_SCAN` in `server.py`, `_REMEDIATION_LOG` in `app/remediation.py`) and reset on restart. Swapping in Postgres/SQLite would take an afternoon and unlocks real trend-over-time reporting beyond the current 30-day in-memory window — and removes the need for the demo-data-seeding feature entirely.
4. **Schedule scans instead of scanning on click.** A cron job or Celery beat task calling `_run_full_scan()` every N hours, rather than relying on a manual "Re-scan" button or first-page-load, matches how a real compliance-and-remediation tool should run. Pair this with the external-scheduler approach for `POST /api/weekly-report` described above.

Smaller hardening items before any real-device use: store device/ServiceNow/SMTP credentials in a secrets manager (not env vars); add read-only vs. write-capable SSH accounts as appropriate (the account used for `push_remediation` needs enable/config-mode access, unlike a read-only scoring pass); rate-limit `/api/scan` and the auto-remediation path so a scripted bulk trigger can't hammer the fleet; add auth in front of the dashboard itself (it currently has none, by design, to keep the prototype trivial to demo); consider gating auto-remediation behind an approval step for `high`-severity findings even though this tool re-verifies every fix, since a compliance tool that changes production config unattended is a bigger blast radius than a read-only one.

---

## Approach, tools, and assumptions

### Approach
- **Rule engine over a real config parser.** Each CIS v8 control is a small, independent Python function that regex/line-scans the raw `show running-config` text (`app/checks/cis_v8_rules.py`). This was chosen over a full Cisco config object model (e.g. via `ciscoconfparse`) for transparency: every rule is a few lines you can read top to bottom and audit yourself, which matters more for a compliance tool than parsing elegance.
- **A fix is only ever "auto-remediated" if it re-verifies.** `app/remediation.py` never reports a control as fixed just because a patch function ran — it re-fetches the config and re-runs the check afterward, and only marks it resolved if it now actually passes. This also catches cases where fixing one control incidentally resolves a different one (e.g. clearing default SNMP community strings can satisfy both CIS-4.8 and CIS-4.10).
- **Never guess at site-specific values.** `app/checks/cis_v8_fixes.py` deliberately has no fix function for controls whose correct value depends on real infrastructure this tool has no way to know (a management subnet CIDR, a TACACS+/syslog/NTP server IP, SNMPv3 credentials, a real VLAN plan). Those are routed to a ServiceNow change request for a human, with the specific reason documented, rather than writing a plausible-looking but potentially wrong or insecure value.
- **Simulated integration layers with a clean swap point.** `app/device_client.py`, `app/servicenow_client.py`, and `app/email_client.py` each follow the same simulator/real seam, so the demo is honest about what's real (the rule engine, remediation logic, scoring, and UI) versus what's standing in for external systems this environment can't reach.
- **Severity-weighted scoring**, not a flat pass-count percentage. A device failing one `high`-severity control and passing 32 `low`-severity ones should not look "97% compliant" — the weighted score (high=5, medium=3, low=1) reflects that.
- **CLI-native UI.** The dashboard is styled deliberately close to a terminal/NOC console (monospace control IDs, evidence rendered as raw config-text snippets, remediation shown as literal CLI) rather than a generic SaaS dashboard look, since the audience is network engineers, not executives.

### Tools used
- **Python 3.12 / Flask 3** — backend and server-rendered dashboard (Jinja2 templates, no SPA framework — kept deliberately simple).
- **Netmiko** — the real-device SSH path, both for reading config and for pushing remediation (`app/device_client.py`).
- **Chart.js** (via CDN) — the dashboard's remediation-status pie chart and 30-day trend line chart.
- **Gunicorn** — production WSGI server for deployment.
- **APScheduler** — optional in-process weekly-email scheduler for single-worker deployments.
- **requests** — real ServiceNow Table API and Meraki Dashboard API calls.
- **pytest** — automated test suite covering rule correctness, scoring, remediation orchestration, ServiceNow ticketing, email delivery, Meraki compliance, and demo-data seeding.
- **No external JS framework / no database** — kept the prototype's dependency footprint minimal so it's auditable and trivially deployable; see [Going to production](#going-to-production) for what a non-prototype version would add.

### Assumptions
- **CIS v8 mapping is interpretive, not an official CIS publication.** CIS Controls v8 is platform-agnostic; the Cisco-specific implementation of each Safeguard here reflects a reasonable, defensible reading of the control intent applied to switch configuration, consistent with how CIS's own benchmark documents operationalize the controls — but it is this project's interpretation, not a verbatim CIS document.
- **Config text is plain, unencrypted `show running-config` output.** The rules and fix functions assume standard IOS/NX-OS syntax conventions. Heavily customized config templates or non-Cisco syntax are out of scope for this prototype's rule/fix engines, though the same architecture would extend to them with a separate rule set.
- **Auto-remediation is scoped to what's safely determinable from the config alone.** This is a deliberate, conservative line, not a technical limitation — the ~11 controls left to a human all require real infrastructure values or topology judgment this tool has no way to know, and guessing would be worse than asking.
- **Simulated fleet of 3 IOS/NX-OS switches (+3 simulated Meraki switches) is a representative sample, not a complete demo of scale.** The scoring/remediation/rendering logic does not assume a fleet size; `app/device_client.py`'s `list_inventory()` and `app/meraki_client.py`'s simulated fleet are the only places size is determined.

---

## Continuous integration

Every push and pull request runs `.github/workflows/ci.yml`, which:

1. **Tests** the rule engine, scoring, remediation orchestration, ServiceNow client, email client, Meraki client, and demo-data seeding (`pytest tests/`) on Python 3.10, 3.11, and 3.12.
2. **Lints** for actual errors (undefined names, syntax issues) — not style nitpicks, to keep the gate meaningful rather than noisy.
3. **Verifies control coverage** programmatically (fails the build if the rule count ever drops below 25).
4. **Boots the app** in simulator mode and hits every route and API endpoint, including the two new demo-data-seeding endpoints, as a real smoke test — catching template/route-wiring breaks that unit tests alone wouldn't.
5. **Builds the Docker image** to catch packaging issues before they reach a deploy.

Replace `<your-org>/<your-repo>` in the badge URL above once this is pushed to GitHub.

---

## Project structure

```
cis-compliance/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions: tests, lint, smoke test, Docker build
├── server.py                    # Flask entrypoint, routes, in-memory scan cache, remediation flow
├── app/
│   ├── checks/
│   │   ├── cis_v8_rules.py     # 33 CIS v8 control checks (the core scoring logic)
│   │   └── cis_v8_fixes.py     # Auto-remediation config-patch functions, ~22 controls
│   ├── device_client.py        # Simulator <-> real-device (Netmiko) seam; read + push config
│   ├── servicenow_client.py    # Simulator <-> real ServiceNow Table API seam
│   ├── email_client.py         # Simulator <-> real SMTP seam for the weekly report email
│   ├── meraki_client.py        # Real Cisco Meraki Dashboard API client (+ simulated fallback)
│   ├── remediation.py          # Remediation orchestration, audit log, demo-data seeding
│   ├── reporting.py            # Weekly report aggregation + chart data feeds
│   ├── scoring.py              # Per-device + fleet-wide scoring/aggregation
│   ├── templates/               # Jinja2 dashboard, device-detail, and weekly-report views
│   └── static/css/style.css    # NOC-console design system
├── simulator/
│   ├── mock_device.py          # Simulated SSH/device interface, with mutable "live" config
│   └── sample_configs/         # 3 realistic IOS configs (legacy/partial/hardened)
├── tests/
│   ├── conftest.py              # Shared autouse fixture resetting all in-memory state
│   ├── test_cis_rules.py
│   ├── test_remediation.py
│   ├── test_reporting.py
│   ├── test_servicenow_client.py
│   ├── test_email_client.py
│   └── test_meraki_client.py
├── requirements.txt
├── Procfile                     # Heroku/Railway-style deploy
├── Dockerfile                    # Container deploy
└── README.md
```

---

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard — fleet summary, device table, remediation charts, Meraki panel |
| `/device/<host>` | GET | Per-device control breakdown + remediation history |
| `/reports/weekly` | GET | Weekly remediation report page (`?days=7\|30\|90`) |
| `/api/reports` | GET | JSON: full last-scan data (all devices, all controls) |
| `/api/controls` | GET | JSON: list of all 33 controls this tool checks, with CIS mapping |
| `/api/scan` | POST | Trigger a fresh pull + auto-remediate + re-score of the entire fleet |
| `/api/remediations` | GET | JSON: full remediation audit log (optional `?host=` filter) |
| `/api/remediation-summary` | GET | JSON: pie + 30-day trend data for the dashboard charts |
| `/api/weekly-report` | GET / POST | GET returns the report as JSON; POST also sends the email |
| `/api/meraki-compliance` | GET | JSON: Meraki switch fleet vs. latest firmware |
| `/api/seed-demo-data` | POST | Backfill 30 days of clearly-labeled synthetic remediation history (simulator only, `?days=`) |
| `/api/clear-demo-data` | POST | Remove only the synthetic `[DEMO]`-tagged records |
| `/healthz` | GET | Liveness check |

---

## Control coverage summary

33 controls across 8 CIS v8 Safeguard families: Account Management (5), Access Control Management (8), AAA/Authentication (4), Network Monitoring/SNMP (3), Audit Log Management (4), Network Infrastructure Management (6), segmentation hardening adjacent to Malware Defense intent (2 — DHCP snooping/DAI), and Security Awareness (1 — login banner). Run `GET /api/controls` for the full machine-readable list with descriptions. ~22 of the 33 are auto-remediable; see [Automated remediation & change management](#automated-remediation--change-management) for which and why.
