# VM Tracker

Local-first vulnerability management tracker for a weekly scan-and-close workflow:
ingest scan exports, classify findings by type, track ageing and closure against
SLA, and report by department, application, system owner and environment.

FastAPI + SQLite backend serving a vanilla-JS operator console. No cloud service,
no external CDN — it runs on one machine and is reachable across your LAN.

## Quick start

```bash
python -m pip install -r requirements.txt
python run.py                       # http://127.0.0.1:9797
```

Sign in with **`admin` / `admin`**. The console then requires you to set your own
password before anything else is reachable — no page, export or API call works
until you do. After that, load a scan from **Scan imports**.

To choose a different bootstrap password, set `VM_TRACKER_ADMIN_PASSWORD` before
the very first start; it still forces a change at first sign-in.

To try it with the bundled synthetic bank data, import in this order from the
console: `samples/scan_week1.csv`, then `samples/scan_week2.csv`, then
`samples/mitigations.xlsx` with the file type set to "Mitigation / remediation
evidence". Regenerate the samples any time with `python samples/gen_samples.py`.

## Tests

```bash
python -m pytest tests -q                    # 101 tests
python -m pytest tests -q -k "not test_ui"   # skip the browser tests
```

The UI tests drive a real headless browser. They skip themselves unless you have
`pip install playwright && python -m playwright install chromium`.

## Console

| Page | What it's for |
|---|---|
| **Executive view** | Risk-score trend as the headline, with SLA breach rate, MTTR and open critical/high alongside. Severity donut, SLA gauges, ageing profile, ownership breakdowns, widest-spread vulnerabilities. |
| **Vulnerability register** | The full filtered table. Click a dashed cell to edit in place; click a row for the record with its full history. Bulk-update selected rows or everything matching the filter. |
| **Department / Application / System owner / Environment / Vulnerability type** | Five grouped dashboards, each with a scorecard, a group × type heat matrix, ageing table and trend. Click a scorecard row to drill into the register for that group. |
| **Hosts & ownership** | Edit hostname, department, application, owner, environment, criticality, location. Edits are pinned so scan imports never overwrite them. Bulk-assign ownership across a filter. |
| **Scan imports** | Drop a file, preview the column mapping, then import. Full import history showing what each scan opened, reopened and closed. |
| **Settings** | SLA targets per severity, the classification rule engine, user accounts and password resets, background jobs and the watch folder, display/text size, and the audit log. |

Every page carries the same filter bar, and every export reflects whatever filter
is applied. Filter sets can be saved and reloaded by name.

## Paths and settings

| What | Value |
|---|---|
| Data dir (Windows) | `%LOCALAPPDATA%\VM Tracker` |
| Data dir (macOS/Linux) | `~/.VM Tracker` |
| Override | `VM_TRACKER_DATA_DIR` (the literal `VM Tracker_DATA_DIR` is also honoured) |
| Database | `<data dir>/vmtracker.db` (SQLite, WAL) |
| Watch folder | `<data dir>/watch` by default; changeable in **Settings → Background jobs** |
| Port / host | `9797` / `0.0.0.0` — override with `VM_TRACKER_PORT`, `VM_TRACKER_HOST` |
| Admin password (first run) | `admin`, or set `VM_TRACKER_ADMIN_PASSWORD` |

Reachable from other machines at `http://<server-ip>:9797/`. Open the port first:

```
netsh advfirewall firewall add rule name="VM Tracker" dir=in action=allow protocol=TCP localport=9797
```

Interactive API docs: `http://127.0.0.1:9797/api/docs`

## Users and roles

| Role | Can |
|---|---|
| `viewer` | read every dashboard, filter, export |
| `analyst` | the above, plus import scans and edit findings and ownership |
| `admin` | the above, plus manage users, SLA targets, classification rules and jobs |

Passwords are PBKDF2-SHA256, 200,000 rounds, minimum 8 characters. Sessions last
12 hours; the browser uses a cookie, API and mobile clients send `X-VMT-Token`.

**Resetting a password.** In **Settings → Users**, *Reset password* against any
account either takes a password you type or generates one and shows it once. The
account is signed out of every session and must choose its own password at the
next sign-in. The reset is written to the audit log against your username.

If you lock yourself out of the only admin account, reset it from a shell with the
server stopped:

```bash
python -c "from app import db, auth; db.init_db(); u=db.q1(\"SELECT id FROM users WHERE username='admin'\"); auth.set_password(u['id'],'NewPassword123', must_change=1)"
```

## Data model

- **assets** — one row per host. Ownership columns are editable; edited fields are
  recorded in `manual_fields` and skipped by future imports.
- **vulns** — one row per unique vulnerability, carrying its classification
  (category, sub-type, confidence, which rule fired).
- **findings** — one row per (asset, vulnerability, port). The tracked unit:
  status, first/last detected, age, due date, SLA breach flag, risk score.
- **finding_events** / **audit_log** — why a status changed, and who changed what.
- **scans** — every import with its row counts and outcome.

Schema changes go through `ensure_table` / `ensure_column`, which check
`PRAGMA table_info` before any `ALTER TABLE`. Nothing is ever dropped, so
upgrading in place never wipes the register.

## Lifecycle

```
(absent) --seen--> OPEN --absent from a later scan of that asset--> CLOSED
                    |  \--mitigation import--> MITIGATED --seen again--> OPEN (reopened)
                    \--manual---------------> RISK_ACCEPTED | FALSE_POSITIVE
```

Re-importing the same file is idempotent — only `last_detected` moves. Auto-closure
considers only assets present in the file being imported, so one department's scan
can never close another department's findings. A finding that returns after being
mitigated reopens with a counter and an event explaining why.

## Importing

`POST /api/scans/import` (multipart) with `kind=scan` or `kind=mitigation`.
Set `dry_run=true` to see the detected column mapping and a 25-row classification
preview before anything is written — the console's **Preview mapping** button.

Headers are auto-mapped from a large alias table, so Nessus (`Plugin ID`),
Qualys (`QID`), Rapid7, OpenVAS, Defender exports and hand-built spreadsheets all
work. Formats: CSV, TSV, XLSX, JSON and native `.nessus` XML. The Qualys 1-5 and
Nessus 0-4 severity scales are told apart from the file's own headers.

Mitigation files match on host + plugin/title and flip findings to mitigated,
closed, risk accepted or false positive, carrying over ticket reference and notes.

## Classification engine

Four-stage cascade, each result tagged with its confidence and the rule that fired:

1. regex rules over title + family + product + solution + description
2. scanner plugin-family mapping
3. port and service heuristics
4. host OS hint, then `Other`

About 50 built-in rules cover Windows/Linux/Unix/macOS patches, Oracle, SQL Server,
MySQL, PostgreSQL, MongoDB, Redis, Db2, Apache, IIS, Tomcat, WebLogic, browsers,
Office, Java and Log4j, containers, network devices, TLS/PKI and hardening gaps.
Categories: OS, Database, Application, Web/Middleware, Network, Virtualization,
Security, Cloud/Container, Crypto/PKI, Configuration, Other.

For in-house systems the scanner names in its own way, add a rule in **Settings →
Classification rules** (priority 1 beats the built-ins), test it against a real
vulnerability title, then re-run classification over history. Rules live in the
database, so no code change or restart is needed.

## SLA

**Settings → SLA targets** sets remediation days per severity (default
15/30/60/90/180). Saving recomputes every due date and breach flag across the
register and writes the change to the audit log. Breach rate, per-severity
"within SLA %", MTTR and the SLA gauges all follow from these numbers.

## Display

The console defaults to a comfortable size, and each person can scale it to taste:
the **A− / A+** control sits in the top status bar on every page, and
**Settings → Display** has a slider with presets and a live preview. The setting is
stored against your account rather than the browser, so it follows you to any
machine you sign in from. Range is 80% to 160%.

## Exports

Any filtered view exports to **Excel**, **PDF**, **PowerPoint** or **CSV** from the
buttons on the page header. Every export prints the active filter set on its cover
for audit purposes.

- **Excel** — Summary sheet (KPIs, severity, SLA, type, department, ageing), a
  Findings sheet with autofilter and colour-coded severity, plus one sheet per
  grouping.
- **PDF** — landscape report: KPI strip, SLA table, type and department tables,
  widest-spread vulnerabilities, then the findings detail.
- **PowerPoint** — a nine-slide review deck with a native line chart for the trend.
- **CSV** — the raw filtered rows, 37 columns.

## Background jobs

| Job | Schedule | Does |
|---|---|---|
| `aging` | 02:10 daily | recompute age, due dates, SLA breach flags |
| `watch` | every 5 min | import anything dropped in `<data dir>/watch` |
| `sessions` | hourly | purge expired logins |
| `vacuum` | Sundays 03:00 | compact the database |

The watch folder suits a scheduled scanner export: drop the file in and it is
ingested, logged and moved to `watch/processed` (or `watch/failed` with the reason).
Files whose name contains "mitig" or "remedi" are treated as mitigation evidence.
Run any job on demand from **Settings → Background jobs**.

**Pointing it somewhere else.** Set any path in **Settings → Background jobs** — a
network share the scanner writes to, for example — and imports become hands-free.
The path is validated for write access before being saved, stored in the database
so it survives restarts, and the change is audited. Clear it to return to the
default. On Windows a UNC path works (`\\fileserver\scans\weekly`) as long as the
account running the service can write to it.

## Packaging

**Windows.** Run this on the Windows machine itself — PyInstaller freezes for the
OS it runs on, so a Windows .exe cannot be built from macOS or Linux:

```
packaging\build_windows.bat
```

Double-clicking it works too. It needs only Python 3.11+ installed; everything
else is fetched into a throwaway virtual environment under `build\.venv`, so
nothing lands in your system Python. The script finds Python (via the `py`
launcher or PATH), installs dependencies, runs the tests, builds the exe, then
**starts the built exe and checks it actually serves the console** before
declaring success. Output: `dist\VMTracker\VMTracker.exe`.

Switches pass straight through the `.bat` to `build_windows.ps1`:

| Switch | Effect |
|---|---|
| `-OneFile` | One `VMTracker.exe` instead of a folder. Easy to copy, but it unpacks to a temp folder on every start, so it launches slower — prefer the folder build for a server. |
| `-Installer` | Also build the Inno Setup installer (looks in the usual install locations, not just PATH). |
| `-SkipTests` | Skip the test suite. |
| `-NoSmokeTest` | Skip launching the built exe to verify it. |
| `-Clean` | Delete `build\`, `dist\`, `packaging\Output\` and the venv first. |
| `-Python <path>` | Use a specific `python.exe`. |

```
packaging\build_windows.bat -Installer          ' exe + installer
packaging\build_windows.bat -OneFile -SkipTests ' quick single-file build
```

With `-Installer` you also get `packaging\Output\VMTracker-Setup-0.9.0.exe`,
which offers a desktop shortcut, a firewall rule for TCP 9797, and optional
start-at-boot. Uninstalling leaves your data directory intact.

Two things worth knowing. For the folder build, ship the **whole**
`dist\VMTracker` folder — the exe alone will not run. And the binary is
unsigned, so SmartScreen shows a "Windows protected your PC" prompt on first run;
*More info → Run anyway*, or sign it with your organisation's code-signing
certificate (`signtool sign /fd SHA256 /a dist\VMTracker\VMTracker.exe`).

**Building without a Windows machine.** `.github/workflows/build-windows.yml`
builds and smoke-tests the exe on a GitHub-hosted Windows runner on every push;
download it from the run's Artifacts section. Push a `v*` tag and it also builds
the installer and attaches it to a GitHub release.

**macOS / Linux**:

```bash
packaging/build_unix.sh
```

Produces `dist/VMTracker/VMTracker`. To run it as a service on Linux, copy
`packaging/vmtracker.service` to `/etc/systemd/system/` and enable it.

**Android** (optional): `android_client/` is a Flutter client for the same API —
sign in, executive KPIs, filterable register, and status changes from your phone.
See `android_client/README.md`.

## Layout

```
app/config.py     data dir / port resolution, frozen-bundle awareness
app/db.py         schema + idempotent ensure_table / ensure_column migrations
app/parsing.py    CSV / TSV / XLSX / JSON / .nessus readers, header auto-mapping
app/classify.py   OS / Database / Application classification engine
app/ingest.py     scan + mitigation import, lifecycle state machine, ageing & SLA
app/auth.py       users, roles, sessions
app/filters.py    shared filter -> parameterised SQL
app/queries.py    dashboard aggregations
app/exports.py    XLSX / CSV / PDF / PPTX builders
app/jobs.py       APScheduler jobs + watch folder
app/api.py        REST API
web/              operator console (HTML, CSS, four JS files, no build step)
packaging/        PyInstaller spec, icon, Windows build script, Inno Setup script,
                  build scripts, systemd unit
.github/          GitHub Actions workflow that builds the Windows exe
android_client/   optional Flutter client
samples/          synthetic demo data + generator
tests/            per-phase smoke tests + browser tests
```

## Notes and limits

- SQLite handles this workload comfortably; the register is one row per
  host-vulnerability-port, so a few hundred thousand rows is unremarkable.
- The trend is derived from finding dates rather than nightly snapshots, so it
  reflects the register's current best knowledge of history rather than what a
  dashboard would have shown on the day.
- There is no TLS in the app itself. On a trusted internal network that is usually
  fine; anywhere else, put it behind a reverse proxy that terminates TLS.
- `sla_breach_rate` counts open-past-due plus remediated-late over the same
  population. If you'd rather report only on closed work, use the per-severity
  "within SLA %" on the SLA panel, which separates the two.
