# VM Tracker

Local-first vulnerability management tracker: FastAPI backend + SQLite, serving a
vanilla-JS operator console. Phases 1-3 complete (backend, ingestion engine,
classification, auth, dashboards). Phase 4 (web console UI) is next.

## Quick start

```bash
python -m pip install fastapi "uvicorn[standard]" apscheduler openpyxl \
                      python-multipart reportlab python-pptx xlsxwriter
python run.py                      # http://127.0.0.1:9797
```

On first start the server creates an `admin` account, prints the generated
password, and writes it to `initial-admin-password.txt` in the data directory.
Set `VM_TRACKER_ADMIN_PASSWORD` to choose it yourself.

Interactive API docs: <http://127.0.0.1:9797/api/docs>

## Paths and settings

| What | Value |
|---|---|
| Data dir (Windows) | `%LOCALAPPDATA%\VM Tracker` |
| Data dir (macOS/Linux) | `~/.VM Tracker` |
| Override | `VM_TRACKER_DATA_DIR` (also accepts the literal `VM Tracker_DATA_DIR`) |
| Database | `<data dir>/vmtracker.db` (SQLite, WAL) |
| Port / host | `9797` / `0.0.0.0` — override with `VM_TRACKER_PORT`, `VM_TRACKER_HOST` |
| Admin password (first run) | `VM_TRACKER_ADMIN_PASSWORD` |

Reachable from other machines on the network at `http://<server-ip>:9797/`.
Open the port in the host firewall (Windows: `netsh advfirewall firewall add rule
name="VM Tracker" dir=in action=allow protocol=TCP localport=9797`).

## Tests

```bash
python -m pytest tests/ -q          # 58 tests, phases 1-3
python samples/gen_samples.py       # regenerate demo scan data
```

## Layout

```
app/config.py     data dir / port resolution, frozen-bundle awareness
app/db.py         schema + idempotent ensure_table / ensure_column migrations
app/parsing.py    CSV / TSV / XLSX / JSON / .nessus readers, header auto-mapping
app/classify.py   OS / Database / Application classification engine (rules in DB)
app/ingest.py     scan + mitigation import, lifecycle state machine, aging & SLA
app/auth.py       users, roles (viewer / analyst / admin), sessions
app/filters.py    shared filter -> parameterised SQL
app/queries.py    dashboard aggregations (KPIs, groups, trend, aging, SLA)
app/api.py        REST API
samples/          demo scan data + generator
tests/            per-phase smoke tests
```

## Data model

- **assets** — one row per host; ownership columns (department, application,
  system owner, environment, criticality) are editable and pinned in
  `manual_fields` so scan imports never overwrite an operator correction.
- **vulns** — one row per unique vulnerability definition, carrying its
  classification (category, subcategory, confidence, which rule fired).
- **findings** — one row per (asset, vulnerability, port): the tracked unit, with
  status, first/last detected, age, due date, SLA breach flag and risk score.
- **finding_events** / **audit_log** — why a status changed, and who changed what.

## Lifecycle

```
(absent) --seen--> OPEN --absent from a later scan of that asset--> CLOSED
                    |  \--mitigation import--> MITIGATED --seen again--> OPEN (reopened)
                    \--manual---------------> RISK_ACCEPTED | FALSE_POSITIVE
```

Re-importing the same file is idempotent. Auto-closure only considers assets
present in the file being imported, so a single department's scan can never close
another department's findings.

## Importing

`POST /api/scans/import` (multipart) with `kind=scan` or `kind=mitigation`;
`dry_run=true` returns the detected column mapping plus a 25-row preview before
anything is written. Headers are auto-mapped, so Nessus (`Plugin ID`), Qualys
(`QID`), Rapid7, OpenVAS and hand-built spreadsheets all work; the Qualys 1-5 vs
Nessus 0-4 severity scales are disambiguated from the file's own headers.

## Classification engine

Four-stage cascade, each result tagged with confidence and the rule that fired:
regex rules over title/family/product/solution -> scanner plugin-family map ->
port/service heuristics -> OS hint. ~50 built-in rules cover Windows/Linux/Unix
patches, Oracle/SQL Server/MySQL/PostgreSQL/Mongo/Redis/Db2, Apache/IIS/Tomcat/
WebLogic, browsers, Office, Java, containers, network devices, TLS/PKI and
hardening gaps. Add your own in-house rules via `POST /api/rules` (priority 1
beats the built-ins), then `POST /api/rules/reclassify` to re-run history.

## SLA

`GET/PUT /api/sla` — remediation targets per severity (default 15/30/60/90/180
days). Changing a target recomputes due dates and breach flags across every
finding and is written to the audit log.
