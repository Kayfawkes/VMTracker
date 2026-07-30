"""Phase 2 smoke test: parsing, classification, ingest lifecycle, aging/SLA."""
import datetime as dt
import os
import tempfile
from pathlib import Path

import pytest
from conftest import use_data_dir

from app import classify, db, ingest, parsing

DATA = tempfile.mkdtemp(prefix="vmt2_")


@pytest.fixture(autouse=True)
def _env():
    use_data_dir(DATA)
    yield
    db.reset_thread_conn()

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture()
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    yield c
    c.close()


# ---------------------------------------------------------------- parsing
def test_header_aliasing_across_scanners():
    m = parsing.build_mapping(["Host", "IP Address", "Plugin ID", "Name", "Risk", "Port"])
    assert m["Host"] == "hostname" and m["Plugin ID"] == "plugin_id"
    assert m["Name"] == "title" and m["Risk"] == "severity"

    q = parsing.build_mapping(["DNS", "IP", "QID", "Title", "Severity", "Last Detected"])
    assert q["QID"] == "plugin_id" and q["Title"] == "title"
    assert q["Last Detected"] == "last_detected"


def test_severity_normalisation():
    assert parsing.norm_severity("Critical") == "Critical"
    assert parsing.norm_severity("4") == "Critical"                      # Nessus scale
    assert parsing.norm_severity("4", qualys_scale=True) == "High"       # Qualys scale
    assert parsing.norm_severity("Moderate") == "Medium"
    assert parsing.norm_severity("", cvss=9.6) == "Critical"
    assert parsing.norm_severity(None) == "Info"


def test_date_and_bool_coercion():
    assert parsing.to_date("2025-03-04") == "2025-03-04"
    assert parsing.to_date("04/03/2025") == "2025-03-04"
    assert parsing.to_date("4-Mar-2025") == "2025-03-04"
    assert parsing.to_date("garbage") is None
    assert parsing.to_bool("Yes") == 1 and parsing.to_bool("false") == 0


def test_reads_csv_and_xlsx():
    raw = (SAMPLES / "scan_week1.csv").read_bytes()
    headers, rows = parsing.read_any(raw, "scan_week1.csv")
    assert "Plugin ID" in headers and len(rows) > 100
    raw2 = (SAMPLES / "mitigations.xlsx").read_bytes()
    h2, r2 = parsing.read_any(raw2, "mitigations.xlsx")
    assert "Hostname" in h2 and len(r2) > 10


# ------------------------------------------------------------ classifier
@pytest.mark.parametrize("title,expected_cat,expected_sub", [
    ("Microsoft SQL Server Unsupported Version Detection", "Database", "Microsoft SQL Server"),
    ("Oracle Database Server Multiple Vulnerabilities (Jan 2024 CPU)", "Database", "Oracle Database"),
    ("MySQL 5.7.x < 5.7.44 Multiple Vulnerabilities", "Database", "MySQL/MariaDB"),
    ("Microsoft Windows KB5034441: Security Update for Windows Server 2019", "OS", "Windows"),
    ("Red Hat Enterprise Linux glibc Buffer Overflow", "OS", "Linux"),
    ("Apache HTTP Server 2.4.x < 2.4.58 Multiple Vulnerabilities", "Web/Middleware", "Apache HTTP"),
    ("Cross-Site Scripting (XSS) in login form parameter", "Application", "Web Application"),
    ("Google Chrome < 121.0.6167.85 Multiple Vulnerabilities", "Application", "Browser"),
    ("VMware ESXi 7.0 < ESXi70U3 Multiple Vulnerabilities", "Virtualization", "VMware"),
    ("Cisco IOS XE Web UI Privilege Escalation", "Network", "Cisco"),
    ("Default Credentials Detected on Management Interface", "Configuration", "Credential Hygiene"),
    ("SSL Medium Strength Cipher Suites Supported", "Crypto/PKI", "TLS/Certificate"),
])
def test_rule_classification(conn, title, expected_cat, expected_sub):
    clf = classify.Classifier(conn)
    res = clf.classify(title=title)
    assert (res["category"], res["subcategory"]) == (expected_cat, expected_sub)
    assert res["confidence"] >= 0.8


def test_family_then_port_fallback(conn):
    clf = classify.Classifier(conn)
    fam = clf.classify(title="Some unknown check", family="Databases")
    assert fam["category"] == "Database" and fam["classified_by"] == "family"
    prt = clf.classify(title="Unknown service issue", port="1433")
    assert prt["category"] == "Database" and prt["classified_by"] == "port"
    unk = clf.classify(title="Totally unknown thing")
    assert unk["category"] == "Other" and unk["classified_by"] == "fallback"


def test_os_family_detection():
    assert classify.os_family("Microsoft Windows Server 2019") == "Windows"
    assert classify.os_family("Red Hat Enterprise Linux 8.6") == "Linux"
    assert classify.os_family("VMware ESXi 7.0") == "Hypervisor"


# ---------------------------------------------------------------- ingest
def _import(conn, fname, **kw):
    return ingest.import_scan((SAMPLES / fname).read_bytes(), fname, conn=conn, **kw)


def test_week1_import_populates_model(conn):
    res = _import(conn, "scan_week1.csv", name="Week 1")
    assert res["rows_total"] == res["rows_imported"] > 100
    assert res["findings_new"] == res["rows_imported"]
    assert res["assets_touched"] == 45

    assets = db.q("SELECT * FROM assets", conn=conn)
    assert len(assets) == 45
    assert all(a["department"] for a in assets)          # enrichment columns landed
    assert {a["os_family"] for a in assets} <= {"Windows", "Linux", "Hypervisor", "Network OS"}

    cats = {r["category"]: r["n"] for r in db.q(
        "SELECT category, COUNT(*) n FROM vulns GROUP BY category", conn=conn)}
    assert cats.get("Database", 0) >= 3 and cats.get("OS", 0) >= 2
    assert db.q1("SELECT COUNT(*) n FROM vulns WHERE category='Other'", conn=conn)["n"] == 0


def test_reimport_is_idempotent(conn):
    _import(conn, "scan_week1.csv")
    before = db.q1("SELECT COUNT(*) n FROM findings", conn=conn)["n"]
    res = _import(conn, "scan_week1.csv")
    after = db.q1("SELECT COUNT(*) n FROM findings", conn=conn)["n"]
    assert before == after
    assert res["findings_new"] == 0 and res["findings_closed"] == 0
    assert res["findings_updated"] == res["rows_imported"]


def test_week2_closes_absent_and_opens_new(conn):
    _import(conn, "scan_week1.csv", name="Week 1")
    res = _import(conn, "scan_week2.csv", name="Week 2")
    assert res["findings_closed"] > 0, "fixed vulns should auto-close"
    assert res["findings_new"] > 0, "newly detected vulns should open"

    closed = db.q1("SELECT COUNT(*) n FROM findings WHERE status='closed'", conn=conn)["n"]
    assert closed == res["findings_closed"]
    # closure is recorded as an event with a reason
    ev = db.q1("SELECT * FROM finding_events WHERE event_type='closed' LIMIT 1", conn=conn)
    assert ev["to_status"] == "closed" and "not present" in ev["note"]
    # days_to_close computed
    row = db.q1("SELECT days_to_close FROM findings WHERE status='closed' AND days_to_close "
                "IS NOT NULL LIMIT 1", conn=conn)
    assert row and row["days_to_close"] >= 0


def test_reopen_after_mitigation(conn):
    _import(conn, "scan_week1.csv")
    f = db.q1("SELECT * FROM findings LIMIT 1", conn=conn)
    conn.execute("UPDATE findings SET status='mitigated', mitigated_date=? WHERE id=?",
                 ("2026-01-01", f["id"]))
    conn.commit()
    res = _import(conn, "scan_week1.csv")
    again = db.q1("SELECT * FROM findings WHERE id=?", (f["id"],), conn=conn)
    assert again["status"] == "open" and again["reopened_count"] == 1
    assert res["findings_reopened"] == 1
    ev = db.q1("SELECT * FROM finding_events WHERE finding_id=? AND event_type='reopened'",
               (f["id"],), conn=conn)
    assert ev["from_status"] == "mitigated"


def test_mitigation_file_flips_status(conn):
    _import(conn, "scan_week1.csv")
    _import(conn, "scan_week2.csv")
    open_before = db.q1("SELECT COUNT(*) n FROM findings WHERE status IN ('open','reopened')",
                        conn=conn)["n"]
    res = _import(conn, "mitigations.xlsx", kind="mitigation")
    assert res["findings_updated"] > 0
    mitigated = db.q1("SELECT COUNT(*) n FROM findings WHERE status='mitigated'", conn=conn)["n"]
    open_after = db.q1("SELECT COUNT(*) n FROM findings WHERE status IN ('open','reopened')",
                       conn=conn)["n"]
    assert mitigated > 0 and open_after < open_before
    row = db.q1("SELECT * FROM findings WHERE status='mitigated' AND ticket_ref IS NOT NULL "
                "LIMIT 1", conn=conn)
    assert row["ticket_ref"].startswith("CHG") and row["mitigated_date"]


def test_aging_and_sla(conn):
    _import(conn, "scan_week1.csv")
    ingest.recompute_aging(conn)
    rows = db.q("SELECT age_days, due_date, sla_days, sla_breached, severity, status, "
                "first_detected FROM findings WHERE status='open'", conn=conn)
    assert rows and all(r["age_days"] > 0 for r in rows)
    crit = [r for r in rows if r["severity"] == "Critical"]
    assert crit and crit[0]["sla_days"] == 15
    first = dt.date.fromisoformat(crit[0]["first_detected"])
    assert dt.date.fromisoformat(crit[0]["due_date"]) == first + dt.timedelta(days=15)
    assert any(r["sla_breached"] == 1 for r in crit), "old critical findings must breach SLA"


def test_manual_edits_survive_reimport(conn):
    _import(conn, "scan_week1.csv")
    a = db.q1("SELECT * FROM assets LIMIT 1", conn=conn)
    conn.execute("UPDATE assets SET application='Manually Corrected App', "
                 "manual_fields='[\"application\"]' WHERE id=?", (a["id"],))
    conn.commit()
    _import(conn, "scan_week1.csv")
    after = db.q1("SELECT application FROM assets WHERE id=?", (a["id"],), conn=conn)
    assert after["application"] == "Manually Corrected App"


def test_dry_run_previews_without_writing(conn):
    res = _import(conn, "scan_week1.csv", dry_run=True)
    assert res["dry_run"] and len(res["preview"]) == 25
    assert db.q1("SELECT COUNT(*) n FROM findings", conn=conn)["n"] == 0
    assert res["detected_columns"]["Name"] == "title"


def test_rejects_unusable_file(conn):
    with pytest.raises(ValueError):
        ingest.import_scan(b"alpha,beta\n1,2\n", "junk.csv", conn=conn)
