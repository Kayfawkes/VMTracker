"""Phase 3 smoke test: auth + roles, filter engine, editable columns, dashboards."""
import os
import tempfile
from pathlib import Path

DATA = tempfile.mkdtemp(prefix="vmt3_")
os.environ["VM_TRACKER_DATA_DIR"] = DATA
os.environ["VM_TRACKER_ADMIN_PASSWORD"] = "admin-pass-123"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, ingest, queries  # noqa: E402
from app.main import app  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        conn = db.get_conn()
        if not db.q1("SELECT COUNT(*) n FROM findings", conn=conn)["n"]:
            for fname, kind in [("scan_week1.csv", "scan"), ("scan_week2.csv", "scan"),
                                ("mitigations.xlsx", "mitigation")]:
                ingest.import_scan((SAMPLES / fname).read_bytes(), fname, kind=kind, conn=conn)
        yield c


def as_admin(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin-pass-123"})
    assert r.status_code == 200
    return r.json()["token"]


def hdr(token):
    return {"x-vmt-token": token}


# ------------------------------------------------------------------ auth
def test_endpoints_require_authentication(client):
    client.cookies.clear()
    for path in ("/api/findings", "/api/dashboard/executive", "/api/users"):
        assert client.get(path).status_code == 401


def test_login_and_session(client):
    token = as_admin(client)
    me = client.get("/api/auth/me", headers=hdr(token)).json()
    assert me["username"] == "admin" and me["role"] == "admin"
    assert me["must_change"] == 1  # bootstrap account forces a password change


def test_bad_password_rejected(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_role_enforcement(client):
    admin = as_admin(client)
    client.post("/api/users", headers=hdr(admin), json={
        "username": "viewer1", "password": "viewer-pass-1", "role": "viewer"})
    client.post("/api/users", headers=hdr(admin), json={
        "username": "analyst1", "password": "analyst-pass-1", "role": "analyst"})

    v = client.post("/api/auth/login",
                    json={"username": "viewer1", "password": "viewer-pass-1"}).json()["token"]
    a = client.post("/api/auth/login",
                    json={"username": "analyst1", "password": "analyst-pass-1"}).json()["token"]

    fid = client.get("/api/findings?page_size=1", headers=hdr(v)).json()["rows"][0]["id"]
    assert client.get("/api/findings", headers=hdr(v)).status_code == 200      # viewer reads
    assert client.patch(f"/api/findings/{fid}", headers=hdr(v),
                        json={"notes": "nope"}).status_code == 403              # viewer cannot edit
    assert client.patch(f"/api/findings/{fid}", headers=hdr(a),
                        json={"notes": "analyst note"}).status_code == 200
    assert client.get("/api/users", headers=hdr(a)).status_code == 403          # analyst not admin
    assert client.put("/api/sla", headers=hdr(a), json={"Critical": 7}).status_code == 403


def test_password_change_flow(client):
    admin = as_admin(client)
    client.post("/api/users", headers=hdr(admin), json={
        "username": "pwuser", "password": "initial-pass-1", "role": "viewer"})
    t = client.post("/api/auth/login",
                    json={"username": "pwuser", "password": "initial-pass-1"}).json()["token"]
    bad = client.post("/api/auth/password", headers=hdr(t),
                      json={"current_password": "wrong", "new_password": "second-pass-2"})
    assert bad.status_code == 400
    ok = client.post("/api/auth/password", headers=hdr(t),
                     json={"current_password": "initial-pass-1", "new_password": "second-pass-2"})
    assert ok.status_code == 200
    assert client.post("/api/auth/login",
                       json={"username": "pwuser", "password": "second-pass-2"}).status_code == 200


def test_short_password_rejected(client):
    admin = as_admin(client)
    r = client.post("/api/users", headers=hdr(admin),
                    json={"username": "weak", "password": "abc", "role": "viewer"})
    assert r.status_code == 400


# --------------------------------------------------------------- filters
def test_filters_narrow_results(client):
    t = as_admin(client)
    all_rows = client.get("/api/findings?page_size=1", headers=hdr(t)).json()["total"]
    crit = client.get("/api/findings?severity=Critical&status=open&page_size=1",
                      headers=hdr(t)).json()
    assert 0 < crit["total"] < all_rows
    assert all(r["severity"] == "Critical" and r["status"] in ("open", "reopened")
               for r in client.get("/api/findings?severity=Critical&status=open&page_size=50",
                                   headers=hdr(t)).json()["rows"])

    db_only = client.get("/api/findings?category=Database&page_size=50", headers=hdr(t)).json()
    assert db_only["total"] > 0
    assert {r["category"] for r in db_only["rows"]} == {"Database"}

    multi = client.get("/api/findings?severity=Critical&severity=High&page_size=1",
                       headers=hdr(t)).json()
    assert multi["total"] > crit["total"]


def test_search_and_sort(client):
    t = as_admin(client)
    host = client.get("/api/findings?page_size=1", headers=hdr(t)).json()["rows"][0]["hostname"]
    hits = client.get(f"/api/findings?q={host}&page_size=100", headers=hdr(t)).json()
    assert hits["total"] > 0 and all(r["hostname"] == host for r in hits["rows"])

    asc = client.get("/api/findings?sort=age&direction=asc&page_size=20",
                     headers=hdr(t)).json()["rows"]
    assert [r["age_days"] for r in asc] == sorted(r["age_days"] for r in asc)


def test_filter_options_populated(client):
    t = as_admin(client)
    opts = client.get("/api/filters/options", headers=hdr(t)).json()
    assert len(opts["department"]) >= 5 and "Database" in opts["category"]
    assert "system_owner" in opts["dimensions"] or "system_owner" in opts["sortable"]


# ------------------------------------------------------- editable columns
def test_edit_asset_columns_and_pin_against_scans(client):
    t = as_admin(client)
    asset = client.get("/api/assets", headers=hdr(t)).json()[0]
    r = client.patch(f"/api/assets/{asset['id']}", headers=hdr(t), json={
        "application": "Core Banking (corrected)", "system_owner": "F. Frimpong",
        "department": "Treasury"})
    assert r.status_code == 200
    assert set(r.json()["changed"]) >= {"application", "system_owner"}
    assert r.json()["asset"]["application"] == "Core Banking (corrected)"

    # a re-import must not clobber the manual correction
    ingest.import_scan((SAMPLES / "scan_week2.csv").read_bytes(), "scan_week2.csv",
                       conn=db.get_conn())
    again = db.q1("SELECT application, manual_fields FROM assets WHERE id=?", (asset["id"],))
    assert again["application"] == "Core Banking (corrected)"
    assert "application" in again["manual_fields"]

    # audit trail records who changed what
    log = client.get("/api/audit?entity=asset", headers=hdr(t)).json()
    assert any(e["field"] == "application" and e["actor"] == "admin" for e in log)


def test_unlock_restores_scanner_authority(client):
    t = as_admin(client)
    asset = client.get("/api/assets", headers=hdr(t)).json()[0]
    client.patch(f"/api/assets/{asset['id']}", headers=hdr(t), json={"location": "Manual Site"})
    r = client.get(f"/api/assets/{asset['id']}/unlock/location", headers=hdr(t)).json()
    assert "location" not in r["manual_fields"]


def test_edit_finding_status_creates_event(client):
    t = as_admin(client)
    row = client.get("/api/findings?status=open&page_size=1", headers=hdr(t)).json()["rows"][0]
    r = client.patch(f"/api/findings/{row['id']}", headers=hdr(t), json={
        "status": "risk_accepted", "notes": "Compensating control approved by CISO",
        "ticket_ref": "RSK-4412"})
    assert r.status_code == 200
    detail = client.get(f"/api/findings/{row['id']}", headers=hdr(t)).json()
    assert detail["status"] == "risk_accepted" and detail["ticket_ref"] == "RSK-4412"
    assert any(e["event_type"] == "manual-update" and e["to_status"] == "risk_accepted"
               for e in detail["events"])


def test_manual_close_computes_days_to_close(client):
    t = as_admin(client)
    row = client.get("/api/findings?status=open&page_size=5", headers=hdr(t)).json()["rows"][-1]
    client.patch(f"/api/findings/{row['id']}", headers=hdr(t), json={"status": "closed"})
    after = db.q1("SELECT status, closed_date, days_to_close FROM findings WHERE id=?",
                  (row["id"],))
    assert after["status"] == "closed" and after["days_to_close"] >= 0


def test_bulk_assignment_by_filter(client):
    t = as_admin(client)
    before = client.get("/api/findings?category=Database&status=open&page_size=1",
                        headers=hdr(t)).json()["total"]
    r = client.post("/api/findings/bulk", headers=hdr(t), json={
        "filters": {"category": "Database", "status": "open"},
        "fields": {"remediation_owner": "DBA Team"}})
    assert r.json()["updated"] == before
    check = client.get("/api/findings?category=Database&remediation_owner=DBA Team&page_size=1",
                       headers=hdr(t)).json()
    assert check["total"] == before


# ------------------------------------------------------------ dashboards
def test_executive_view_shape(client):
    t = as_admin(client)
    ex = client.get("/api/dashboard/executive", headers=hdr(t)).json()
    k = ex["kpis"]
    assert k["open"] > 0 and k["open_critical_high"] == k["open_critical"] + k["open_high"]
    assert 0 <= k["sla_breach_rate"] <= 100
    assert k["mttr_days"] >= 0
    assert len(ex["severity"]) == 5 and ex["severity"][0]["severity"] == "Critical"
    assert len(ex["trend"]) == 12 and "total_risk" in ex["trend"][0]
    assert {r["severity"] for r in ex["sla"]} == {"Critical", "High", "Medium", "Low", "Info"}
    assert ex["by_category"] and ex["top_vulnerabilities"]


def test_all_five_group_dashboards(client):
    t = as_admin(client)
    for dim in ("department", "application", "system_owner", "environment", "category"):
        d = client.get(f"/api/dashboard/group/{dim}", headers=hdr(t)).json()
        assert d["rows"], f"{dim} produced no rows"
        row = d["rows"][0]
        assert {"open", "critical", "high", "breached", "avg_age", "closure_rate"} <= set(row)
        assert d["matrix"]["categories"] and d["aging"]
        assert sum(r["open"] for r in d["rows"]) == d["kpis"]["open"]


def test_group_dashboard_respects_filters(client):
    t = as_admin(client)
    full = client.get("/api/dashboard/group/department", headers=hdr(t)).json()
    filtered = client.get("/api/dashboard/group/department?category=Database",
                          headers=hdr(t)).json()
    assert filtered["kpis"]["open"] < full["kpis"]["open"]
    assert filtered["matrix"]["categories"] == ["Database"]


def test_unknown_dimension_rejected(client):
    t = as_admin(client)
    assert client.get("/api/dashboard/group/nonsense", headers=hdr(t)).status_code == 400


def test_aging_buckets_cover_population(client):
    t = as_admin(client)
    buckets = client.get("/api/dashboard/executive", headers=hdr(t)).json()["aging"]
    kpis = client.get("/api/dashboard/kpis", headers=hdr(t)).json()
    assert sum(b["n"] for b in buckets) == kpis["open"]


# ------------------------------------------------------------ SLA policy
def test_operator_can_set_sla_and_metrics_follow(client):
    t = as_admin(client)
    before = client.get("/api/dashboard/kpis", headers=hdr(t)).json()["open_breached"]
    r = client.put("/api/sla", headers=hdr(t),
                   json={"Critical": 3, "High": 7, "Medium": 14, "Low": 30, "Info": 60})
    assert r.status_code == 200
    assert dict((x["severity"], x["days"]) for x in r.json())["Critical"] == 3
    after = client.get("/api/dashboard/kpis", headers=hdr(t)).json()["open_breached"]
    assert after >= before, "tighter SLAs must not reduce breach count"
    sla = client.get("/api/dashboard/sla", headers=hdr(t)).json()
    assert dict((x["severity"], x["target_days"]) for x in sla)["High"] == 7
    client.put("/api/sla", headers=hdr(t),
               json={"Critical": 15, "High": 30, "Medium": 60, "Low": 90, "Info": 180})


def test_invalid_sla_rejected(client):
    t = as_admin(client)
    assert client.put("/api/sla", headers=hdr(t), json={"Critical": "soon"}).status_code == 400
    assert client.put("/api/sla", headers=hdr(t), json={"Bogus": 5}).status_code == 400


# -------------------------------------------------- classification admin
def test_custom_rule_changes_classification(client):
    t = as_admin(client)
    probe = {"title": "Acme Ledger Core 4.2 privilege escalation"}
    assert client.post("/api/rules/test", headers=hdr(t), json=probe).json()["category"] == "Other"
    client.post("/api/rules", headers=hdr(t), json={
        "name": "Acme Ledger (in-house)", "priority": 1, "pattern": r"\bacme\s+ledger\b",
        "category": "Application", "subcategory": "Core Banking Platform"})
    res = client.post("/api/rules/test", headers=hdr(t), json=probe).json()
    assert res["category"] == "Application" and res["subcategory"] == "Core Banking Platform"


def test_bad_regex_rejected(client):
    t = as_admin(client)
    r = client.post("/api/rules", headers=hdr(t),
                    json={"name": "bad", "pattern": "([unclosed", "category": "OS"})
    assert r.status_code == 400


def test_saved_views_roundtrip(client):
    t = as_admin(client)
    client.post("/api/views", headers=hdr(t), json={
        "name": "Critical DB - Treasury", "scope": "findings",
        "filters": {"category": ["Database"], "severity": ["Critical"]}})
    views = client.get("/api/views", headers=hdr(t)).json()
    v = next(x for x in views if x["name"] == "Critical DB - Treasury")
    assert "Database" in v["filters"]
    assert client.delete(f"/api/views/{v['id']}", headers=hdr(t)).status_code == 200
