"""Phase 4-6 smoke test: console assets, exports (xlsx/pdf/pptx/csv), scheduler jobs."""
import io
import os
import re
import tempfile
import zipfile
from pathlib import Path

import pytest
from conftest import use_data_dir
from fastapi.testclient import TestClient

from app import db, ingest, jobs
from app.main import app

DATA = tempfile.mkdtemp(prefix="vmt4_")
SAMPLES = Path(__file__).resolve().parent.parent / "samples"
WEB = Path(__file__).resolve().parent.parent / "web"


@pytest.fixture(scope="module", autouse=True)
def _env():
    use_data_dir(DATA, "admin-pass-123")
    yield
    db.reset_thread_conn()


@pytest.fixture(scope="module")
def client(_env):
    with TestClient(app) as c:
        conn = db.get_conn()
        if not db.q1("SELECT COUNT(*) n FROM findings", conn=conn)["n"]:
            for fname, kind in [("scan_week1.csv", "scan"), ("scan_week2.csv", "scan"),
                                ("mitigations.xlsx", "mitigation")]:
                ingest.import_scan((SAMPLES / fname).read_bytes(), fname, kind=kind, conn=conn)
        yield c


@pytest.fixture(scope="module")
def token(client):
    return client.post("/api/auth/login",
                       json={"username": "admin", "password": "admin-pass-123"}).json()["token"]


def hdr(t):
    return {"x-vmt-token": t}


# --------------------------------------------------------------- console
def test_console_html_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "VM<b>TRACKER</b>" in r.text and 'id="login"' in r.text
    assert "/static/app.css" in r.text


def test_static_assets_served(client):
    for path in ("/static/app.css", "/static/js/api.js", "/static/js/charts.js",
                 "/static/js/views.js", "/static/js/app.js"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert len(r.text) > 500, path


def test_console_references_only_existing_files(client):
    html = client.get("/").text
    for ref in re.findall(r'(?:href|src)="(/static/[^"]+)"', html):
        assert client.get(ref).status_code == 200, f"{ref} is referenced but missing"


def test_no_browser_storage_or_external_cdn():
    """The console must work offline on a segregated network."""
    for f in list(WEB.glob("**/*.js")) + list(WEB.glob("**/*.html")) + list(WEB.glob("**/*.css")):
        text = f.read_text(encoding="utf-8")
        assert "cdn." not in text and "googleapis" not in text, f"{f.name} loads a remote asset"
        # w3.org appears only as an XML namespace URI, never fetched
        remote = text.replace("http://www.w3.org/2000/svg", "").replace("http://127.0.0.1", "")
        assert "http://" not in remote, f"{f.name} has a remote URL"
        assert "localStorage" not in text and "sessionStorage" not in text, \
            f"{f.name} uses browser storage"


# --------------------------------------------------------------- exports
def test_csv_export_matches_filter(client, token):
    total = client.get("/api/findings?category=Database&page_size=1",
                       headers=hdr(token)).json()["total"]
    r = client.get("/api/export/csv?category=Database", headers=hdr(token))
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    lines = r.content.decode("utf-8-sig").strip().splitlines()
    assert len(lines) == total + 1                    # + header row
    assert "Vulnerability" in lines[0] and "System Owner" in lines[0]


def test_xlsx_export_structure(client, token):
    r = client.get("/api/export/xlsx?status=open", headers=hdr(token))
    assert r.status_code == 200
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(r.content))
    assert {"Summary", "Findings", "By Department", "By Type"} <= set(wb.sheetnames)
    ws = wb["Summary"]
    labels = [ws.cell(row=i, column=1).value for i in range(1, 20)]
    assert "Open findings" in labels and "SLA breach rate (%)" in labels
    fs = wb["Findings"]
    assert fs.cell(row=1, column=1).value == "Finding ID"
    assert fs.max_row > 10
    wb.close()


def test_pdf_export_is_valid(client, token):
    r = client.get("/api/export/pdf?severity=Critical", headers=hdr(token))
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 8000
    assert r.headers["content-type"] == "application/pdf"


def test_pptx_export_is_valid(client, token):
    r = client.get("/api/export/pptx", headers=hdr(token))
    assert r.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    slides = [n for n in zf.namelist() if n.startswith("ppt/slides/slide")]
    assert len(slides) >= 8, f"expected a full deck, got {len(slides)} slides"
    from pptx import Presentation
    prs = Presentation(io.BytesIO(r.content))
    text = " ".join(sh.text_frame.text for s in prs.slides for sh in s.shapes
                    if sh.has_text_frame)
    assert "Vulnerability Management Review" in text
    assert "SLA" in text and "department" in text.lower()


def test_export_respects_filters_end_to_end(client, token):
    """A tight filter must yield a smaller export than a loose one."""
    wide = client.get("/api/export/csv?status=open", headers=hdr(token)).content
    tight = client.get("/api/export/csv?status=open&severity=Critical",
                       headers=hdr(token)).content
    assert len(tight) < len(wide)
    body = tight.decode("utf-8-sig").strip().splitlines()[1:]
    assert body and all("Critical" in line for line in body)


def test_unknown_export_format_rejected(client, token):
    assert client.get("/api/export/docx", headers=hdr(token)).status_code == 400


def test_export_requires_login(client):
    client.cookies.clear()
    assert client.get("/api/export/csv").status_code == 401


def test_export_is_audited(client, token):
    client.get("/api/export/csv?severity=High", headers=hdr(token))
    log = client.get("/api/audit?entity=export", headers=hdr(token)).json()
    assert any(e["field"] == "csv" and e["actor"] == "admin" for e in log)


# ------------------------------------------------------------- scheduler
def test_scheduler_running_with_jobs(client, token):
    st = client.get("/api/system/jobs", headers=hdr(token)).json()
    assert st["running"] is True
    assert {"aging", "sessions", "watch", "vacuum"} <= {j["id"] for j in st["jobs"]}
    assert Path(st["watch_folder"]).exists()


def test_run_job_on_demand(client, token):
    r = client.post("/api/system/jobs/aging/run", headers=hdr(token)).json()
    assert r["status"] == "ok" and "recomputed" in r["detail"]


def test_watch_folder_auto_imports(client, token):
    before = db.q1("SELECT COUNT(*) n FROM scans")["n"]
    watch = jobs.watch_dir()
    (watch / "scan_week1.csv").write_bytes((SAMPLES / "scan_week1.csv").read_bytes())
    r = client.post("/api/system/jobs/watch/run", headers=hdr(token)).json()
    assert r["status"] == "ok" and "scan_week1.csv" in r["detail"]
    assert db.q1("SELECT COUNT(*) n FROM scans")["n"] == before + 1
    assert (watch / "processed" / "scan_week1.csv").exists()
    assert not (watch / "scan_week1.csv").exists()


def test_watch_folder_quarantines_bad_file(client, token):
    watch = jobs.watch_dir()
    (watch / "garbage.csv").write_text("alpha,beta\n1,2\n")
    r = client.post("/api/system/jobs/watch/run", headers=hdr(token)).json()
    assert "FAILED" in r["detail"]
    assert (watch / "failed" / "garbage.csv").exists()


def test_system_summary(client, token):
    s = client.get("/api/system/summary", headers=hdr(token)).json()
    assert s["counts"]["findings"] > 0 and s["counts"]["assets"] > 0
    assert s["last_scan"]["scan_date"]
