"""Optional end-to-end UI test. Skipped unless playwright + chromium are installed:

    pip install playwright && python -m playwright install chromium
"""
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytest.importorskip("playwright", reason="playwright not installed")
from playwright.sync_api import sync_playwright  # noqa: E402

PORT = 9799
PASSWORD = "ui-test-pass-123"


def free_port(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


@pytest.fixture(scope="module")
def server():
    data = tempfile.mkdtemp(prefix="vmt_ui_")
    env = {**os.environ, "VM_TRACKER_DATA_DIR": data,
           "VM_TRACKER_ADMIN_PASSWORD": PASSWORD}
    subprocess.run(
        [sys.executable, "-c",
         "from app import db, ingest, auth; db.init_db(); auth.bootstrap_admin();"
         "ingest.import_scan(open('samples/scan_week1.csv','rb').read(),'scan_week1.csv');"
         "ingest.import_scan(open('samples/scan_week2.csv','rb').read(),'scan_week2.csv')"],
        cwd=ROOT, env=env, check=True)
    proc = subprocess.Popen([sys.executable, "run.py", "--port", str(PORT), "--no-banner"],
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(50):
        if not free_port(PORT):
            break
        time.sleep(0.2)
    yield f"http://127.0.0.1:{PORT}"
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def page(server):
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(args=["--no-sandbox"])
        except Exception as exc:
            pytest.skip(f"chromium unavailable: {exc}")
        errors = []
        pg = browser.new_page(viewport={"width": 1500, "height": 950})
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(server)
        pg.fill("#lu", "admin")
        pg.fill("#lp", PASSWORD)
        pg.click("#lgo")
        pg.wait_for_selector("#shell.ready", timeout=20000)
        pg.wait_for_timeout(1500)
        pg.keyboard.press("Escape")
        pg.errors = errors
        yield pg
        browser.close()


def test_every_view_renders_without_js_errors(page):
    for route in ["executive", "findings", "department", "application", "system_owner",
                  "environment", "category", "assets", "imports", "admin"]:
        page.evaluate(f"go('{route}')")
        page.wait_for_timeout(1200)
        assert page.query_selector(".page-head h1"), f"{route} rendered no heading"
        assert not page.query_selector(".empty b"), f"{route} shows an error panel"
    assert page.errors == [], f"JavaScript errors: {page.errors}"


def test_filters_narrow_the_table(page):
    page.evaluate("go('findings')")
    page.wait_for_timeout(1200)
    def matching():
        # the header reports the full match count, not just the visible page
        return int(re.search(r"([\d,]+) findings match",
                             page.inner_text(".page-head .sub")).group(1).replace(",", ""))

    before = matching()
    page.select_option('select[data-fk="severity"]', ["Critical"])
    page.click("#fApply")
    page.wait_for_timeout(1500)
    assert matching() < before
    sevs = page.eval_on_selector_all("#ftable tbody tr td:nth-child(5)",
                                     "e=>e.map(x=>x.innerText.trim())")
    assert set(sevs) == {"Critical"}
    page.click("#fClear")
    page.wait_for_timeout(1200)


def test_inline_edit_persists(page):
    page.evaluate("go('findings')")
    page.wait_for_timeout(1300)
    cell = page.query_selector('#ftable tbody tr td[data-edit="ticket_ref"]')
    cell.click()
    page.wait_for_timeout(300)
    page.keyboard.type("CHG-UI-1")
    page.keyboard.press("Enter")
    page.wait_for_timeout(1200)
    assert "CHG-UI-1" in cell.inner_text()
    page.reload()
    page.wait_for_selector("#ftable", timeout=15000)
    page.wait_for_timeout(1500)
    assert "CHG-UI-1" in page.inner_text("#ftable")


def test_export_downloads_a_file(page):
    page.evaluate("go('executive')")
    page.wait_for_timeout(1500)
    with page.expect_download(timeout=40000) as dl:
        page.click('[data-export="xlsx"]')
    assert dl.value.suggested_filename.endswith(".xlsx")


def test_scorecard_drills_into_register(page):
    page.evaluate("go('department')")
    page.wait_for_timeout(1600)
    page.click("#scorecard tbody tr:first-child")
    page.wait_for_timeout(1600)
    assert page.evaluate("S.route") == "findings"
    assert page.evaluate("Object.keys(S.filters)").count("department") == 1
