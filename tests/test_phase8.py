"""Tests for the follow-up requests: admin:admin + forced reset, admin password
reset, configurable watch folder, and the saved interface scale."""
import os
import tempfile
from pathlib import Path

import pytest
from conftest import use_data_dir
from fastapi.testclient import TestClient

from app import auth, db, jobs
from app.main import app

DATA = tempfile.mkdtemp(prefix="vmt8_")
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="module", autouse=True)
def _env():
    use_data_dir(DATA)          # no override: exercise the real admin/admin default
    yield
    db.reset_thread_conn()


@pytest.fixture(scope="module")
def client(_env):
    with TestClient(app) as c:
        yield c


def hdr(t):
    return {"x-vmt-token": t}


def login(client, user="admin", pwd="admin"):
    r = client.post("/api/auth/login", json={"username": user, "password": pwd})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------ first-run credentials
def test_first_run_is_admin_admin_and_must_change(client):
    res = login(client)
    assert res["user"]["username"] == "admin"
    assert res["user"]["role"] == "admin"
    assert res["user"]["must_change"] == 1, "the default account must force a password change"


def test_default_password_written_to_data_dir(client):
    login(client)
    f = Path(DATA) / "initial-admin-password.txt"
    assert f.exists()
    body = f.read_text()
    assert "admin" in body and "must change" in body.lower()


def test_forced_change_flag_clears_after_change(client):
    token = login(client)["token"]
    short = client.post("/api/auth/password", headers=hdr(token),
                        json={"current_password": "admin", "new_password": "abc"})
    assert short.status_code == 400, "short passwords must be rejected"

    ok = client.post("/api/auth/password", headers=hdr(token),
                     json={"current_password": "admin", "new_password": "operator-pass-1"})
    assert ok.status_code == 200
    assert client.get("/api/auth/me", headers=hdr(token)).json()["must_change"] == 0
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": "admin"}).status_code == 401


def test_env_var_still_overrides_the_default():
    """A deployment can set its own bootstrap password instead of admin:admin."""
    other = tempfile.mkdtemp(prefix="vmt8b_")
    conn = db.connect(str(Path(other) / "t.db"))
    db.init_db(conn)
    os.environ["VM_TRACKER_ADMIN_PASSWORD"] = "chosen-pass-99"
    try:
        assert auth.bootstrap_admin(conn) == "chosen-pass-99"
        row = conn.execute("SELECT password_hash, salt, must_change FROM users").fetchone()
        assert auth.verify_password("chosen-pass-99", row["password_hash"], row["salt"])
        assert row["must_change"] == 1
    finally:
        os.environ.pop("VM_TRACKER_ADMIN_PASSWORD", None)
        conn.close()


# ------------------------------------------------ admin password reset
def test_admin_generates_a_reset_password(client):
    token = login(client, pwd="operator-pass-1")["token"]
    client.post("/api/users", headers=hdr(token),
                json={"username": "kwame", "password": "first-pass-1", "role": "analyst"})

    res = client.post("/api/users/2/reset-password", headers=hdr(token), json={}).json()
    generated = res["generated_password"]
    assert generated and len(generated) >= 12
    assert client.post("/api/auth/login",
                       json={"username": "kwame", "password": "first-pass-1"}).status_code == 401
    after = login(client, "kwame", generated)
    assert after["user"]["must_change"] == 1


def test_admin_sets_an_explicit_reset_password(client):
    token = login(client, pwd="operator-pass-1")["token"]
    res = client.post("/api/users/2/reset-password", headers=hdr(token),
                      json={"new_password": "chosen-reset-1"})
    assert res.status_code == 200 and res.json()["generated_password"] is None
    assert login(client, "kwame", "chosen-reset-1")["user"]["must_change"] == 1


def test_reset_revokes_existing_sessions(client):
    admin = login(client, pwd="operator-pass-1")["token"]
    victim = login(client, "kwame", "chosen-reset-1")["token"]
    assert client.get("/api/auth/me", headers=hdr(victim)).status_code == 200
    client.post("/api/users/2/reset-password", headers=hdr(admin),
                json={"new_password": "rotated-pass-1"})
    assert client.get("/api/auth/me", headers=hdr(victim)).status_code == 401


def test_reset_is_audited_and_admin_only(client):
    admin = login(client, pwd="operator-pass-1")["token"]
    log = client.get("/api/audit?entity=user", headers=hdr(admin)).json()
    assert any(e["field"] == "password" and "reset by admin" in (e["new_value"] or "")
               for e in log)

    analyst = login(client, "kwame", "rotated-pass-1")["token"]
    client.post("/api/auth/password", headers=hdr(analyst),
                json={"current_password": "rotated-pass-1", "new_password": "analyst-own-1"})
    a2 = login(client, "kwame", "analyst-own-1")["token"]
    assert client.post("/api/users/1/reset-password", headers=hdr(a2),
                       json={}).status_code == 403


def test_short_reset_password_rejected(client):
    token = login(client, pwd="operator-pass-1")["token"]
    assert client.post("/api/users/2/reset-password", headers=hdr(token),
                       json={"new_password": "abc"}).status_code == 400


# ------------------------------------------------ custom watch folder
def test_watch_folder_defaults_into_data_dir(client):
    token = login(client, pwd="operator-pass-1")["token"]
    st = client.get("/api/system/jobs", headers=hdr(token)).json()
    assert st["watch_folder"] == str(Path(DATA) / "watch")
    assert st["watch_folder_custom"] is False


def test_set_custom_watch_folder_and_import_from_it(client):
    token = login(client, pwd="operator-pass-1")["token"]
    custom = tempfile.mkdtemp(prefix="vmt8_share_")
    r = client.put("/api/system/watch-folder", headers=hdr(token), json={"path": custom})
    assert r.status_code == 200 and r.json()["custom"] is True
    assert r.json()["watch_folder"] == custom
    assert (Path(custom) / "processed").is_dir()

    # the auto-import job now reads from the new location
    (Path(custom) / "scan_week1.csv").write_bytes((SAMPLES / "scan_week1.csv").read_bytes())
    run = client.post("/api/system/jobs/watch/run", headers=hdr(token)).json()
    assert run["status"] == "ok" and "scan_week1.csv" in run["detail"]
    assert (Path(custom) / "processed" / "scan_week1.csv").exists()
    assert db.q1("SELECT COUNT(*) n FROM findings")["n"] > 0


def test_watch_folder_survives_restart(client):
    token = login(client, pwd="operator-pass-1")["token"]
    saved = db.get_setting(jobs.WATCH_SETTING)
    assert saved and str(jobs.watch_dir()) == saved


def test_unwritable_watch_folder_rejected_with_reason(client):
    token = login(client, pwd="operator-pass-1")["token"]
    r = client.put("/api/system/watch-folder", headers=hdr(token),
                   json={"path": "/proc/nonexistent/cannot-create"})
    assert r.status_code == 400
    assert "cannot use that folder" in r.json()["detail"].lower()


def test_reset_watch_folder_to_default(client):
    token = login(client, pwd="operator-pass-1")["token"]
    r = client.put("/api/system/watch-folder", headers=hdr(token), json={"path": ""})
    assert r.json()["custom"] is False
    assert r.json()["watch_folder"] == str(Path(DATA) / "watch")


def test_watch_folder_change_is_audited_and_admin_only(client):
    admin = login(client, pwd="operator-pass-1")["token"]
    log = client.get("/api/audit?entity=setting", headers=hdr(admin)).json()
    assert any(e["field"] == "watch_folder" for e in log)
    analyst = login(client, "kwame", "analyst-own-1")["token"]
    assert client.put("/api/system/watch-folder", headers=hdr(analyst),
                      json={"path": "/tmp"}).status_code == 403


# ------------------------------------------------ interface scale
def test_scale_defaults_and_persists_per_user(client):
    admin = login(client, pwd="operator-pass-1")["token"]
    assert client.get("/api/prefs", headers=hdr(admin)).json()["ui_scale"] == 1.0

    assert client.put("/api/prefs", headers=hdr(admin),
                      json={"ui_scale": 1.25}).json()["ui_scale"] == 1.25
    assert client.get("/api/prefs", headers=hdr(admin)).json()["ui_scale"] == 1.25

    # a second sign-in keeps the setting; another user is unaffected
    again = login(client, pwd="operator-pass-1")["token"]
    assert client.get("/api/prefs", headers=hdr(again)).json()["ui_scale"] == 1.25
    other = login(client, "kwame", "analyst-own-1")["token"]
    assert client.get("/api/prefs", headers=hdr(other)).json()["ui_scale"] == 1.0


def test_out_of_range_scale_rejected(client):
    token = login(client, pwd="operator-pass-1")["token"]
    for bad in (0.2, 4, "big"):
        assert client.put("/api/prefs", headers=hdr(token),
                          json={"ui_scale": bad}).status_code == 400


def test_console_exposes_the_scale_control(client):
    css = client.get("/static/app.css").text
    assert "--ui-scale" in css and "zoom: var(--ui-scale)" in css
    js = client.get("/static/js/app.js").text
    assert "setScale" in js and "'/api/prefs'" in js
