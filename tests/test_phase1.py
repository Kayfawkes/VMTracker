"""Phase 1 smoke test: paths, idempotent migrations, health endpoint."""
import os
import sqlite3
import tempfile

os.environ.setdefault("VM_TRACKER_DATA_DIR", tempfile.mkdtemp(prefix="vmt1_"))

from fastapi.testclient import TestClient  # noqa: E402

from app import config, db  # noqa: E402
from app.main import app  # noqa: E402


def test_data_dir_honours_env_override():
    assert str(config.data_dir()) == os.environ["VM_TRACKER_DATA_DIR"]
    assert config.db_path().parent == config.data_dir()


def test_init_db_creates_all_tables():
    conn = db.connect(":memory:")
    report = db.init_db(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in db.TABLES:
        assert t in names, f"missing table {t}"
    assert report["schema_version"] == db.SCHEMA_VERSION


def test_migration_is_idempotent_and_preserves_data():
    conn = db.connect(":memory:")
    db.init_db(conn)
    conn.execute(
        "INSERT INTO assets(asset_key,hostname,department) VALUES('k1','srv-01','Finance')"
    )
    conn.commit()

    # simulate a later release adding a column, then re-running init twice
    assert db.ensure_column(conn, "assets", "new_field_v2", "TEXT") is True
    assert db.ensure_column(conn, "assets", "new_field_v2", "TEXT") is False  # no-op second time
    db.init_db(conn)
    db.init_db(conn)

    rows = conn.execute("SELECT hostname, department FROM assets").fetchall()
    assert len(rows) == 1 and rows[0]["hostname"] == "srv-01"
    assert "new_field_v2" in db.columns_of(conn, "assets")


def test_sla_defaults_seeded_once():
    conn = db.connect(":memory:")
    db.init_db(conn)
    db.init_db(conn)
    rows = conn.execute("SELECT severity, days FROM sla_policy ORDER BY days").fetchall()
    assert len(rows) == len(db.DEFAULT_SLA)
    assert dict((r["severity"], r["days"]) for r in rows)["Critical"] == 15


def test_health_endpoint():
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "findings" in body["tables"] and "class_rules" in body["tables"]
        assert body["schema_version"] == db.SCHEMA_VERSION


def test_settings_roundtrip():
    conn = db.connect(":memory:")
    db.init_db(conn)
    db.set_setting("org_name", "Acme Bank", conn)
    assert db.get_setting("org_name", conn=conn) == "Acme Bank"
    db.set_setting("org_name", "Acme Bank PLC", conn)
    assert db.get_setting("org_name", conn=conn) == "Acme Bank PLC"


def test_sqlite_file_actually_created():
    with TestClient(app) as client:
        client.get("/api/health")
    assert config.db_path().exists()
    con = sqlite3.connect(config.db_path())
    assert con.execute("SELECT count(*) FROM sla_policy").fetchone()[0] == 5
    con.close()
