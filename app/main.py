"""VM Tracker - FastAPI backend + static operator console host."""
from __future__ import annotations

import datetime as dt
import socket
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import api, auth, config, db

STARTED_AT = dt.datetime.now(dt.timezone.utc)

@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.migration_report = db.init_db()
    pwd = auth.bootstrap_admin()
    if pwd:
        print("\n  First run: administrator account created")
        print(f"    username: admin\n    password: {pwd}")
        print(f"    (also written to {config.data_dir() / 'initial-admin-password.txt'})\n")
    auth.purge_expired_sessions()
    yield
    db.reset_thread_conn()


app = FastAPI(
    title=f"{config.APP_NAME} API",
    version=config.VERSION,
    docs_url="/api/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local-first LAN tool; console is served from same origin
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    conn = db.get_conn()
    tables = [
        r["name"]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    ]
    return {
        "status": "ok",
        "app": config.APP_NAME,
        "version": config.VERSION,
        "schema_version": int(db.get_setting("schema_version", "0")),
        "tables": tables,
        "data_dir": str(config.data_dir()),
        "db_path": str(config.db_path()),
        "host": socket.gethostname(),
        "started_at": STARTED_AT.isoformat(),
        "uptime_seconds": round((dt.datetime.now(dt.timezone.utc) - STARTED_AT).total_seconds(), 1),
    }


@app.get("/api/meta")
def meta() -> dict:
    return {
        "app": config.APP_NAME,
        "version": config.VERSION,
        "port": config.port(),
        "migration": getattr(app.state, "migration_report", {}),
    }


app.include_router(api.router)


def mount_console() -> None:
    web = config.web_dir()
    if web.exists():
        app.mount("/static", StaticFiles(directory=str(web)), name="static")

        @app.get("/")
        def index():  # pragma: no cover - trivial
            idx = web / "index.html"
            if idx.exists():
                return FileResponse(str(idx))
            return JSONResponse({"detail": "console not built yet"}, status_code=404)


mount_console()
