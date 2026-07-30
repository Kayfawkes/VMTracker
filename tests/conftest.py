"""Shared test setup.

Every test module points the app at its own data directory. Because pytest
imports all test modules before running any of them, modules must not mutate the
environment at import time — the last import would win and quietly reconfigure
the others. Each module instead calls use_data_dir() from an autouse fixture, and
the app re-reads the environment on every path lookup.
"""
from __future__ import annotations

import os

from app import db


def use_data_dir(path: str, admin_password: str | None = None) -> None:
    """Point the app at `path` and reset any pooled connection to the old database."""
    os.environ["VM_TRACKER_DATA_DIR"] = str(path)
    if admin_password is None:
        os.environ.pop("VM_TRACKER_ADMIN_PASSWORD", None)
    else:
        os.environ["VM_TRACKER_ADMIN_PASSWORD"] = admin_password
    db.reset_thread_conn()
