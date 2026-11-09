"""Configuration and path resolution for VM Tracker.

Data directory resolution order:
  1. env VM_TRACKER_DATA_DIR   (canonical -- env var names cannot portably contain spaces)
  2. env "VM Tracker_DATA_DIR" (literal spec name, honoured if the platform allows it)
  3. %LOCALAPPDATA%\\VM Tracker   on Windows
  4. ~/.VM Tracker                everywhere else
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "VM Tracker"
APP_SLUG = "vmtracker"
VERSION = "0.9.0"

DEFAULT_PORT = 9797
DEFAULT_HOST = "0.0.0.0"  # reachable from remote systems on the LAN

_ENV_DATA_DIR = "VM_TRACKER_DATA_DIR"
_ENV_DATA_DIR_LITERAL = "VM Tracker_DATA_DIR"


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def bundle_dir() -> Path:
    """Directory holding bundled read-only resources (web/, samples/)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def data_dir_path() -> Path:
    """Where the data directory should be, without trying to create it.

    Error handlers need the intended location even when creating it is what
    failed, so resolving and creating are kept apart.
    """
    override = os.environ.get(_ENV_DATA_DIR) or os.environ.get(_ENV_DATA_DIR_LITERAL)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    return Path.home() / f".{APP_NAME}"


def data_dir() -> Path:
    p = data_dir_path()
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return data_dir() / "vmtracker.db"


def uploads_dir() -> Path:
    p = data_dir() / "uploads"
    p.mkdir(parents=True, exist_ok=True)
    return p


def exports_dir() -> Path:
    p = data_dir() / "exports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def logs_dir() -> Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def web_dir() -> Path:
    return bundle_dir() / "web"


def port() -> int:
    return int(os.environ.get("VM_TRACKER_PORT", DEFAULT_PORT))


def host() -> str:
    return os.environ.get("VM_TRACKER_HOST", DEFAULT_HOST)
