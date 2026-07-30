"""VM Tracker launcher.

Dev:   python run.py
Frozen: VMTracker.exe  (same code path, PyInstaller entry point)
"""
from __future__ import annotations

import argparse
import socket
import sys

import uvicorn

from app import config


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vmtracker", description=f"{config.APP_NAME} server")
    ap.add_argument("--host", default=config.host())
    ap.add_argument("--port", type=int, default=config.port())
    ap.add_argument("--data-dir", default=None, help="override data directory")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args(argv)

    if args.data_dir:
        import os

        os.environ["VM_TRACKER_DATA_DIR"] = args.data_dir

    if not args.no_banner:
        print(f"  {config.APP_NAME} {config.VERSION}")
        print(f"  data dir : {config.data_dir()}")
        print(f"  database : {config.db_path()}")
        print(f"  console  : http://127.0.0.1:{args.port}/   (LAN: http://{lan_ip()}:{args.port}/)")
        print(f"  api docs : http://127.0.0.1:{args.port}/api/docs\n")

    uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="info", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
