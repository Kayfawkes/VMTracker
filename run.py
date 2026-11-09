"""VM Tracker launcher.

Dev:    python run.py
Frozen: VMTracker.exe  (same code path, PyInstaller entry point)

Anything that goes wrong during startup is printed, written to
<data dir>/logs/startup.log, and — when the window was opened by
double-clicking — held on screen so the message can actually be read.
"""
from __future__ import annotations

import argparse
import datetime as dt
import multiprocessing
import os
import socket
import sys
import traceback
from pathlib import Path

BANNER_WIDTH = 66


# --------------------------------------------------------------------------
# Console helpers
# --------------------------------------------------------------------------
def owns_console() -> bool:
    """True when this process opened the console window itself.

    A double-clicked exe owns its window, so the window disappears the instant
    the process ends and any error with it. Launched from an existing prompt,
    the shell owns the window and the text stays put.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes

        buf = (ctypes.c_uint32 * 4)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(buf, 4)
        return n <= 1
    except Exception:
        return False


def hold_window(code: int) -> int:
    """Keep a double-clicked window open long enough to read the message."""
    if owns_console():
        try:
            print()
            input("Press Enter to close this window . . . ")
        except (EOFError, KeyboardInterrupt, OSError):
            pass
    return code


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def port_in_use(host: str, port: int) -> bool:
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.6)
        return s.connect_ex((probe_host, port)) == 0


def log_startup_failure(message: str) -> Path | None:
    """Record a failure where it can still be found after the window closes."""
    try:
        from app import config

        path = config.logs_dir() / "startup.log"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n{'=' * 70}\n{dt.datetime.now().isoformat(timespec='seconds')}\n")
            fh.write(message.rstrip() + "\n")
        return path
    except Exception:
        return None


def fail(title: str, detail: str, hint: str = "") -> int:
    body = f"{title}\n{detail}" + (f"\n\n{hint}" if hint else "")
    print(f"\n  {'-' * BANNER_WIDTH}")
    print(f"  {title}")
    print(f"  {'-' * BANNER_WIDTH}")
    for line in detail.splitlines():
        print(f"  {line}")
    if hint:
        print()
        for line in hint.splitlines():
            print(f"  {line}")
    written = log_startup_failure(body)
    if written:
        print(f"\n  Also written to: {written}")
    return hold_window(1)


# --------------------------------------------------------------------------
# Diagnostics
# --------------------------------------------------------------------------
def diagnose(args) -> int:
    """Print everything needed to work out why startup fails on this machine."""
    print(f"\n  VM Tracker - startup diagnostics")
    print(f"  {'-' * BANNER_WIDTH}")
    rows: list[tuple[str, str]] = [
        ("python", sys.version.split()[0]),
        ("executable", sys.executable),
        ("frozen", str(getattr(sys, "frozen", False))),
        ("bundle dir", str(getattr(sys, "_MEIPASS", "(not frozen)"))),
        ("platform", f"{sys.platform} / {os.name}"),
        ("cwd", os.getcwd()),
    ]
    problems: list[str] = []

    try:
        from app import config

        rows += [
            ("version", config.VERSION),
            ("data dir", str(config.data_dir_path())),
            ("web assets", str(config.web_dir())),
            ("host:port", f"{args.host}:{args.port}"),
        ]
        index = config.web_dir() / "index.html"
        rows.append(("console bundled", "yes" if index.exists() else "NO - web/ is missing"))
        if not index.exists():
            problems.append("The web console was not bundled into this build.")

        try:
            probe = config.data_dir() / ".write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            rows.append(("data dir writable", "yes"))
        except OSError as exc:
            rows.append(("data dir writable", f"NO - {exc}"))
            problems.append(f"Cannot write to the data directory: {exc}")
    except Exception as exc:
        rows.append(("config", f"FAILED - {exc}"))
        problems.append(f"The application package failed to load: {exc}")

    for mod in ("fastapi", "uvicorn", "apscheduler", "openpyxl", "xlsxwriter",
                "reportlab", "pptx", "multipart"):
        try:
            __import__(mod)
            rows.append((f"import {mod}", "ok"))
        except Exception as exc:
            rows.append((f"import {mod}", f"MISSING - {exc}"))
            problems.append(f"Bundled dependency '{mod}' is missing from this build.")

    busy = port_in_use(args.host, args.port)
    rows.append((f"port {args.port}", "IN USE" if busy else "free"))
    if busy:
        problems.append(f"Port {args.port} is already taken by another process.")

    for label, value in rows:
        print(f"  {label:<20} {value}")

    print(f"  {'-' * BANNER_WIDTH}")
    if problems:
        print(f"  {len(problems)} problem(s) found:")
        for p in problems:
            print(f"    - {p}")
    else:
        print("  No problems found. The server should start normally.")
    print()
    return hold_window(0)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vmtracker", description="VM Tracker server")
    ap.add_argument("--host", default=None, help="interface to bind (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=None, help="port to listen on (default 9797)")
    ap.add_argument("--data-dir", default=None, help="override the data directory")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--diagnose", action="store_true",
                    help="check this installation and report problems, then exit")
    args = ap.parse_args(argv)

    if args.data_dir:
        os.environ["VM_TRACKER_DATA_DIR"] = str(Path(args.data_dir).expanduser())

    # Import the package only after the data dir is set, and report a failed
    # import plainly: in a frozen build it means the bundle is incomplete.
    try:
        from app import config
    except Exception:
        return fail(
            "VM Tracker could not start",
            "The application package failed to load:\n\n"
            + traceback.format_exc(limit=3).rstrip(),
            "If this is the packaged build, the folder is probably incomplete.\n"
            "Keep the whole VMTracker folder together - VMTracker.exe cannot run on its own.",
        )

    if args.host is None:
        args.host = config.host()
    if args.port is None:
        args.port = config.port()

    if args.diagnose:
        return diagnose(args)

    try:
        data = config.data_dir()
        probe = data / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return fail(
            "VM Tracker could not start",
            f"The data directory cannot be used:\n  {config.data_dir_path()}\n  {exc}",
            "Pick somewhere you can write to, for example:\n"
            '  VMTracker.exe --data-dir "D:\\VMTrackerData"',
        )

    if port_in_use(args.host, args.port):
        return fail(
            f"Port {args.port} is already in use",
            "Another program is listening on that port - most likely VM Tracker\n"
            "is already running. Check http://127.0.0.1:%d/ in a browser." % args.port,
            f"To run a second copy on another port:\n  VMTracker.exe --port {args.port + 1}",
        )

    if not (config.web_dir() / "index.html").exists():
        return fail(
            "The web console is missing from this build",
            f"Expected it at:\n  {config.web_dir()}",
            "Rebuild with packaging\\build_windows.bat, and keep the whole\n"
            "VMTracker folder together when you copy it somewhere else.",
        )

    try:
        import uvicorn

        from app.main import app as asgi_app
    except Exception:
        return fail(
            "VM Tracker could not start",
            "A required component failed to load:\n\n"
            + traceback.format_exc(limit=3).rstrip(),
            "Run 'VMTracker.exe --diagnose' for a full report.",
        )

    if not args.no_banner:
        print(f"\n  {config.APP_NAME} {config.VERSION}")
        print(f"  data dir : {config.data_dir()}")
        print(f"  database : {config.db_path()}")
        print(f"  console  : http://127.0.0.1:{args.port}/")
        if args.host not in ("127.0.0.1", "localhost"):
            print(f"  network  : http://{lan_ip()}:{args.port}/")
        print(f"  api docs : http://127.0.0.1:{args.port}/api/docs")
        print(f"\n  Leave this window open. Press Ctrl+C to stop the server.\n")

    try:
        # Pass the application object rather than an "app.main:app" import
        # string: a frozen build has no importable source tree for uvicorn to
        # resolve that string against.
        uvicorn.run(asgi_app, host=args.host, port=args.port,
                    log_level="info", access_log=False)
    except KeyboardInterrupt:
        print("\n  Stopped.")
        return 0
    except OSError as exc:
        return fail(
            "VM Tracker could not bind to the network",
            f"{args.host}:{args.port} - {exc}",
            "Another process may hold the port, or the address may not exist\n"
            "on this machine. Try:  VMTracker.exe --host 127.0.0.1",
        )
    except Exception:
        return fail(
            "VM Tracker stopped unexpectedly",
            traceback.format_exc().rstrip(),
            "Run 'VMTracker.exe --diagnose' for a full report.",
        )
    return 0


if __name__ == "__main__":
    # Windows has no fork(): a frozen child process re-runs this file from the
    # top, so without this a spawned worker would start the whole server again.
    multiprocessing.freeze_support()
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        sys.exit(fail("VM Tracker stopped unexpectedly", traceback.format_exc().rstrip()))
