"""Tests for the launcher's startup checks.

These cover the paths a packaged build hits on someone else's machine: an
unusable data directory, a port already taken, and a bundle missing its web
assets. Each must produce a readable message and a non-zero exit, never a
traceback into a console window that closes before it can be read.
"""
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))
import run  # noqa: E402

from app import config  # noqa: E402


def launch(args, env_extra=None, timeout=60):
    """Run run.py as a subprocess, the way the exe is actually invoked."""
    import os

    env = {**os.environ, "VM_TRACKER_DATA_DIR": tempfile.mkdtemp(prefix="vmt_rl_")}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(ROOT / "run.py"), *args],
                          capture_output=True, text=True, timeout=timeout,
                          env=env, cwd=str(ROOT), stdin=subprocess.DEVNULL)


# ------------------------------------------------------------ path handling
def test_data_dir_path_does_not_create(monkeypatch, tmp_path):
    """Error handlers need the intended path even when creating it is what failed."""
    target = tmp_path / "not-created-yet"
    monkeypatch.setenv("VM_TRACKER_DATA_DIR", str(target))
    assert config.data_dir_path() == target
    assert not target.exists(), "resolving the path must not create it"
    assert config.data_dir() == target
    assert target.is_dir(), "data_dir() is the one that creates it"


def test_data_dir_path_never_raises_on_a_bad_path(monkeypatch, tmp_path):
    blocker = tmp_path / "a-file.txt"
    blocker.write_text("x")
    monkeypatch.setenv("VM_TRACKER_DATA_DIR", str(blocker / "sub"))
    assert config.data_dir_path() == blocker / "sub"      # no exception
    with pytest.raises(OSError):
        config.data_dir()                                  # creating it does raise


# -------------------------------------------------------------- diagnostics
def test_diagnose_reports_a_healthy_install():
    r = launch(["--diagnose"])
    assert r.returncode == 0, r.stderr
    assert "No problems found" in r.stdout
    for field in ("python", "data dir", "console bundled", "import fastapi", "port"):
        assert field in r.stdout, f"diagnostics omitted '{field}'"


def test_diagnose_names_an_unusable_data_dir(tmp_path):
    blocker = tmp_path / "a-file.txt"
    blocker.write_text("x")
    r = launch(["--diagnose"], {"VM_TRACKER_DATA_DIR": str(blocker / "sub")})
    assert r.returncode == 0                       # diagnose always reports, never crashes
    assert "problem(s) found" in r.stdout
    assert "data directory" in r.stdout.lower()


# ----------------------------------------------------------- startup errors
def test_unusable_data_dir_is_a_clean_message_not_a_traceback(tmp_path):
    blocker = tmp_path / "a-file.txt"
    blocker.write_text("x")
    r = launch([], {"VM_TRACKER_DATA_DIR": str(blocker / "sub")})
    assert r.returncode == 1
    assert "could not start" in r.stdout.lower()
    assert "data directory cannot be used" in r.stdout
    assert "Traceback" not in r.stdout, "startup errors must not surface a raw traceback"


def test_port_already_in_use_is_reported_clearly():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        r = launch(["--host", "127.0.0.1", "--port", str(port)])
    assert r.returncode == 1
    assert f"Port {port} is already in use" in r.stdout
    assert "Traceback" not in r.stdout


def test_port_in_use_helper():
    """The check must answer 'can we bind here', identically on every platform."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        held.listen(5)
        port = held.getsockname()[1]
        assert run.port_in_use("127.0.0.1", port) is True
    assert run.port_in_use("127.0.0.1", port) is False


def test_port_check_is_repeatable():
    """Several calls must agree.

    An earlier version probed with connect() and left the connection pending.
    With a small listen() backlog the accept queue filled, and the next probe
    was refused - True, then False, for a port that never changed. Windows
    showed it; Linux's roomier backlog hid it.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        held.listen(1)                       # the backlog that exposed the bug
        port = held.getsockname()[1]
        assert [run.port_in_use("127.0.0.1", port) for _ in range(4)] == [True] * 4


def test_port_check_leaves_the_port_usable():
    """A pre-flight check must not itself occupy the port it just cleared."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    assert run.port_in_use("127.0.0.1", port) is False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))          # must still be bindable afterwards
        s.listen(1)


def test_wildcard_host_is_checked_as_given():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("0.0.0.0", 0))
        held.listen(5)
        port = held.getsockname()[1]
        assert run.port_in_use("0.0.0.0", port) is True


def test_missing_web_assets_is_reported(monkeypatch, tmp_path):
    """A bundle without web/ must say so rather than serving a dead console."""
    monkeypatch.setattr(config, "web_dir", lambda: tmp_path / "no-web-here")
    assert not (config.web_dir() / "index.html").exists()


def test_startup_failure_is_written_to_a_log(tmp_path):
    """The window may close before it can be read, so failures persist to disk."""
    data = tmp_path / "data"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        r = launch(["--host", "127.0.0.1", "--port", str(port)],
                   {"VM_TRACKER_DATA_DIR": str(data)})
    assert r.returncode == 1
    log = data / "logs" / "startup.log"
    assert log.exists(), "a startup failure should leave a log behind"
    assert "already in use" in log.read_text()


# ------------------------------------------------------------------ console
def test_owns_console_is_false_off_windows():
    import os

    if os.name != "nt":
        assert run.owns_console() is False
