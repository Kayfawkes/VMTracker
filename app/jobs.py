"""Background jobs (APScheduler).

  aging      02:10 daily  - recompute age, due dates and SLA breach flags
  sessions   hourly       - purge expired login sessions
  watch      5 minutes    - auto-import any scan dropped into <data dir>/watch
  vacuum     Sunday 03:00 - SQLite maintenance

The watch folder exists because weekly scanning is a routine: drop the export in,
and it is ingested, filed under the scan log and moved to watch/processed.
"""
from __future__ import annotations

import datetime as dt
import shutil
import traceback
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from . import auth, config, db, ingest

SCHEDULER: BackgroundScheduler | None = None
WATCH_SUFFIXES = (".csv", ".tsv", ".xlsx", ".xlsm", ".json", ".nessus", ".xml")


def _record(job: str, started: dt.datetime, status: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO job_runs(job,started_at,ended_at,status,detail) VALUES(?,?,?,?,?)",
        (job, started.isoformat(timespec="seconds"),
         dt.datetime.now().isoformat(timespec="seconds"), status, detail[:1000]),
    )


def run_job(name: str, fn) -> None:
    started = dt.datetime.now()
    try:
        detail = fn() or ""
        _record(name, started, "ok", str(detail))
    except Exception:
        _record(name, started, "failed", traceback.format_exc())
    finally:
        db.reset_thread_conn()


def job_aging() -> str:
    n = ingest.recompute_aging()
    return f"recomputed {n} findings"


def job_sessions() -> str:
    return f"purged {auth.purge_expired_sessions()} expired sessions"


def job_vacuum() -> str:
    conn = db.get_conn()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    return "database compacted"


WATCH_SETTING = "watch_folder"


def default_watch_dir():
    return config.data_dir() / "watch"


def watch_dir():
    """Operator-configurable drop folder; falls back to <data dir>/watch."""
    custom = db.get_setting(WATCH_SETTING)
    p = Path(custom).expanduser() if custom else default_watch_dir()
    try:
        (p / "processed").mkdir(parents=True, exist_ok=True)
        (p / "failed").mkdir(parents=True, exist_ok=True)
    except OSError:
        p = default_watch_dir()
        (p / "processed").mkdir(parents=True, exist_ok=True)
        (p / "failed").mkdir(parents=True, exist_ok=True)
    return p


def set_watch_dir(path: str | None) -> dict:
    """Validate and store a custom watch folder. Empty resets to the default."""
    if not path or not str(path).strip():
        db.execute("DELETE FROM settings WHERE key=?", (WATCH_SETTING,))
        return {"watch_folder": str(watch_dir()), "custom": False}
    p = Path(str(path).strip()).expanduser()
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".vmtracker-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise ValueError(f"Cannot use that folder: {exc}")
    db.set_setting(WATCH_SETTING, str(p))
    return {"watch_folder": str(watch_dir()), "custom": True}


def job_watch() -> str:
    wd = watch_dir()
    handled = []
    for path in sorted(wd.iterdir()):
        if not path.is_file() or path.suffix.lower() not in WATCH_SUFFIXES:
            continue
        kind = "mitigation" if "mitig" in path.name.lower() or "remedi" in path.name.lower() \
            else "scan"
        try:
            res = ingest.import_scan(path.read_bytes(), path.name, kind=kind,
                                     actor="scheduler:watch")
            shutil.move(str(path), str(wd / "processed" / path.name))
            handled.append(f"{path.name}: {res.get('rows_imported', 0)} rows, "
                           f"{res.get('findings_new', 0)} new, "
                           f"{res.get('findings_closed', 0)} closed")
        except Exception as exc:
            shutil.move(str(path), str(wd / "failed" / path.name))
            handled.append(f"{path.name}: FAILED - {exc}")
    return "; ".join(handled) if handled else ""


def start() -> BackgroundScheduler:
    global SCHEDULER
    if SCHEDULER:
        return SCHEDULER
    sched = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True,
                                                             "max_instances": 1})
    sched.add_job(lambda: run_job("aging", job_aging), "cron", hour=2, minute=10, id="aging")
    sched.add_job(lambda: run_job("sessions", job_sessions), "interval", hours=1, id="sessions")
    sched.add_job(lambda: run_job("watch", job_watch), "interval", minutes=5, id="watch")
    sched.add_job(lambda: run_job("vacuum", job_vacuum), "cron", day_of_week="sun", hour=3,
                  id="vacuum")
    sched.start()
    SCHEDULER = sched
    watch_dir()
    return sched


def stop() -> None:
    global SCHEDULER
    if SCHEDULER:
        SCHEDULER.shutdown(wait=False)
        SCHEDULER = None


def status() -> dict:
    jobs = []
    if SCHEDULER:
        for j in SCHEDULER.get_jobs():
            jobs.append({"id": j.id,
                         "next_run": j.next_run_time.isoformat() if j.next_run_time else None})
    return {"running": SCHEDULER is not None, "jobs": jobs,
            "watch_folder": str(watch_dir()),
            "watch_folder_default": str(default_watch_dir()),
            "watch_folder_custom": bool(db.get_setting(WATCH_SETTING)),
            "recent": db.q("SELECT * FROM job_runs ORDER BY id DESC LIMIT 20")}
