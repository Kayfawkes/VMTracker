# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for VM Tracker.

Build:
    pyinstaller packaging/vmtracker.spec --noconfirm

Produces dist/VMTracker/ (one folder, faster start) containing VMTracker[.exe].
Use ONEFILE=1 in the environment for a single-file build instead.
"""
import os
import sys
from pathlib import Path

sys.setrecursionlimit(5000)

ROOT = Path(os.path.abspath(SPECPATH)).parent
ONEFILE = os.environ.get("ONEFILE") == "1"

datas = [
    (str(ROOT / "web"), "web"),
    (str(ROOT / "samples" / "scan_week1.csv"), "samples"),
    (str(ROOT / "samples" / "mitigations.xlsx"), "samples"),
    (str(ROOT / "README.md"), "."),
]

hiddenimports = [
    "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto", "uvicorn.protocols",
    "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan", "uvicorn.lifespan.on",
    "apscheduler.schedulers.background", "apscheduler.executors.pool",
    "apscheduler.triggers.cron", "apscheduler.triggers.interval",
    "openpyxl", "xlsxwriter", "pptx", "reportlab.graphics.barcode",
    "app.api", "app.auth", "app.classify", "app.config", "app.db", "app.exports",
    "app.filters", "app.ingest", "app.jobs", "app.main", "app.parsing", "app.queries",
]

# Trim the bundle: none of these are used at runtime.
excludes = ["tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL.ImageQt",
            "PyQt5", "PySide2", "IPython", "notebook", "pytest", "playwright"]

a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)

icon = ROOT / "packaging" / "vmtracker.ico"
icon_arg = str(icon) if icon.exists() else None

# Version resource is a Windows-only PE feature; PyInstaller ignores it elsewhere.
vinfo = ROOT / "packaging" / "version_info.txt"
version_arg = str(vinfo) if (sys.platform == "win32" and vinfo.exists()) else None

if ONEFILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
        name="VMTracker",
        console=True,
        upx=False,
        icon=icon_arg,
        version=version_arg,
    )
else:
    exe = EXE(
        pyz, a.scripts, [],
        exclude_binaries=True,
        name="VMTracker",
        console=True,
        upx=False,
        icon=icon_arg,
        version=version_arg,
    )
    coll = COLLECT(
        exe, a.binaries, a.zipfiles, a.datas,
        strip=False, upx=False, name="VMTracker",
    )
