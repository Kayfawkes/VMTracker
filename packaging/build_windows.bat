@echo off
REM ===========================================================================
REM  Build VM Tracker for Windows: executable + installer
REM  Prerequisites: Python 3.11+, Inno Setup 6 (iscc.exe on PATH)
REM ===========================================================================
setlocal
cd /d "%~dp0\.."

echo [1/4] Installing dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt pyinstaller || goto :fail

echo [2/4] Running tests...
python -m pytest tests -q || goto :fail

echo [3/4] Building executable...
rmdir /s /q build dist 2>nul
python -m PyInstaller packaging\vmtracker.spec --noconfirm || goto :fail

echo [4/4] Building installer...
where iscc >nul 2>nul
if errorlevel 1 (
  echo   Inno Setup ^(iscc.exe^) not found on PATH - skipping installer.
  echo   Portable build is ready in dist\VMTracker\
  goto :done
)
iscc packaging\installer.iss || goto :fail
echo   Installer written to packaging\Output\

:done
echo.
echo Build complete.
echo   Portable : dist\VMTracker\VMTracker.exe
echo   Installer: packaging\Output\
exit /b 0

:fail
echo.
echo BUILD FAILED - see the output above.
exit /b 1
