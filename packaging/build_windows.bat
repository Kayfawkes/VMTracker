@echo off
REM ===========================================================================
REM  VM Tracker - build VMTracker.exe on Windows
REM
REM  Double-click this file, or run it from a command prompt. All the work is
REM  done by build_windows.ps1; this wrapper exists so you do not have to think
REM  about PowerShell's execution policy, which blocks downloaded .ps1 files by
REM  default. -ExecutionPolicy Bypass applies to this one run only and changes
REM  nothing on the machine.
REM
REM  Pass any of the script's switches straight through, for example:
REM      build_windows.bat -OneFile -Installer
REM      build_windows.bat -SkipTests
REM      build_windows.bat -Clean
REM ===========================================================================
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1" %*
set RC=%ERRORLEVEL%

REM Keep the window open when double-clicked, so the result stays readable.
echo %CMDCMDLINE% | find /i "/c" >nul
if not errorlevel 1 (
  echo.
  pause
)

exit /b %RC%
