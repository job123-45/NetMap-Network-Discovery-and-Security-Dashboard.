@echo off
setlocal
cd /d "%~dp0"
echo NetMap - Windows live scan of this computer only
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_live_scan.ps1"
echo.
pause
