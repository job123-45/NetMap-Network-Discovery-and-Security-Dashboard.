@echo off
setlocal
cd /d "%~dp0"
echo NetMap Windows prerequisite helper
echo This helper may use winget to install Python and will open the official Nmap download page if needed.
echo.
where py >nul 2>nul
if errorlevel 1 (
  where winget >nul 2>nul
  if errorlevel 1 (
    echo Python was not found and winget is unavailable.
    echo Install Python from https://www.python.org/downloads/windows/ then reopen this window.
    start "" "https://www.python.org/downloads/windows/"
    pause
    exit /b 1
  )
  echo Installing current Python 3.14 package through winget...
  winget install --id Python.Python.3.14 -e --accept-package-agreements --accept-source-agreements
  echo.
  echo Close this window and open a NEW one so PATH changes are picked up.
)
where nmap >nul 2>nul
if errorlevel 1 (
  echo Nmap was not found. Opening the official Nmap download page.
  start "" "https://nmap.org/download.html"
  echo Install Nmap for Windows and keep the option to add Nmap to PATH enabled if offered.
  echo Include Npcap when the installer offers it.
)
echo.
echo After installation, open a NEW terminal in this folder and run:
echo   py --version
echo   nmap --version
echo   py netmap.py check
echo.
echo Then double-click Run-Demo.bat for the offline dashboard or Run-NetMap-Windows.bat for a confirmed self-scan.
pause
