@echo off
setlocal
cd /d "%~dp0"
echo =====================================================
echo NetMap - NETWORK DISCOVERY DASHBOARD
echo Upload an authorized Nmap XML scan or choose the synthetic demo.
echo =====================================================
echo.
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher py was not found. Install Python from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
py -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo.
echo Starting NetMap. The dashboard can load authorized XML or clearly labeled synthetic data.
py -m streamlit run dashboard.py
if errorlevel 1 goto failed
goto done
:failed
echo NetMap could not start. See the error above and read WINDOWS_QUICKSTART.md.
pause
exit /b 1
:done
pause
