# NetMap

NetMap is a local dashboard and command-line tool for authorized lab network discovery and review of Nmap XML results. It displays discovered hosts and services, compares two XML snapshots, and exports CSV and HTML reports. The dashboard does not start scans; scan commands are explicit CLI operations.

## Requirements

- Python 3.10 or later
- Nmap only for the optional `scan` and `discover` commands

Install the Python dependencies and launch the dashboard from the repository root:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
py -m streamlit run dashboard.py
```

On Linux or macOS, use `python3 -m venv .venv`, activate `.venv/bin/activate`, install `requirements.txt`, and run `python3 -m streamlit run dashboard.py`.

## Review XML and create reports

Import an Nmap XML file through the dashboard, or use the CLI:

```powershell
py netmap.py report path\to\authorized-scan.xml --csv outputs\report.csv --html outputs\report.html
py netmap.py compare path\to\baseline.xml path\to\later.xml --csv outputs\comparison.csv --html outputs\comparison.html
```

These commands process files locally. Review generated reports before sharing them because they may contain network inventory and service details.

## Optional active scans

Only scan systems and networks you own or have explicit authorization to assess. NetMap's scan commands are intended for private lab targets; this scope check does not grant permission. Inspect the exact target and scan scope before starting. The CLI does not silently start a scan when launching the dashboard.

Check the implemented options without scanning:

```powershell
py netmap.py scan --help
py netmap.py discover --help
```

Then use only the exact authorized private lab target with the documented CLI syntax. Never copy a target from an unrelated example or run a scan until you have verified the target and permission.

## Tests

```powershell
py -m unittest discover -s tests -v
py -m py_compile netmap.py dashboard.py tests\test_netmap.py tests\test_dashboard_overview.py
```

See `WINDOWS_QUICKSTART.md` for the short Windows setup flow.
