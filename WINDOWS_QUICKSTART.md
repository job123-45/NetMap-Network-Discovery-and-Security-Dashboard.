# NetMap Windows quickstart

1. In PowerShell at the repository root:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

   For the complete CI/test toolset, install `requirements-dev.txt` instead (it includes `requirements.txt`). Do not upgrade packages individually; the direct application and audit-tool versions are pinned in those files.

2. Run the deterministic synthetic report workflow:

   ```powershell
   py netmap.py demo
   ```

3. Start the local dashboard:

   ```powershell
   py -m streamlit run dashboard.py
   ```

   Click **Load synthetic demonstration** to explore the fixture. The page is labeled synthetic and no fixture appears automatically.

4. Import XML by uploading it or placing it under the local-only `scans/` directory. Files are limited to 20 MiB. Dashboard imports never start a scan.

   Snapshots and findings are saved in the local SQLite database. Use **Scan History** to reopen saved data, **Comparison** to compare two XML files, **Finding Triage** to record status and notes, and **Data Management** for verified backup/restore and selected-snapshot deletion. `py netmap.py db init` creates the operational database; the bundled demo is stored separately.

5. Run checks:

   ```powershell
   py -m unittest discover -s tests -v
   py -m py_compile netmap.py netmap_models.py netmap_store.py dashboard.py tests\test_netmap.py tests\test_netmap_store.py tests\test_dashboard_overview.py tests\test_end_to_end.py
   py -m ruff check netmap.py netmap_models.py netmap_store.py dashboard.py tests\test_netmap.py tests\test_netmap_store.py tests\test_dashboard_overview.py tests\test_end_to_end.py
   py -m ruff format --check netmap.py netmap_models.py netmap_store.py dashboard.py tests\test_netmap.py tests\test_netmap_store.py tests\test_dashboard_overview.py tests\test_end_to_end.py
   py -m pip check
   ```

Nmap is only required for optional CLI scans. Read `README.md` and `SECURITY.md` first. Active scanning requires `--authorized-lab-target`, accepts only bounded private/loopback IPv4 lab targets, and must only be used with explicit authorization. The dashboard is local-only and binds to loopback.
