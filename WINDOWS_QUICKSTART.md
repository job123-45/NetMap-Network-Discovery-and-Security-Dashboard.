# NetMap Windows Quickstart

1. Open PowerShell in the repository folder, create a virtual environment, and install dependencies:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

2. Start the local dashboard:

   ```powershell
   py -m streamlit run dashboard.py
   ```

3. Upload an Nmap XML file in the dashboard to review its hosts and services. To compare or export XML from the command line, see the examples in `README.md`.

4. Active scanning is optional and requires Nmap. Use `py netmap.py scan --help` or `py netmap.py discover --help` to inspect the exact syntax. Only scan private lab systems or networks you own or have explicit authorization to assess. Inspect the exact target before starting. The private-address scope guard is not permission to scan.

5. Run the automated tests with `py -m unittest discover -s tests -v`.
