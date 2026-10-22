# NetMap Windows quickstart — real scan required

## Start NetMap

From PowerShell in the project folder:

```powershell
py -m pip install -r requirements.txt
py -m streamlit run dashboard.py
```

Or double-click `Run-Demo.bat`; despite its retained filename, it only installs declared dashboard dependencies and launches NetMap. It does not generate sample reports or launch Nmap. The app begins at a scan-selection page.

## Load a scan

1. Choose **Select a saved scan** to pick a validated XML under `scans/`, or choose **Upload a scan** and provide an XML file.
2. Click **Load Scan**. NetMap checks that the file is Nmap XML before opening the dashboard.
3. Overview and the single-scan pages now use this one real XML source. The filename and scan timestamp are visible. Use **Change scan** in the sidebar to return to selection and replace the current scan.
4. CSV and HTML exports contain the currently loaded scan only.

A new app session starts without loaded results and never substitutes sample data. Invalid input is rejected; a valid scan with no hosts or ports shows an explanatory empty state.

## Compare scans

Open **Comparison** after loading a scan. Select valid saved XML for **Baseline scan (original scan)** and **After scan (later scan)**, or choose **Upload two scans** and load one XML into each independent input. Comparison requires both files and reports opened, no-longer-open, and service-fingerprint changes, along with both filenames and timestamps. CSV and HTML comparison downloads contain the selected pair only.

The project includes `scans/live_scan.xml` and `scans/live_scan_after.xml`. Each reports target `172.17.104.158`, one host up and four open TCP ports (135, 139, 445, 8080); the pair has no observed differences. Port 8080's Nmap service/product identification is a fingerprint, not proof of installed Oracle software. An open port by itself does not establish vulnerability.

## Checks

```powershell
py -m unittest discover -s tests -v
py -m py_compile netmap.py dashboard.py tests/test_netmap.py tests/test_dashboard_overview.py
py -m pip check
```

## Capture context and report

The saved `scans/nmap_scan_capture.pcapng` has 94 frames but does not corroborate these scans. Broad filter matches are ICMP host-unreachable packets quoting unrelated port 7680 SYNs; the direct target/scan-port SYN filter matched none, and the capture was between the scan times. See README for details. No screenshot or firewall/VM result is included.

Nmap is not currently on PATH in this environment, so no new scan was run. `NetMap_Assessment_9_Report.docx` and `.pdf` were not regenerated. See `FINAL_CHECKLIST.md` for manual submission steps.
