# NetMap implementation status — real-scan workflow

## Application flow

- New Streamlit sessions open on a scan-selection screen, not a data dashboard. Users can select a valid Nmap XML file from `scans/` or upload an XML file.
- XML is parsed and validated before the dashboard is opened. Invalid XML is rejected. No sample data is automatically loaded.
- One session-selected real scan feeds Overview, Host Discovery, Ports & Services, and Reports & Exports. Changing scans clears the prior result before returning to selection.
- Sidebar contains only Overview, Host Discovery, Ports & Services, Comparison, and Reports & Exports.
- Comparison remains two-source: independently select saved baseline/after scans or upload two separate valid Nmap XML files. It reports newly open ports, ports no longer observed open, and changed service fingerprints. No synthetic fallback exists.
- CSV/HTML exports use current loaded scan data; comparison exports use the two selected real scans. HTML escapes untrusted report values.
- Sample fixtures remain for automated tests only. The dashboard and launcher no longer read or generate demo results.

## Verification on 2026-10-22

- `py -m unittest discover -s tests -v`: 15 tests passed, including four Streamlit AppTest cases.
- `py -m py_compile netmap.py dashboard.py tests/test_netmap.py tests/test_dashboard_overview.py`: passed.
- `py -m pip check`: no broken requirements.
- UI tests verified a fresh session has no metrics/tables/charts; saved scan selection and valid upload load actual scan records; changing scans updates filename/timestamp and displayed scan data; invalid XML is rejected; a valid empty scan shows empty states; comparison requires two real inputs and offers CSV/HTML exports.
- `Run-Demo.bat` now only installs declared dependencies and starts Streamlit; it started on port 8501. It was manually stopped with Ctrl+C (batch exit status 1 from interruption); no synthetic reports were generated.
- The real saved XML pair remains unchanged and previously parsed as one host up and four open TCP ports (135, 139, 445, 8080) in each scan; the saved pair has no differences.
- Prior `tshark` inspection found 94 packets. The suggested broad filter matches six ICMP host-unreachable messages with quoted SYNs to unrelated hosts on port 7680; a direct target/scan-port SYN filter matched none. The capture falls between the two scans and does not corroborate them.

## Not verified / remaining

- A manual browser session and browser download clicks were not run in this audit; AppTest checked the load, comparison and export controls.
- `nmap --version` is unavailable because Nmap is not on PATH. The saved XML records Nmap 7.80; no new scan was run.
- No screenshot files were present except `architecture.png`; no screenshot is claimed.
- The existing Assessment-9 DOCX/PDF was not regenerated. Update both in Word if the submission report needs to describe the revised real-only workflow.
- No new packet capture, firewall experiment, or VM experiment was performed.

## Evidence paths

- Saved XML/text: `scans/live_scan.xml`, `scans/live_scan.txt`, `scans/live_scan_after.xml`, `scans/live_scan_after.txt`.
- Original packet capture (unchanged): `scans/nmap_scan_capture.pcapng`.
- Saved-scan exports: `outputs/live_scan_report.csv`, `outputs/live_scan_hosts.csv`, `outputs/live_scan_report.html`, `outputs/live_scan_comparison.csv`, `outputs/live_scan_comparison.html`.
