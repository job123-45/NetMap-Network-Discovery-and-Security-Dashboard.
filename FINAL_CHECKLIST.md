# NetMap final checklist — real-scan workflow

## Start screen and real input

- [x] Fresh session shows the scan selection screen with no metrics, tables, charts, or synthetic content.
- [x] Select a valid saved XML from `scans/` or upload a scan, then explicitly click **Load Scan**.
- [x] Validate XML before loading; reject invalid/non-Nmap XML without showing stale scan data.
- [x] Valid empty scans load and show useful empty states.
- [x] **Change scan** clears the loaded result and returns to selection.
- [x] Keep test fixtures out of the production dashboard and launcher.

## Dashboard and comparison

- [x] Five navigation views: Overview, Host Discovery, Ports & Services, Comparison, Reports & Exports.
- [x] All single-scan metrics, charts, host/port rows, and reports derive from one session-selected real XML file.
- [x] Source filename and XML-reported timestamp are visible.
- [x] Comparison requires two valid real XML scans with separate Baseline and After inputs.
- [x] Compare open endpoints by host, port and protocol; show opened, no-longer-open, and changed service fingerprints.
- [x] Show both filenames/timestamps and no-differences state; comparison CSV/HTML remain available.
- [x] Saved scans are validated before being offered; upload filenames are not used as filesystem paths.

## Automated checks actually run

- [x] `py -m unittest discover -s tests -v` — 15 passed, including Streamlit AppTest flows.
- [x] `py -m py_compile netmap.py dashboard.py tests/test_netmap.py tests/test_dashboard_overview.py` — passed.
- [x] `py -m pip check` — no broken requirements.
- [ ] Manual browser download and visual review of report HTML remain to be performed.
- [x] `Run-Demo.bat` installed/checks dependencies and started Streamlit on port 8501 without generating demo reports; manually stopped with Ctrl+C (exit status 1 from interruption).
- [ ] Nmap unavailable on PATH; no new scan run. Existing scan XML records version 7.80.

## Existing evidence and limits

- [x] Preserve `scans/live_scan.xml`, `scans/live_scan_after.xml`, text outputs, and `scans/nmap_scan_capture.pcapng` unchanged.
- [x] Document PCAPNG filter results: 94 frames; broad filter matches six ICMP host-unreachable quotations to unrelated hosts/port 7680; direct target/scan-port SYN filter returns no frames. Capture does not corroborate saved scans.
- [ ] Capture screenshots from the actual application for submission; none are present in the project.
- [ ] Update the six-section Assessment-9 DOCX and export a synchronized PDF in Word if needed.
- [x] No new scan, packet capture, firewall experiment, or VM experiment is claimed.
