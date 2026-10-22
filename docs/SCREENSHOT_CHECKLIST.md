# Assessment-9 screenshot and artefact checklist

Capture screenshots from the running real-scan-only application. Do not use test fixtures as live scan evidence.

## Saved artefacts

- Real scan XML/text: `scans/live_scan.xml`, `scans/live_scan.txt`, `scans/live_scan_after.xml`, `scans/live_scan_after.txt`.
- Original PCAPNG: `scans/nmap_scan_capture.pcapng` (readable by tshark but not corroboration of saved scan port states; see README).
- Existing XML-derived report files: `outputs/live_scan_report.csv`, `outputs/live_scan_hosts.csv`, `outputs/live_scan_report.html`, `outputs/live_scan_comparison.csv`, `outputs/live_scan_comparison.html`.
- No screenshots are currently included. No new scan or capture is claimed.

## Screenshots to collect

- [ ] Welcome screen before loading: shows saved scan selection/upload and no data metrics.
- [ ] Overview after loading `live_scan.xml`: source filename/time, host count, four open ports, chart, records and exports.
- [ ] Host Discovery and Ports & Services for the same loaded scan.
- [ ] Comparison with `live_scan.xml` as Baseline and `live_scan_after.xml` as After, showing the actual no-differences result.
- [ ] Reports & Exports and opened report/download files.
- [ ] PowerShell output from unit tests and compilation checks.

Update screenshots only from the actual application and preserve source XML files. The Assessment-9 DOCX/PDF still needs a synchronized manual update if the submission requires documentation of this workflow.
