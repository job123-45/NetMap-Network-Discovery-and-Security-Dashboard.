# NetMap final verification checklist

- [x] Preserve open PR `audit/remove-live-scan-artifacts`; do not restore scan XML, packet captures, real reports, or screenshots.
- [x] Replace dashboard tests that depended on removed private scans with RFC 5737 synthetic XML.
- [x] Stream and bound XML input; test malformed, empty, duplicate, unknown-service, and oversized cases.
- [x] Compare only observations, include coverage/completion limitations, and test host/endpoint/rule changes.
- [x] Add explainable rule evidence and test graph edges against actual observations.
- [x] Test HTML/SVG escaping, CSV formula injection, JSON schema/provenance, and output/input collisions.
- [x] Require an active-scan acknowledgement and test private/loopback IPv4, range, port, rate, and timeout limits without running Nmap.
- [x] Run the synthetic CLI demo and dashboard AppTests; exact final results are in `evidence/verification_results.txt`.
- [x] Add CI for tests, compilation, dependency consistency, and pip-audit.
- [x] Update README, quickstart, architecture, security assumptions, and interview guide to match behavior.
- [x] Capture and visually inspect the empty and synthetic dashboard states, findings, and observed graph. Captures remain ephemeral task evidence; no screenshot file was committed.
- [x] Review final diff/status, path-only secret scan, dependency audit, and unchanged existing PR head before committing/pushing.

## Not claimed

- No live network scan, firewall experiment, production deployment, external integration, CVE match, or vulnerability confirmation.
- The earlier remediation PR removes current-tree artifacts but leaves history unchanged.
