# NetMap implementation status

This file tracks the current local-first XML workflow. Verification details are kept in `evidence/verification_results.txt` and contain synthetic-only results.

## Implemented

- Bounded streaming XML parser, normalized typed models, deterministic local identifiers, service identification confidence, scan coverage and completion metadata.
- Coverage-aware comparison of hosts, endpoint states, service fingerprints, and rule matches; missing observations are not interpreted as closure or offline status.
- Explainable Telnet, FTP, and database exposure-review rules with evidence, limitation, severity, and defensive next step.
- Local Streamlit overview, searchable ports/services, host view, scan history from local XML, findings, comparison, and evidence-backed graph.
- Explicit synthetic demo workflow, with documentation-range addresses and `.test` names.
- HTML, JSON schema v1, CSV inventory/findings, and SVG reports with output hardening.
- Active scan acknowledgement, private/loopback IPv4 bounds, range/port/time/rate caps, no shell, and generic subprocess logging.
- CI and regression tests use synthetic fixtures and do not need network access.

## Verification scope

- The full test and dependency audit are run at final verification. See `evidence/verification_results.txt` for exact commands and results.
- Nmap was unavailable during this work. No live network scan or third-party integration is claimed.
- AppTest is used for dashboard workflow coverage; a manual browser/download review is not claimed unless explicitly recorded.
- Repository history has not been rewritten. The open artifact-remediation PR removes sensitive material from the current tree only.

## Product maturity

This is a local portfolio application with heuristic review rules. It is not a production, multi-user, vulnerability-management, or authenticated service.
