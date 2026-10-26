# NetMap interview guide

## 90-second overview

NetMap ingests Nmap XML locally, converts it into typed scan/host/service records with provenance and scan coverage, compares explicit observations without claiming that missing assets are offline, and creates explainable defensive review signals. The UI and reports use the same normalized data. The optional scanner is separate from the dashboard and is constrained to acknowledged private/loopback IPv4 lab targets.

## Strong technical contributions

### Why use streaming XML parsing?

`ElementTree.iterparse` allows the parser to clear each `<host>` after it has been normalized, avoiding retention of both the complete XML tree and normalized records. A 20 MiB input cap is an additional resource bound. The resulting inventory still occupies memory because the dashboard and comparison operate on it; this is not a constant-memory application.

### How are stable identifiers constructed?

Host IDs are a short SHA-256 prefix of the normalized address; service IDs add protocol and port. This makes IDs repeatable across scans of the same address/endpoint. The IDs are not durable identities when addresses change, and the project does not claim they identify physical devices.

### How does scan differencing avoid false removal claims?

It compares `(address, protocol, port)` records. Explicit `closed` or `filtered` states are state changes. A missing host is only “not observed”. A previously open port missing from the later XML is “no longer observed” only if the later scan is complete and its `scaninfo` includes that port; otherwise it is “not assessed”. Even with coverage, the report says the port was not reported open, not that it was administratively closed.

### What does an exposure finding mean?

It means that a documented rule matched an observed open service label. Each result includes the rule ID, severity, evidence, reason, timestamp, source, and remediation guidance. Service identification confidence is exposed. There is no CVE feed or exploitability analysis, so results are not vulnerability confirmations.

### How is report injection handled?

HTML cells, titles, host inventory, and finding text are escaped. SVG labels are escaped and layout attributes come from fixed templates. CSV values beginning with spreadsheet formula operators after leading whitespace are prefixed with an apostrophe. Writes go to a temporary sibling file and are atomically replaced. Tests cover these paths.

### Why no database or authentication?

The current product is a local analyst tool, so scans remain in user-selected files and session state. A database or account system would add secret storage, access control, and lifecycle requirements without serving the demonstrated workflow. Streamlit binds to loopback; it is not configured for shared deployment.

## Testing strategy

The unit suite uses synthetic XML to cover parse edge cases, stable IDs, scan coverage, duplicate records, comparison limitations, finding evidence, graph construction, output escaping/formula handling, CLI scan guardrails, and end-to-end synthetic exports. Streamlit AppTests cover the initial no-data state, explicit synthetic load, searchable inventory, and two-file comparison. CI runs tests and dependency audit on Python 3.11 and 3.14. Live scanning is excluded from the test suite.

## Trade-offs and next steps

- Address-based IDs are simple and deterministic but do not survive IP reassignment. A future inventory database would need an explicit identity/linking model.
- Port coverage from XML is conservative metadata. Different Nmap options and network filters still limit comparison confidence.
- A 20 MiB XML cap and 250-node graph cap keep local processing/rendering bounded while full tables remain available.
- A larger rule pack should add source citations, fixture evidence, false-positive tests, and a change-control process before it is presented as vulnerability analysis.
- A multi-user deployment would need authentication, authorization, tenant isolation, encrypted storage, retention controls, audit logging, and a new threat model.

## Questions to prepare for

1. **Why not call a missing port closed?** The XML may not cover it, the scan may be partial, or the host may not have been observed. NetMap requires coverage/completion and still labels it “no longer observed.”
2. **Why is Telnet medium severity?** It is a review priority because clear-text administration is generally risky, but NetMap has no asset context or exploit proof. The severity is a rule priority, not CVSS.
3. **Could XML contain malicious markup?** XML strings are treated as untrusted. The parser uses an input-size bound and streaming, and output encoders escape text. No strings become dynamic SVG attributes or executable HTML.
4. **Why not call the service name confirmed?** Nmap may infer a service from the port table. `method="probed"` is distinguished from a table-based label and no identification is treated as confirmed when fields are absent.
5. **What is not production-ready?** There is no auth or persistence, only a small heuristic rule set, no live Nmap run in this audit, and no multi-tenant deployment hardening. The repository is a local portfolio project.
