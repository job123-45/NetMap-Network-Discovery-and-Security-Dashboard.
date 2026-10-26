# Security assumptions and limitations

## Intended use

NetMap is designed for local review of Nmap XML and authorized, bounded IPv4 lab scans. The dashboard never starts scans. The optional CLI supports a single private/loopback IPv4 host or a private/loopback IPv4 discovery range containing at most 256 addresses. It requires `--authorized-lab-target`, limits port selection to 2,048, rate-limits Nmap to at most 100 packets/second, limits retries to two, and enforces a 1–600 second timeout. These are guardrails, not permission checks.

## Trust boundaries and controls

- XML, filenames, hostnames, service banners, and scan reasons are untrusted input. `defusedxml` allows Nmap's normal DTD but rejects entity expansion and external entities; XML is streamed, limited to 20 MiB, normalized, and escaped when rendered.
- The dashboard binds to loopback and has no authentication. Do not expose it to an untrusted network or deploy it as a shared service.
- Uploaded filenames are never used as paths; temporary uploads use a fixed name and short-lived directory.
- HTML/SVG output escapes untrusted text; generated SVG attributes use fixed values/numeric coordinates. CSV fields that may start spreadsheet formulas are prefixed with an apostrophe.
- JSON follows `netmap.report.v1`; reports omit absolute source paths and raw Nmap command arguments.
- Report writes are atomic, and the CLI refuses output/input path collisions.
- Nmap subprocess arguments are passed as a list (no shell), output is captured rather than logged, and scan results are not printed by the runner.
- Current synthetic fixtures use documentation address space and `.test` names. Real scan artifacts are ignored locally and were removed from the remediation branch's working tree.
- The dashboard and CLI persist inventory in a local SQLite database under the user's application-data directory. The database and backups can contain sensitive asset details; keep them local and do not publish them. Set `NETMAP_DATA_DIR` or `NETMAP_DB_PATH` to choose a controlled location. Synthetic records use a separate database.
- Backup restore requires explicit confirmation and validates the database schema before replacement. Snapshot deletion removes dependent observations and comparisons and removes findings that no longer have observations.

## Rule assumptions

An Nmap service label can be inferred from the port table or probe. NetMap exposes that distinction and treats only `method="probed"` as confirmed service identification. The Telnet, FTP, and database rules are review signals. They do not identify CVEs, prove vulnerable software, infer exploitability, or score CVSS.

## Comparison assumptions

Nmap XML can be partial and scan options can differ. A missing endpoint is not closed/offline. A missing host is not removed. Explicit state rows are time-bound observations and can reflect filtering or transient conditions. Coverage and completion are used when present; when absent, confidence is reduced and the change is marked `not_assessed`.

## Operational limitations

- No authentication, cloud service, or multi-user isolation. SQLite persistence is local to one user's machine.
- No live network scan was run for this change. Nmap command behavior is unit-tested with mocks; verify Nmap installation and local lab setup separately.
- No CVE database or external threat intelligence.
- XML is limited to 20 MiB; graphical maps are capped at 250 hosts and 250 services.
- The prior artifact-remediation PR does not rewrite Git history. Removed artifacts may remain in earlier commits. History rewriting is deliberately outside this task; repository maintainers should separately assess whether revocation or history cleanup is needed.

## Reporting a security issue

Do not file sensitive scan data or credentials in public issues. Share a minimal synthetic reproduction with the repository owner through a private channel.
