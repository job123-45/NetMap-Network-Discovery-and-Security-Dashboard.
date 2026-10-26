# NetMap implementation checklist

Baseline branch: `audit/remove-live-scan-artifacts` (existing open PR #1). The tree was clean before implementation. The remediation PR removed live scan XML/text, packet capture, report exports, and real-scan screenshots. That deletion set remains in place. The existing AppTest file still referred to deleted live files, so those tests are being replaced with synthetic-only flows.

## Phases

- [x] Phase 1 — Audit source tree, dependencies, current branch/PR, scripts, baseline test setup, and data-removal remediation. Nmap is unavailable here; no live scan is run.
- [x] Phase 2 — Add typed inventory records, stable IDs, bounded streaming Nmap XML parsing, normalization, provenance, scan completion, and coverage.
- [x] Phase 3 — Add confidence/limitation-aware scan differences and explainable service exposure rules, with unit coverage.
- [x] Phase 4 — Add explicit synthetic loading, exposure and history views, searchable inventory, and host-to-observed-service map.
- [x] Phase 5 — Add safe HTML/SVG/JSON/CSV reports, formula-injection handling, predictable atomic writes, input overwrite checks, size limits, and bounded authorized scan commands.
- [x] Phase 6 — Replace stale live-data AppTests, add parser/analysis/export/CLI regression tests, and add CI.
- [x] Phase 7 — Update README, quickstart, architecture, security assumptions, and interview guide.
- [x] Phase 8 — Full tests, demo, dependency audit, diff and secret/artifact review completed; commit/push and PR update are the final delivery steps.

## Baseline findings

- Existing stack: Python standard-library CLI/parser plus Streamlit, pandas, and Altair dashboard.
- The existing remediation PR is open and removes live-scan artifacts from the current tree without rewriting prior history.
- The pre-change unit suite included UI tests pointing to scans intentionally removed from this branch. Its parser tests covered basic parsing, comparison, and HTML but not CSV formula injection, missing scan coverage, or output safety.
- The parser materialized the full XML tree, had no size bound, and compared endpoint absence as no longer open.
- CLI scan commands had target and range checks but no explicit acknowledgement flag; report outputs did not guard spreadsheet formulas or input overwrite.
- Nmap was not available on PATH. Scanner command construction will be tested through mocked subprocess tests only; no network scan is represented as verified.
