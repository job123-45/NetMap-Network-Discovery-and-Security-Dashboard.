# Synthetic demonstration screenshot checklist

Screenshots for public documentation must use the explicit synthetic demo only. Never include real scan XML, private hostnames, IP ranges, paths, packet captures, or report exports in public screenshots.

- [x] Welcome state: empty state visually inspected in the running local app.
- [x] Synthetic overview: the running app displayed the synthetic-only banner and documentation-range fixture.
- [x] Exposure Findings: captured and visually inspected rule evidence and its limitation in the running app.
- [x] Network Map: captured and visually inspected observed host-to-service edges only.
- [ ] Comparison: show state changes, low-confidence new observations, and limitations.
- [ ] Report exports: use only synthetic demo output.

Screens were captured through the local browser and visually inspected during verification. The captures are ephemeral task evidence and were not added to the repository; comparison and export screens still need saved documentation captures.
