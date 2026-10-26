"""Local-first Streamlit dashboard for imported, authorized, or synthetic Nmap XML."""

from __future__ import annotations

import html
import json
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

import netmap
import netmap_store

ROOT = Path(__file__).resolve().parent

st.set_page_config(
    page_title="NetMap | Network Discovery", page_icon="◈", layout="wide"
)
st.markdown(
    """
<style>
:root { --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --paper:#f8fafc; --blue:#2563eb; --blue-hover:#1d4ed8; --blue-soft:#eff6ff; --green:#15803d; }
html, body, [class*="css"] { font-family:system-ui,-apple-system,'Segoe UI',sans-serif; color:var(--ink); }
.stApp { background:var(--paper); }
[data-testid="stHeader"] { background:transparent; }
[data-testid="stSidebar"] { background:#fff; border-right:1px solid var(--line); }
[data-testid="stSidebar"] > div { padding-top:1.25rem; }
.brand { color:var(--blue); font-size:1.1rem; font-weight:700; letter-spacing:.02em; margin:0 0 .2rem; }
.brand-sub { color:var(--muted); font-size:.78rem; margin-bottom:1.6rem; }
.eyebrow { color:var(--muted); font-size:.75rem; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.page-title { color:var(--ink); font-size:1.8rem; font-weight:700; margin:.15rem 0 .25rem; }
.page-subtitle { color:var(--muted); margin-bottom:1.1rem; }
[data-testid="stMetric"] { background:white; border:1px solid var(--line); border-radius:12px; padding:1rem 1.1rem; box-shadow:0 1px 2px rgba(0,0,0,.05); }
[data-testid="stMetricLabel"] { color:var(--muted); font-size:.8rem; }
[data-testid="stMetricValue"] { color:var(--ink); font-weight:700; }
[data-testid="stVerticalBlockBorderWrapper"] { background:white; border:1px solid var(--line); border-radius:12px; padding:1rem 1.15rem; }
.section-heading { color:var(--ink); font-size:1.05rem; font-weight:700; margin:.2rem 0 .2rem; }
.section-note { color:var(--muted); font-size:.83rem; margin-bottom:.65rem; }
div[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:9px; overflow:hidden; background:#fff; }
div[data-testid="stDataFrame"] [role="columnheader"] { background:#f1f5f9 !important; color:#475569 !important; }
.scan-banner { background:#f1f5f9; border:1px solid #cbd5e1; border-radius:10px; color:#334155; padding:.8rem 1rem; margin:.6rem 0 1rem; font-weight:600; }
.status-pill { display:inline-block; border-radius:999px; padding:.25rem .65rem; margin:.12rem .25rem .55rem 0; background:#dcfce7; color:#15803d; font-size:.78rem; font-weight:600; }
div.stButton > button[kind="primary"] { background:var(--blue); border-color:var(--blue); color:white; }
div.stButton > button[kind="primary"]:hover { background:var(--blue-hover); border-color:var(--blue-hover); }
button[kind="secondary"]:focus-visible, div.stButton > button:focus-visible { outline:2px solid #2563eb; outline-offset:2px; }
@media (max-width: 800px) { .page-title {font-size:1.45rem;} }
</style>
""",
    unsafe_allow_html=True,
)

active_scan = st.session_state.get("active_scan")
with st.sidebar:
    st.markdown(
        '<div class="brand">◈ NetMap</div><div class="brand-sub">Network discovery & security</div>',
        unsafe_allow_html=True,
    )
    pages = [
        "Load scan",
        "Overview",
        "Network Map",
        "Exposure Findings",
        "Host Discovery",
        "Ports & Services",
        "Scan History",
        "Comparison",
        "Assets",
        "Finding Triage",
        "Data Management",
        "Reports & Exports",
    ]
    page = st.radio(
        "Workspace",
        pages,
        index=1 if active_scan else 0,
        label_visibility="collapsed",
    )
    if not active_scan and page not in {"Load scan", "Data Management"}:
        page = "Load scan"
    if active_scan:
        if st.button("Change scan", key="change-active-scan"):
            st.session_state.pop("active_scan", None)
            st.rerun()
    else:
        page = "Load scan"
        st.caption("LOAD AN XML SCAN TO BEGIN")
    st.divider()
    st.caption("LOCAL ANALYSIS · NO SCANS FROM THIS DASHBOARD")

if page == "Load scan":
    st.markdown(
        '<div class="eyebrow">NetMap · Network intelligence</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="page-title">Network Discovery Dashboard</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="page-subtitle">Import authorized Nmap XML, compare observations, inspect evidence-based review signals, and export reports.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="eyebrow">Network intelligence</div>', unsafe_allow_html=True
    )
    st.markdown(
        f'<div class="page-title">{html.escape(page)}</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="page-subtitle">Review saved Nmap results, understand changes, and export shareable reports.</div>',
        unsafe_allow_html=True,
    )


def show_source_banner(message: str) -> None:
    st.markdown(
        f'<div class="scan-banner">{html.escape(message)}</div>', unsafe_allow_html=True
    )


def show_host_status_badges(hosts: pd.DataFrame) -> None:
    if hosts.empty:
        return
    badges = "".join(
        f'<span class="status-pill">{html.escape(str(row.ip_address))} · {html.escape(str(row.host_status).upper())}</span>'
        for row in hosts.itertuples(index=False)
    )
    st.markdown(badges, unsafe_allow_html=True)


def frame_csv_bytes(frame: pd.DataFrame) -> bytes:
    return netmap.csv_bytes(frame.to_dict(orient="records"), list(frame.columns))


def styled_frame(frame: pd.DataFrame):
    return frame.style.set_table_styles(
        [
            {
                "selector": "th",
                "props": [
                    ("background-color", "#F1F5F9"),
                    ("color", "#475569"),
                    ("font-weight", "600"),
                    ("border-bottom", "1px solid #E2E8F0"),
                ],
            },
            {"selector": "td", "props": [("color", "#0F172A")]},
        ]
    )


def get_scan_data(path: Path) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    parsed = netmap.parse_scan(path)
    return (
        parsed,
        pd.DataFrame(parsed["rows"], columns=netmap.REPORT_FIELDS),
        pd.DataFrame(parsed["hosts"], columns=netmap.HOST_FIELDS),
    )


def remember_scan(
    parsed: dict,
    ports: pd.DataFrame,
    hosts: pd.DataFrame,
    source_name: str,
    source_kind: str | None = None,
) -> None:
    """Keep the selected scan and provenance in this local Streamlit session."""
    safe_name = Path(str(source_name).replace("\\", "/")).name
    kind = source_kind or parsed.get("source_kind", "imported_nmap_xml")
    if netmap.is_bundled_synthetic(parsed):
        kind = "synthetic_demo"
    parsed = {**parsed, "source": safe_name}
    netmap.set_scan_provenance(parsed, kind, safe_name)
    db_path = netmap_store.database_path(synthetic=kind == "synthetic_demo")
    snapshot_id, duplicate = netmap_store.store_snapshot(
        parsed, netmap.analyze_exposure(parsed), path=db_path
    )
    ports = ports.copy()
    hosts = hosts.copy()
    for frame in (ports, hosts):
        frame["source_kind"] = kind
        frame["source_file"] = safe_name
    st.session_state["active_scan"] = {
        "kind": parsed["source_kind"],
        "parsed": parsed,
        "ports": ports.copy(),
        "hosts": hosts.copy(),
        "source_name": safe_name,
        "snapshot_id": snapshot_id,
        "duplicate": duplicate,
        "database_path": str(db_path),
    }


def parse_uploaded_scan(uploaded) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    """Parse uploaded bytes from a short-lived temp file without trusting its name."""
    if uploaded.size > netmap.MAX_XML_BYTES:
        raise ValueError(
            f"File exceeds NetMap's {netmap.MAX_XML_BYTES // (1024 * 1024)} MiB upload limit."
        )
    with tempfile.TemporaryDirectory(prefix="netmap-upload-") as temp_dir:
        temp_path = Path(temp_dir) / "upload.xml"
        temp_path.write_bytes(uploaded.getvalue())
        return get_scan_data(temp_path)


def styled_report(parsed: dict, source_name: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "report.html"
        provenance = (
            "SYNTHETIC DEMONSTRATION DATA — NOT A LIVE SCAN"
            if parsed.get("source_kind") == "synthetic_demo"
            else "Imported Nmap XML"
        )
        netmap.write_html(
            output,
            "NetMap Scan Report",
            parsed["rows"],
            netmap.REPORT_FIELDS,
            f"{provenance} | Source: {Path(source_name).name} | Scan time: {parsed['scan_time']}",
            netmap.analyze_exposure(parsed),
            parsed.get("hosts", []),
        )
        return output.read_bytes()


def show_scan_metrics(parsed: dict, ports: pd.DataFrame, hosts: pd.DataFrame) -> None:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hosts discovered", len(hosts))
    m2.metric(
        "Open ports",
        int((ports["state"] == "open").sum()) if not ports.empty else 0,
        help="Port rows whose Nmap state is exactly open.",
    )
    m3.metric("Port records", len(ports))
    services = (
        ports.loc[ports["service"].astype(bool), "service"].nunique()
        if not ports.empty
        else 0
    )
    m4.metric("Services detected", int(services))
    st.caption(
        f"Scan timestamp: {parsed['scan_time']} · Source file: {Path(str(parsed['source'])).name} · Source kind: {parsed.get('source_kind', 'imported_nmap_xml')}"
    )
    if hosts.empty:
        st.info("This valid Nmap XML contains no host records.")
    elif ports.empty:
        st.info("Hosts were recorded, but this scan contains no port records.")
    elif not (ports["state"].str.lower() == "open").any():
        st.info("No open ports were reported in this scan.")


def show_port_state_chart(
    ports: pd.DataFrame, title: str = "Port state distribution"
) -> None:
    if ports.empty:
        st.info("No port records are available for a chart.")
        return
    counts = (
        ports["state"]
        .value_counts()
        .rename_axis("Port state")
        .reset_index(name="Records")
    )
    counts["color"] = counts["Port state"].map(
        lambda state: "#2563EB" if state.lower() == "open" else "#94A3B8"
    )
    chart = (
        alt.Chart(counts)
        .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
        .encode(
            x=alt.X("Port state:N", title=None, sort="-y"),
            y=alt.Y("Records:Q", title="Records", scale=alt.Scale(domainMin=0)),
            color=alt.Color("color:N", scale=None, legend=None),
            tooltip=[alt.Tooltip("Port state:N"), alt.Tooltip("Records:Q")],
        )
        .properties(height=220, title=title)
    )
    st.altair_chart(chart, width="stretch")


def show_ports(ports: pd.DataFrame, key: str) -> None:
    if ports.empty:
        st.info(
            "No port records were included. A host discovery-only scan may contain hosts without port details."
        )
    else:
        query = (
            st.text_input(
                "Search address, port, service or product", key=f"search-{key}"
            )
            .strip()
            .casefold()
        )
        states = sorted(ports["state"].dropna().unique().tolist())
        selected = st.multiselect(
            "Filter by port state", states, default=states, key=f"state-{key}"
        )
        filtered = ports[ports["state"].isin(selected)]
        if query:
            text_rows = (
                filtered.astype(str)
                .apply(
                    lambda column: column.str.casefold().str.contains(
                        query, regex=False
                    )
                )
                .any(axis=1)
            )
            filtered = filtered[text_rows]
        st.dataframe(styled_frame(filtered), width="stretch", hide_index=True)


def show_network_map(parsed: dict) -> None:
    graph = netmap.build_network_graph(parsed)
    if not graph["nodes"]:
        st.info("No host or service observations are available to map.")
        return
    st.caption(
        "Edges show only host-to-service observations present in this scan. No inferred network paths are drawn."
    )
    if graph["omitted_host_count"] or graph["omitted_service_count"]:
        st.info(
            f"The visual is capped for readability; {graph['omitted_host_count']} host(s) and {graph['omitted_service_count']} service(s) are omitted from the graph. The complete inventory remains in Ports & Services and report exports."
        )
    try:
        st.graphviz_chart(netmap.network_graph_dot(parsed), width="stretch")
    except (st.errors.StreamlitAPIException, ValueError):
        st.info(
            "The graphical map is unavailable in this Streamlit runtime; use the evidence table below."
        )
    if graph["edges"]:
        st.dataframe(pd.DataFrame(graph["edges"]), width="stretch", hide_index=True)
    else:
        st.info(
            "No open services were observed; host inventory remains available below."
        )
    if graph["nodes"]:
        st.dataframe(pd.DataFrame(graph["nodes"]), width="stretch", hide_index=True)


def show_findings(parsed: dict) -> None:
    findings = netmap.analyze_exposure(parsed)
    if findings:
        st.dataframe(pd.DataFrame(findings), width="stretch", hide_index=True)
    else:
        st.info("No configured exposure-review rules matched the observed services.")
    st.caption(
        "Rule results are defensive review signals. They do not confirm CVEs, vulnerabilities, or exploitability."
    )


def show_scan_history(current: dict) -> None:
    db_path = current["database_path"]
    snapshots = netmap_store.list_snapshots(db_path)
    st.caption("Snapshot history is stored in the local NetMap SQLite database.")
    if not snapshots:
        st.info("No snapshots are stored yet.")
        return
    st.dataframe(pd.DataFrame(snapshots), width="stretch", hide_index=True)
    selected = st.selectbox(
        "Open saved snapshot",
        snapshots,
        format_func=lambda item: (
            f"{item['scan_time']} · {item['source']} · {item['snapshot_id'][:8]}"
        ),
    )
    if st.button("Load selected snapshot", key="load-saved-snapshot"):
        parsed = netmap_store.load_snapshot(selected["snapshot_id"], db_path)
        remember_scan(
            parsed,
            pd.DataFrame(parsed["rows"], columns=netmap.REPORT_FIELDS),
            pd.DataFrame(parsed["hosts"], columns=netmap.HOST_FIELDS),
            selected["source"],
            selected["source_kind"],
        )
        st.rerun()


def export_scan(
    parsed: dict, ports: pd.DataFrame, hosts: pd.DataFrame, key: str
) -> None:
    left, middle, right = st.columns(3)
    left.download_button(
        "Download ports CSV",
        frame_csv_bytes(ports),
        "netmap-ports.csv",
        "text/csv",
        key=f"pcsv-{key}",
    )
    middle.download_button(
        "Download hosts CSV",
        frame_csv_bytes(hosts),
        "netmap-hosts.csv",
        "text/csv",
        key=f"hcsv-{key}",
    )
    source_name = Path(str(parsed.get("source", key))).name
    right.download_button(
        "Download styled HTML",
        styled_report(parsed, source_name),
        "netmap-report.html",
        "text/html",
        key=f"html-{key}",
    )
    findings = netmap.analyze_exposure(parsed)
    st.download_button(
        "Download findings CSV",
        netmap.csv_bytes(
            findings,
            [
                "rule_id",
                "severity",
                "title",
                "address",
                "protocol",
                "port",
                "evidence",
                "explanation",
                "limitation",
                "recommendation",
                "timestamp",
                "source",
                "classification",
            ],
        ),
        "netmap-findings.csv",
        "text/csv",
        key=f"fcsv-{key}",
    )
    report = (
        json.dumps(
            netmap.report_document(parsed), ensure_ascii=False, sort_keys=True, indent=2
        )
        + "\n"
    )
    st.download_button(
        "Download JSON report",
        report.encode("utf-8"),
        "netmap-report.json",
        "application/json",
        key=f"json-{key}",
    )
    with tempfile.TemporaryDirectory(prefix="netmap-svg-") as temp_dir:
        svg_path = Path(temp_dir) / "network.svg"
        netmap.write_network_svg(svg_path, parsed)
        st.download_button(
            "Download network SVG",
            svg_path.read_bytes(),
            "netmap-network.svg",
            "image/svg+xml",
            key=f"svg-{key}",
        )


def show_comparison(
    before_path: Path,
    after_path: Path,
    before_name: str,
    after_name: str,
    key: str,
    source_label: str,
) -> pd.DataFrame:
    before, after = netmap.parse_scan(before_path), netmap.parse_scan(after_path)
    before["source"] = before_name
    after["source"] = after_name
    if netmap.is_bundled_synthetic(before) and netmap.is_bundled_synthetic(after):
        source_label = "Synthetic demonstration data"
    kind = (
        "synthetic_demo"
        if source_label == "Synthetic demonstration data"
        else "imported_nmap_xml"
    )
    netmap.set_scan_provenance(before, kind, before_name)
    netmap.set_scan_provenance(after, kind, after_name)
    db_path = netmap_store.database_path(synthetic=kind == "synthetic_demo")
    before_id, _ = netmap_store.store_snapshot(
        before, netmap.analyze_exposure(before), path=db_path
    )
    after_id, _ = netmap_store.store_snapshot(
        after, netmap.analyze_exposure(after), path=db_path
    )
    changes = netmap.compare_parsed_scans(before, after, before_name, after_name)
    netmap_store.save_comparison(before_id, after_id, changes, db_path)
    frame = pd.DataFrame(changes, columns=netmap.COMPARE_FIELDS)
    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Newly observed open",
        int((frame["change"] == "newly_observed_open").sum()) if not frame.empty else 0,
    )
    c2.metric(
        "No longer observed",
        int((frame["change"] == "no_longer_observed").sum()) if not frame.empty else 0,
    )
    c3.metric(
        "Service label changed",
        int((frame["change"] == "service_changed").sum()) if not frame.empty else 0,
    )
    st.caption(
        f"Baseline: {html.escape(before_name)} ({before['scan_time']}; {len(before['hosts'])} hosts, {len(before['rows'])} port records) · After: {html.escape(after_name)} ({after['scan_time']}; {len(after['hosts'])} hosts, {len(after['rows'])} port records)"
    )
    if frame.empty:
        st.success(
            "No differences were detected in the recorded endpoint and service observations."
        )
    else:
        for change_type, heading in (
            ("host_newly_observed", "Hosts newly observed in the later input"),
            ("newly_observed_open", "Newly observed open endpoints"),
            ("no_longer_observed", "No longer observed in covered scan"),
            ("not_assessed", "Not assessed due to coverage or host uncertainty"),
            ("state_changed", "Observed state changes"),
            ("service_changed", "Changed service fingerprints"),
            ("finding_new", "New rule-based review signals"),
            ("finding_no_longer_matches", "Rule signals no longer match"),
            ("host_not_observed", "Hosts not recorded in later scan"),
        ):
            subset = frame.loc[frame["change"] == change_type]
            if not subset.empty:
                st.markdown(
                    f'<div class="section-heading">{heading} · {len(subset)}</div>',
                    unsafe_allow_html=True,
                )
                st.dataframe(styled_frame(subset), width="stretch", hide_index=True)
    a, b = st.columns(2)
    a.download_button(
        "Download comparison CSV",
        frame_csv_bytes(frame),
        "netmap-comparison.csv",
        "text/csv",
        key=f"ccsv-{key}",
    )
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "comparison.html"
        netmap.write_html(
            output,
            "NetMap Before/After Comparison",
            changes,
            netmap.COMPARE_FIELDS,
            f"Real Nmap XML scans | {source_label} | Before: {before_name} ({before['scan_time']}) | After: {after_name} ({after['scan_time']})",
        )
        b.download_button(
            "Download comparison HTML",
            output.read_bytes(),
            "netmap-comparison.html",
            "text/html",
            key=f"chtml-{key}",
        )
    return frame


if page == "Load scan":
    st.markdown(
        '<div class="section-heading">Open a scan</div><div class="section-note">Select or upload an Nmap XML file. Alternatively, load the clearly labeled synthetic fixture for a safe demonstration.</div>',
        unsafe_allow_html=True,
    )
    scans_dir = ROOT / "scans"
    scan_paths = {}
    invalid_count = 0
    if scans_dir.is_dir():
        for candidate in sorted(
            scans_dir.glob("*.xml"), key=lambda path: path.name.casefold()
        ):
            try:
                netmap.parse_scan(candidate)
                scan_paths[candidate.name] = candidate
            except (ValueError, OSError):
                invalid_count += 1

    source_choice = st.radio(
        "Scan input",
        ["Select a saved scan", "Upload a scan"],
        horizontal=True,
        key="initial-scan-source",
    )
    selected_path = None
    uploaded_scan = None
    if source_choice == "Select a saved scan":
        if scan_paths:
            selected_name = st.selectbox(
                "Saved Nmap XML scan", list(scan_paths), key="initial-saved-scan"
            )
            selected_path = scan_paths[selected_name]
        else:
            st.info(
                "No valid Nmap XML scans were found in the project's scans folder. Choose Upload a scan to open an XML file."
            )
        if invalid_count:
            st.caption(
                f"Ignored {invalid_count} XML file(s) that are not valid Nmap scan results."
            )
    else:
        uploaded_scan = st.file_uploader(
            "Upload an Nmap XML file", type=["xml"], key="initial-scan-upload"
        )

    can_load = (
        source_choice == "Select a saved scan" and selected_path is not None
    ) or (source_choice == "Upload a scan" and uploaded_scan is not None)
    if st.button(
        "Load Scan", type="primary", key="load-initial-scan", disabled=not can_load
    ):
        try:
            if selected_path is not None:
                parsed, ports, hosts = get_scan_data(selected_path)
                source_name = selected_path.name
            else:
                parsed, ports, hosts = parse_uploaded_scan(uploaded_scan)
                source_name = uploaded_scan.name
            remember_scan(parsed, ports, hosts, source_name)
            st.rerun()
        except (ValueError, OSError) as exc:
            st.session_state.pop("active_scan", None)
            st.error(
                f"Unable to load that scan. Select a valid Nmap XML result or upload another file. Details: {exc}"
            )
    if st.button("Load synthetic demonstration", key="load-synthetic-demo"):
        try:
            parsed, ports, hosts = get_scan_data(ROOT / "sample_data" / "before.xml")
            parsed["source_kind"] = "synthetic_demo"
            remember_scan(
                parsed, ports, hosts, "synthetic-before.xml", "synthetic_demo"
            )
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(f"Synthetic fixture could not be loaded: {type(exc).__name__}.")

elif page == "Overview":
    parsed = active_scan["parsed"]
    ports = active_scan["ports"]
    hosts = active_scan["hosts"]
    key = "active-real-scan"
    label = (
        "SYNTHETIC DEMONSTRATION DATA · NOT A LIVE SCAN"
        if active_scan["kind"] == "synthetic_demo"
        else f"NMAP XML OBSERVATION · {active_scan['source_name']}"
    )
    show_source_banner(label)
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Discovered hosts", len(hosts))
    d2.metric(
        "Open ports",
        int((ports["state"].str.lower() == "open").sum()) if not ports.empty else 0,
    )
    d3.metric(
        "Services detected",
        int(ports.loc[ports["service"].astype(bool), "service"].nunique())
        if not ports.empty
        else 0,
    )
    d4.metric("Port records", len(ports))
    st.caption(
        f"Filename: {active_scan['source_name']} · Scan timestamp: {parsed['scan_time']}"
    )
    left, right = st.columns([1, 1.7])
    with left, st.container(border=True):
        st.markdown(
            '<div class="section-heading">Host inventory</div><div class="section-note">Hosts reported by the selected XML scan</div>',
            unsafe_allow_html=True,
        )
        if hosts.empty:
            st.info("This valid scan contains no host records.")
        else:
            show_host_status_badges(hosts)
            st.dataframe(
                styled_frame(hosts[["ip_address", "host_status", "hostname"]]),
                width="stretch",
                hide_index=True,
            )
    with right, st.container(border=True):
        st.markdown(
            '<div class="section-heading">Port state distribution</div><div class="section-note">Counts calculated only from the selected XML scan</div>',
            unsafe_allow_html=True,
        )
        show_port_state_chart(ports)
    with st.container(border=True):
        st.markdown(
            '<div class="section-heading">Ports and services</div><div class="section-note">Records parsed from the selected scan source</div>',
            unsafe_allow_html=True,
        )
        show_ports(ports, key)
    with st.container(border=True):
        st.markdown(
            '<div class="section-heading">Exposure review signals</div><div class="section-note">Explainable rules derived only from observed open service labels.</div>',
            unsafe_allow_html=True,
        )
        show_findings(parsed)
    with st.container(border=True):
        st.markdown(
            '<div class="section-heading">Observed network map</div><div class="section-note">Host-to-service observations from this scan.</div>',
            unsafe_allow_html=True,
        )
        show_network_map(parsed)
    export_scan(parsed, ports, hosts, key)

elif page == "Network Map":
    show_network_map(active_scan["parsed"])

elif page == "Exposure Findings":
    show_findings(active_scan["parsed"])

elif page == "Scan History":
    show_scan_history(active_scan)

elif page in ("Host Discovery", "Ports & Services", "Reports & Exports"):
    parsed = active_scan["parsed"]
    ports = active_scan["ports"]
    hosts = active_scan["hosts"]
    key = "active-real-scan"
    label = (
        "SYNTHETIC DEMONSTRATION DATA · NOT A LIVE SCAN"
        if active_scan["kind"] == "synthetic_demo"
        else f"NMAP XML OBSERVATION · {active_scan['source_name']}"
    )
    show_source_banner(label)
    if page == "Host Discovery":
        st.markdown(
            '<div class="section-heading">Host inventory</div><div class="section-note">Hosts and addresses reported by the loaded scan.</div>',
            unsafe_allow_html=True,
        )
        show_scan_metrics(parsed, ports, hosts)
        if hosts.empty:
            st.info("This valid scan contains no host records.")
        else:
            query = (
                st.text_input("Search address, hostname, or status", key="search-hosts")
                .strip()
                .casefold()
            )
            visible_hosts = hosts
            if query:
                matching = (
                    visible_hosts.astype(str)
                    .apply(
                        lambda column: column.str.casefold().str.contains(
                            query, regex=False
                        )
                    )
                    .any(axis=1)
                )
                visible_hosts = visible_hosts[matching]
            show_host_status_badges(visible_hosts)
            st.dataframe(styled_frame(visible_hosts), width="stretch", hide_index=True)
    elif page == "Ports & Services":
        st.markdown(
            '<div class="section-heading">Ports and service fingerprints</div><div class="section-note">Filter rows by state or search observed values.</div>',
            unsafe_allow_html=True,
        )
        show_scan_metrics(parsed, ports, hosts)
        show_port_state_chart(ports)
        show_ports(ports, key)
    else:
        st.markdown(
            '<div class="section-heading">Export scan reports</div><div class="section-note">Downloads contain only the currently loaded scan.</div>',
            unsafe_allow_html=True,
        )
        show_scan_metrics(parsed, ports, hosts)
        show_ports(ports, key)
        show_findings(parsed)
        export_scan(parsed, ports, hosts, key)

elif page == "Comparison":
    source = st.radio(
        "Comparison inputs",
        ["Select saved scans", "Upload two scans"],
        horizontal=True,
        key="comparison-source",
    )
    if source == "Select saved scans":
        scans_dir = ROOT / "scans"
        scan_files = []
        invalid_count = 0
        if scans_dir.is_dir():
            for candidate in sorted(
                scans_dir.glob("*.xml"), key=lambda path: path.name.casefold()
            ):
                try:
                    netmap.parse_scan(candidate)
                    scan_files.append(candidate)
                except (ValueError, OSError):
                    invalid_count += 1
        if not scan_files:
            st.warning(
                "No valid Nmap XML scans were found in the project's scans folder. Add a valid scan or choose Upload two scans."
            )
        else:
            names = [path.name for path in scan_files]
            baseline_default = (
                names.index("live_scan.xml") if "live_scan.xml" in names else 0
            )
            after_default = (
                names.index("live_scan_after.xml")
                if "live_scan_after.xml" in names
                else min(1, len(names) - 1)
            )
            baseline_col, after_col = st.columns(2)
            with baseline_col:
                baseline_name = st.selectbox(
                    "Baseline scan (original scan)",
                    names,
                    index=baseline_default,
                    key="comparison-baseline-file",
                )
            with after_col:
                after_name = st.selectbox(
                    "After scan (later scan)",
                    names,
                    index=after_default,
                    key="comparison-after-file",
                )
            st.caption(
                "Both inputs are validated Nmap XML files from the local scans folder."
            )
            if invalid_count:
                st.caption(
                    f"Ignored {invalid_count} XML file(s) that are not valid Nmap scan results."
                )
            if st.button("Compare scans", type="primary", key="compare-project-scans"):
                try:
                    show_comparison(
                        scans_dir / baseline_name,
                        scans_dir / after_name,
                        baseline_name,
                        after_name,
                        "project-scans",
                        source_label="Saved project scans",
                    )
                except (ValueError, OSError) as exc:
                    st.error(f"Unable to compare the selected scans: {exc}")

    else:
        a, b = st.columns(2)
        baseline_upload = a.file_uploader(
            "Baseline scan (original scan)",
            type=["xml"],
            key="comparison-baseline-upload",
        )
        after_upload = b.file_uploader(
            "After scan (later scan)", type=["xml"], key="comparison-after-upload"
        )
        if baseline_upload and after_upload:
            if (
                baseline_upload.size > netmap.MAX_XML_BYTES
                or after_upload.size > netmap.MAX_XML_BYTES
            ):
                st.error(
                    f"Each XML input must be at most {netmap.MAX_XML_BYTES // (1024 * 1024)} MiB."
                )
                st.stop()
            if st.button(
                "Compare uploaded scans", type="primary", key="compare-uploaded-scans"
            ):
                with tempfile.TemporaryDirectory(prefix="netmap-compare-") as temp_dir:
                    temp_root = Path(temp_dir)
                    before_path = temp_root / "baseline.xml"
                    after_path = temp_root / "after.xml"
                    before_path.write_bytes(baseline_upload.getvalue())
                    after_path.write_bytes(after_upload.getvalue())
                    try:
                        show_comparison(
                            before_path,
                            after_path,
                            baseline_upload.name,
                            after_upload.name,
                            "uploaded-scans",
                            source_label="Uploaded Nmap XML scans",
                        )
                    except (ValueError, OSError) as exc:
                        st.error(f"Unable to compare the uploaded scans: {exc}")
        else:
            st.info(
                "Select both a baseline scan and an after scan. Two valid Nmap XML files are required before comparison."
            )

elif page == "Assets":
    db_path = active_scan.get("database_path") if active_scan else None
    assets = netmap_store.list_assets(db_path)
    if not assets:
        st.info("No persisted assets yet. Load an authorized Nmap XML scan first.")
    else:
        st.caption(
            "Inventory is derived from imported snapshots in the selected local database."
        )
        st.dataframe(pd.DataFrame(assets), width="stretch", hide_index=True)

elif page == "Finding Triage":
    db_path = active_scan.get("database_path") if active_scan else None
    statuses = ["all", *netmap_store.FINDING_STATUSES]
    selected_status = st.selectbox(
        "Status", statuses, format_func=lambda value: value.replace("_", " ").title()
    )
    selected_severity = st.selectbox(
        "Severity", ["all", "critical", "high", "medium", "low", "info"]
    )
    query = st.text_input("Search findings", key="triage-search")
    findings = netmap_store.list_findings(
        db_path, status=selected_status, severity=selected_severity, query=query
    )
    if not findings:
        st.info(
            "No findings match this filter. Import a scan with review signals to begin triage."
        )
    else:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        key: item.get(key)
                        for key in (
                            "finding_id",
                            "severity",
                            "title",
                            "status_label",
                            "ip_address",
                            "port",
                            "first_seen",
                            "last_seen",
                            "snapshot_count",
                        )
                    }
                    for item in findings
                ]
            ),
            width="stretch",
            hide_index=True,
        )
        options = {
            f"{item['severity'].upper()} · {item['title']} · {item['finding_id'][:8]}": item
            for item in findings
        }
        label = st.selectbox("Finding to update", list(options))
        finding = options[label]
        with st.form("finding-triage-form"):
            new_status = st.selectbox(
                "Set status",
                netmap_store.FINDING_STATUSES,
                index=netmap_store.FINDING_STATUSES.index(finding["status"]),
            )
            reason = st.text_area(
                "Decision reason (required for accepted risk or false positive)",
                max_chars=4000,
            )
            investigation = st.text_area("Investigation note", max_chars=4000)
            remediation = st.text_area("Remediation note", max_chars=4000)
            submitted = st.form_submit_button("Save triage")
        if submitted:
            try:
                netmap_store.update_finding(
                    finding["finding_id"],
                    new_status,
                    reason=reason,
                    investigation_note=investigation,
                    remediation_note=remediation,
                    path=db_path,
                )
                st.success("Finding triage saved.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
        st.subheader("Triage history")
        st.dataframe(
            pd.DataFrame(netmap_store.finding_history(finding["finding_id"], db_path)),
            width="stretch",
            hide_index=True,
        )

elif page == "Data Management":
    real_path = netmap_store.database_path()
    demo_path = netmap_store.database_path(synthetic=True)
    st.caption(
        "NetMap keeps this inventory on this device. Synthetic demonstration data uses a separate database."
    )
    st.write(f"Operational database: `{real_path}`")
    st.write(f"Synthetic database: `{demo_path}`")
    for title, path in (
        ("Operational data", real_path),
        ("Synthetic demo data", demo_path),
    ):
        with st.expander(title, expanded=True):
            stats = netmap_store.database_stats(path)
            st.json(stats)
            if path.exists():
                st.download_button(
                    f"Download {title.lower()} backup",
                    netmap_store.backup_bytes(path),
                    f"netmap-{title.split()[0].lower()}-backup.sqlite3",
                    "application/vnd.sqlite3",
                    key=f"backup-{title}",
                )
                snapshots = netmap_store.list_snapshots(path)
                if snapshots:
                    selected = st.selectbox(
                        f"Snapshot to delete from {title.lower()}",
                        snapshots,
                        format_func=lambda item: (
                            f"{item['scan_time']} · {item['source']} · {item['snapshot_id'][:8]}"
                        ),
                        key=f"delete-snapshot-{title}",
                    )
                    confirm = st.checkbox(
                        "Confirm deletion of this snapshot and dependent observations",
                        key=f"confirm-delete-{title}",
                    )
                    if st.button(
                        "Delete selected snapshot",
                        disabled=not confirm,
                        key=f"delete-{title}",
                    ):
                        netmap_store.delete_snapshot(selected["snapshot_id"], path)
                        st.success("Snapshot and dependent observations deleted.")
                        st.rerun()
    backup_upload = st.file_uploader(
        "Restore a NetMap SQLite backup", type=["sqlite3", "db"], key="restore-backup"
    )
    if backup_upload:
        confirm_restore = st.checkbox(
            "I understand restore replaces the operational database; a pre-restore backup will be created."
        )
        if st.button("Restore operational backup", disabled=not confirm_restore):
            try:
                netmap_store.restore_bytes(
                    backup_upload.getvalue(), real_path, confirmed=True
                )
                st.success(
                    "Backup restored; a safety backup was created beside the database."
                )
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
