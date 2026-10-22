"""Real-scan-only Streamlit dashboard for saved Nmap XML results."""
from __future__ import annotations

import tempfile
import html
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

import netmap

ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="NetMap | Network Discovery", page_icon="◈", layout="wide")
st.markdown("""
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
""", unsafe_allow_html=True)

active_scan = st.session_state.get("active_scan")
with st.sidebar:
    st.markdown('<div class="brand">◈ NetMap</div><div class="brand-sub">Network discovery & security</div>', unsafe_allow_html=True)
    if active_scan:
        page = st.radio("Workspace", ["Overview", "Host Discovery", "Ports & Services", "Comparison", "Reports & Exports"], label_visibility="collapsed")
        if st.button("Change scan", key="change-active-scan"):
            st.session_state.pop("active_scan", None)
            st.rerun()
    else:
        page = "Load scan"
        st.caption("LOAD AN XML SCAN TO BEGIN")
    st.divider()
    st.caption("LOCAL ANALYSIS · NO SCANS FROM THIS DASHBOARD")

if page == "Load scan":
    st.markdown('<div class="eyebrow">NetMap · Network intelligence</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-title">Network Discovery Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Load an Nmap XML scan to view discovered hosts, open ports, services, and scan reports.</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="eyebrow">Network intelligence</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="page-title">{html.escape(page)}</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Review saved Nmap results, understand changes, and export shareable reports.</div>', unsafe_allow_html=True)


def show_source_banner(message: str) -> None:
    st.markdown(f'<div class="scan-banner">{html.escape(message)}</div>', unsafe_allow_html=True)


def show_host_status_badges(hosts: pd.DataFrame) -> None:
    if hosts.empty:
        return
    badges = "".join(
        f'<span class="status-pill">{html.escape(str(row.ip_address))} · {html.escape(str(row.host_status).upper())}</span>'
        for row in hosts.itertuples(index=False)
    )
    st.markdown(badges, unsafe_allow_html=True)


def frame_csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8")


def styled_frame(frame: pd.DataFrame):
    return frame.style.set_table_styles([
        {"selector": "th", "props": [("background-color", "#F1F5F9"), ("color", "#475569"), ("font-weight", "600"), ("border-bottom", "1px solid #E2E8F0")]},
        {"selector": "td", "props": [("color", "#0F172A")]},
    ])


def get_scan_data(path: Path) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    parsed = netmap.parse_scan(path)
    return parsed, pd.DataFrame(parsed["rows"], columns=netmap.REPORT_FIELDS), pd.DataFrame(parsed["hosts"], columns=netmap.HOST_FIELDS)


def remember_real_scan(parsed: dict, ports: pd.DataFrame, hosts: pd.DataFrame, source_name: str) -> None:
    """Keep the currently loaded real XML scan available throughout this session."""
    parsed = {**parsed, "source": source_name}
    st.session_state["active_scan"] = {
        "kind": "real",
        "parsed": parsed,
        "ports": ports.copy(),
        "hosts": hosts.copy(),
        "source_name": source_name,
    }


def parse_uploaded_scan(uploaded) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    """Parse uploaded bytes from a short-lived temp file without trusting its name."""
    with tempfile.TemporaryDirectory(prefix="netmap-upload-") as temp_dir:
        temp_path = Path(temp_dir) / "upload.xml"
        temp_path.write_bytes(uploaded.getvalue())
        return get_scan_data(temp_path)


def styled_report(parsed: dict, source_name: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "report.html"
        netmap.write_html(output, "NetMap Scan Report", parsed["rows"], netmap.REPORT_FIELDS,
                          f"Real Nmap XML scan | Source: {source_name} | Scan time: {parsed['scan_time']}")
        return output.read_bytes()


def show_scan_metrics(parsed: dict, ports: pd.DataFrame, hosts: pd.DataFrame) -> None:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hosts discovered", len(hosts))
    m2.metric("Open ports", int((ports["state"] == "open").sum()) if not ports.empty else 0, help="Port rows whose Nmap state is exactly open.")
    m3.metric("Port records", len(ports))
    services = ports.loc[ports["service"].astype(bool), "service"].nunique() if not ports.empty else 0
    m4.metric("Services detected", int(services))
    st.caption(f"Scan timestamp: {parsed['scan_time']} · Source file: {parsed['source']}")
    if hosts.empty:
        st.info("This valid Nmap XML contains no host records.")
    elif ports.empty:
        st.info("Hosts were recorded, but this scan contains no port records.")
    elif not (ports["state"].str.lower() == "open").any():
        st.info("No open ports were reported in this scan.")


def show_port_state_chart(ports: pd.DataFrame, title: str = "Port state distribution") -> None:
    if ports.empty:
        st.info("No port records are available for a chart.")
        return
    counts = ports["state"].value_counts().rename_axis("Port state").reset_index(name="Records")
    counts["color"] = counts["Port state"].map(lambda state: "#2563EB" if state.lower() == "open" else "#94A3B8")
    chart = alt.Chart(counts).mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5).encode(
        x=alt.X("Port state:N", title=None, sort="-y"),
        y=alt.Y("Records:Q", title="Records", scale=alt.Scale(domainMin=0)),
        color=alt.Color("color:N", scale=None, legend=None),
        tooltip=[alt.Tooltip("Port state:N"), alt.Tooltip("Records:Q")],
    ).properties(height=220, title=title)
    st.altair_chart(chart, use_container_width=True)


def show_ports(ports: pd.DataFrame, key: str) -> None:
    if ports.empty:
        st.info("No port records were included. A host discovery-only scan may contain hosts without port details.")
    else:
        states = sorted(ports["state"].dropna().unique().tolist())
        selected = st.multiselect("Filter by port state", states, default=states, key=f"state-{key}")
        st.dataframe(styled_frame(ports[ports["state"].isin(selected)]), use_container_width=True, hide_index=True)


def export_scan(parsed: dict, ports: pd.DataFrame, hosts: pd.DataFrame, key: str) -> None:
    left, middle, right = st.columns(3)
    left.download_button("Download ports CSV", frame_csv_bytes(ports), "netmap-ports.csv", "text/csv", key=f"pcsv-{key}")
    middle.download_button("Download hosts CSV", frame_csv_bytes(hosts), "netmap-hosts.csv", "text/csv", key=f"hcsv-{key}")
    source_name = Path(str(parsed.get("source", key))).name
    right.download_button("Download styled HTML", styled_report(parsed, source_name), "netmap-report.html", "text/html", key=f"html-{key}")


def show_comparison(before_path: Path, after_path: Path, before_name: str, after_name: str, key: str, source_label: str) -> pd.DataFrame:
    before, after = netmap.parse_scan(before_path), netmap.parse_scan(after_path)
    after["source"] = after_name
    changes = netmap.compare_parsed_scans(before, after, before_name, after_name)
    frame = pd.DataFrame(changes, columns=netmap.COMPARE_FIELDS)
    c1, c2, c3 = st.columns(3)
    c1.metric("Newly open", int((frame["change"] == "opened").sum()) if not frame.empty else 0)
    c2.metric("No longer open", int((frame["change"] == "no_longer_open").sum()) if not frame.empty else 0)
    c3.metric("Service label changed", int((frame["change"] == "service_changed").sum()) if not frame.empty else 0)
    st.caption(f"Baseline: {before_name} ({before['scan_time']}; {len(before['hosts'])} hosts, {len(before['rows'])} port records) · After: {after_name} ({after['scan_time']}; {len(after['hosts'])} hosts, {len(after['rows'])} port records)")
    if frame.empty:
        st.success("No differences were detected in open ports or service labels between these scans.")
    else:
        for change_type, heading in (("opened", "Newly opened ports"),
                                     ("no_longer_open", "Ports no longer open"),
                                     ("service_changed", "Changed service fingerprints")):
            subset = frame.loc[frame["change"] == change_type]
            if not subset.empty:
                st.markdown(f'<div class="section-heading">{heading} · {len(subset)}</div>', unsafe_allow_html=True)
                st.dataframe(styled_frame(subset), use_container_width=True, hide_index=True)
    a, b = st.columns(2)
    a.download_button("Download comparison CSV", frame_csv_bytes(frame), "netmap-comparison.csv", "text/csv", key=f"ccsv-{key}")
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "comparison.html"
        netmap.write_html(output, "NetMap Before/After Comparison", changes, netmap.COMPARE_FIELDS,
                          f"Real Nmap XML scans | {source_label} | Before: {before_name} ({before['scan_time']}) | After: {after_name} ({after['scan_time']})")
        b.download_button("Download comparison HTML", output.read_bytes(), "netmap-comparison.html", "text/html", key=f"chtml-{key}")
    return frame


if page == "Load scan":
    st.markdown('<div class="section-heading">Open a real Nmap scan</div><div class="section-note">Select a valid saved XML file or upload an Nmap XML scan. No dashboard data appears before a successful load.</div>', unsafe_allow_html=True)
    scans_dir = ROOT / "scans"
    scan_paths = {}
    invalid_count = 0
    if scans_dir.is_dir():
        for candidate in sorted(scans_dir.glob("*.xml"), key=lambda path: path.name.casefold()):
            try:
                netmap.parse_scan(candidate)
                scan_paths[candidate.name] = candidate
            except (ValueError, OSError):
                invalid_count += 1

    source_choice = st.radio("Scan input", ["Select a saved scan", "Upload a scan"], horizontal=True, key="initial-scan-source")
    selected_path = None
    uploaded_scan = None
    if source_choice == "Select a saved scan":
        if scan_paths:
            selected_name = st.selectbox("Saved Nmap XML scan", list(scan_paths), key="initial-saved-scan")
            selected_path = scan_paths[selected_name]
        else:
            st.info("No valid Nmap XML scans were found in the project's scans folder. Choose Upload a scan to open an XML file.")
        if invalid_count:
            st.caption(f"Ignored {invalid_count} XML file(s) that are not valid Nmap scan results.")
    else:
        uploaded_scan = st.file_uploader("Upload an Nmap XML file", type=["xml"], key="initial-scan-upload")

    can_load = (source_choice == "Select a saved scan" and selected_path is not None) or (source_choice == "Upload a scan" and uploaded_scan is not None)
    if st.button("Load Scan", type="primary", key="load-initial-scan", disabled=not can_load):
        try:
            if selected_path is not None:
                parsed, ports, hosts = get_scan_data(selected_path)
                source_name = selected_path.name
            else:
                parsed, ports, hosts = parse_uploaded_scan(uploaded_scan)
                source_name = uploaded_scan.name
            remember_real_scan(parsed, ports, hosts, source_name)
            st.rerun()
        except (ValueError, OSError) as exc:
            st.session_state.pop("active_scan", None)
            st.error(f"Unable to load that scan. Select a valid Nmap XML result or upload another file. Details: {exc}")

elif page == "Overview":
    parsed = active_scan["parsed"]
    ports = active_scan["ports"]
    hosts = active_scan["hosts"]
    key = "active-real-scan"
    show_source_banner(f"REAL NMAP XML SCAN · {active_scan['source_name']}")
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Discovered hosts", len(hosts))
    d2.metric("Open ports", int((ports["state"].str.lower() == "open").sum()) if not ports.empty else 0)
    d3.metric("Services detected", int(ports.loc[ports["service"].astype(bool), "service"].nunique()) if not ports.empty else 0)
    d4.metric("Port records", len(ports))
    st.caption(f"Filename: {active_scan['source_name']} · Scan timestamp: {parsed['scan_time']}")
    left, right = st.columns([1, 1.7])
    with left:
        with st.container(border=True):
            st.markdown('<div class="section-heading">Host inventory</div><div class="section-note">Hosts reported by the selected XML scan</div>', unsafe_allow_html=True)
            if hosts.empty:
                st.info("This valid scan contains no host records.")
            else:
                show_host_status_badges(hosts)
                st.dataframe(styled_frame(hosts[["ip_address", "host_status", "hostname"]]), use_container_width=True, hide_index=True)
    with right:
        with st.container(border=True):
            st.markdown('<div class="section-heading">Port state distribution</div><div class="section-note">Counts calculated only from the selected XML scan</div>', unsafe_allow_html=True)
            show_port_state_chart(ports)
    with st.container(border=True):
        st.markdown('<div class="section-heading">Ports and services</div><div class="section-note">Records parsed from the selected real Nmap XML file</div>', unsafe_allow_html=True)
        show_ports(ports, key)
    export_scan(parsed, ports, hosts, key)

elif page in ("Host Discovery", "Ports & Services", "Reports & Exports"):
    parsed = active_scan["parsed"]
    ports = active_scan["ports"]
    hosts = active_scan["hosts"]
    key = "active-real-scan"
    show_source_banner(f"REAL NMAP XML SCAN · {active_scan['source_name']}")
    if page == "Host Discovery":
        st.markdown('<div class="section-heading">Host inventory</div><div class="section-note">Hosts and addresses reported by the loaded scan.</div>', unsafe_allow_html=True)
        show_scan_metrics(parsed, ports, hosts)
        if hosts.empty:
            st.info("This valid scan contains no host records.")
        else:
            show_host_status_badges(hosts)
            st.dataframe(styled_frame(hosts), use_container_width=True, hide_index=True)
    elif page == "Ports & Services":
        st.markdown('<div class="section-heading">Ports and service fingerprints</div><div class="section-note">Filter rows by Nmap port state.</div>', unsafe_allow_html=True)
        show_scan_metrics(parsed, ports, hosts)
        show_port_state_chart(ports)
        show_ports(ports, key)
    else:
        st.markdown('<div class="section-heading">Export scan reports</div><div class="section-note">Downloads contain only the currently loaded scan.</div>', unsafe_allow_html=True)
        show_scan_metrics(parsed, ports, hosts)
        show_ports(ports, key)
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
            for candidate in sorted(scans_dir.glob("*.xml"), key=lambda path: path.name.casefold()):
                try:
                    netmap.parse_scan(candidate)
                    scan_files.append(candidate)
                except (ValueError, OSError):
                    invalid_count += 1
        if not scan_files:
            st.warning("No valid Nmap XML scans were found in the project's scans folder. Add a valid scan or choose Upload two scans.")
        else:
            names = [path.name for path in scan_files]
            baseline_default = names.index("live_scan.xml") if "live_scan.xml" in names else 0
            after_default = names.index("live_scan_after.xml") if "live_scan_after.xml" in names else min(1, len(names) - 1)
            baseline_col, after_col = st.columns(2)
            with baseline_col:
                baseline_name = st.selectbox(
                    "Baseline scan (original scan)", names, index=baseline_default, key="comparison-baseline-file"
                )
            with after_col:
                after_name = st.selectbox(
                    "After scan (later scan)", names, index=after_default, key="comparison-after-file"
                )
            st.caption("Both comparison inputs are validated Nmap XML scans from the project's scans folder.")
            if invalid_count:
                st.caption(f"Ignored {invalid_count} XML file(s) that are not valid Nmap scan results.")
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
        baseline_upload = a.file_uploader("Baseline scan (original scan)", type=["xml"], key="comparison-baseline-upload")
        after_upload = b.file_uploader("After scan (later scan)", type=["xml"], key="comparison-after-upload")
        if baseline_upload and after_upload:
            if st.button("Compare uploaded scans", type="primary", key="compare-uploaded-scans"):
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
            st.info("Select both a baseline scan and an after scan. Two valid Nmap XML files are required before comparison.")
