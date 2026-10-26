#!/usr/bin/env python3
"""NetMap - lab-only network discovery, Nmap XML reporting and scan comparison.

Use only on systems you own or have explicit permission to test. By design, active
commands accept private IP addresses/ranges rather than DNS hostnames/public targets.
Dependencies: Python 3.10+ standard library. Nmap is required for discover/scan.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import iterparse as safe_iterparse

from netmap_models import HostAsset, ScanInventory, ServiceObservation

REPORT_FIELDS = [
    "scan_time",
    "scan_id",
    "source_kind",
    "source_file",
    "service_id",
    "ip_address",
    "addresses",
    "host_status",
    "port",
    "protocol",
    "state",
    "service",
    "service_identification",
    "product",
    "version",
    "service_method",
    "service_confidence",
    "reason",
]
COMPARE_FIELDS = [
    "change",
    "confidence",
    "limitation",
    "rule_id",
    "evidence",
    "ip_address",
    "port",
    "protocol",
    "before_service",
    "after_service",
    "before_state",
    "after_state",
    "baseline_scan",
    "baseline_timestamp",
    "after_scan",
    "after_timestamp",
]
HOST_FIELDS = [
    "host_id",
    "scan_id",
    "scan_time",
    "source_kind",
    "source_file",
    "ip_address",
    "address_type",
    "addresses",
    "host_status",
    "reason",
    "hostname",
]
MAX_XML_BYTES = 20 * 1024 * 1024
MAX_SCAN_TIMEOUT = 600
MAX_PORTS_PER_SCAN = 2048
MAX_DISCOVERY_HOSTS = 256
MAX_GRAPH_NODES_PER_KIND = 250


def _csv_safe(value: Any) -> str:
    """Prevent spreadsheet applications from evaluating untrusted cells as formulas."""
    text = str(value if value is not None else "")
    if text.lstrip("\ufeff\t\r\n ").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _atomic_write(path: str | Path, writer) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except OSError as exc:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise ValueError(
            f"Could not write report to '{destination}': {exc.strerror or 'filesystem error'}"
        ) from exc


def _reject_input_overwrite(
    inputs: list[str | Path], outputs: list[str | Path]
) -> None:
    resolved_inputs = {Path(path).resolve() for path in inputs}
    for output in outputs:
        if Path(output).resolve() in resolved_inputs:
            raise ValueError("An output path cannot overwrite an input scan file.")


def _scan_time(root: ET.Element) -> str:
    readable = root.get("startstr")
    if readable:
        return readable
    raw = root.get("start")
    if raw:
        try:
            return (
                datetime.fromtimestamp(int(raw), tz=UTC)
                .astimezone()
                .isoformat(timespec="seconds")
            )
        except (ValueError, OverflowError, OSError):
            pass
    return "unknown"


def _host_details(host: ET.Element) -> tuple[str, str, str, str, str, str]:
    addresses = host.findall("address")
    present_addresses = [
        (node.get("addr", ""), node.get("addrtype", "unknown"))
        for node in addresses
        if node.get("addr")
    ]
    selected = None
    for wanted in ("ipv4", "ipv6", "mac"):
        selected = next(
            (a for a in addresses if a.get("addrtype") == wanted and a.get("addr")),
            None,
        )
        if selected is not None:
            break
    ip = selected.get("addr", "unknown") if selected is not None else "unknown"
    addr_type = (
        selected.get("addrtype", "unknown") if selected is not None else "unknown"
    )
    all_addresses = "; ".join(
        f"{address} ({kind})" for address, kind in present_addresses
    )
    status_node = host.find("status")
    status = (
        status_node.get("state", "unknown") if status_node is not None else "unknown"
    )
    reason = status_node.get("reason", "") if status_node is not None else ""
    hostname_node = host.find("hostnames/hostname")
    hostname = hostname_node.get("name", "") if hostname_node is not None else ""
    return ip, addr_type, all_addresses, status, reason, hostname


def _service_details(port: ET.Element) -> tuple[str, str, str, str, str]:
    service = port.find("service")
    if service is None:
        return "unknown", "", "", "", ""
    return (
        service.get("name", "unknown"),
        service.get("product", ""),
        service.get("version", ""),
        service.get("method", ""),
        service.get("conf", ""),
    )


def parse_scan(path: str | Path) -> dict[str, Any]:
    """Stream and normalize bounded Nmap XML without retaining the source tree."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise ValueError(
            f"Cannot access Nmap XML file '{file_path.name}': {exc.strerror or 'file error'}"
        ) from exc
    if size > MAX_XML_BYTES:
        raise ValueError(
            f"Nmap XML exceeds the {MAX_XML_BYTES // (1024 * 1024)} MiB input limit."
        )
    if size == 0:
        raise ValueError("Nmap XML file is empty.")
    try:
        iterator = safe_iterparse(
            file_path,
            events=("start", "end"),
            forbid_dtd=False,
            forbid_entities=True,
            forbid_external=True,
        )
        _, root = next(iterator)
        if root.tag != "nmaprun":
            raise ValueError(
                f"'{file_path.name}' is not Nmap XML (expected <nmaprun>)."
            )
        scan_time = _scan_time(root)
        scanner = root.get("scanner", "unknown")
        scan_args = root.get("args", "")
        scan_id = hashlib.sha256(
            f"{scanner}|{scan_time}|{scan_args}".encode()
        ).hexdigest()[:16]
        scan_coverage: dict[str, set[int]] = {}
        coverage_known = False
        complete = None
        hosts_by_ip: dict[str, dict[str, str]] = {}
        rows_by_endpoint: dict[tuple[str, str, str], dict[str, str]] = {}
        for event, node in iterator:
            if event != "end":
                continue
            if node.tag == "scaninfo":
                protocol = node.get("protocol", "unknown").lower()
                services = node.get("services", "")
                try:
                    ports = _expand_port_list(services)
                except ValueError:
                    ports = set()
                scan_coverage.setdefault(protocol, set()).update(ports)
                coverage_known = coverage_known or bool(ports)
                node.clear()
                root.remove(node)
            elif node.tag == "finished":
                complete = node.get("exit", "") == "success"
                node.clear()
            elif node.tag == "host":
                ip, addr_type, addresses, status, reason, hostname = _host_details(node)
                try:
                    ip = str(ipaddress.ip_address(ip)) if ip != "unknown" else ip
                except ValueError:
                    ip = "unknown"
                host_id = hashlib.sha256(ip.lower().encode("utf-8")).hexdigest()[:16]
                host = HostAsset(
                    host_id=host_id,
                    scan_id=scan_id,
                    scan_time=scan_time,
                    ip_address=ip,
                    address_type=addr_type,
                    addresses=addresses,
                    host_status=status.lower(),
                    reason=reason,
                    hostname=hostname,
                ).to_record()
                hosts_by_ip[ip] = host
                ports_node = node.find("ports")
                if ports_node is not None:
                    for port_node in ports_node.findall("port"):
                        raw_port = port_node.get("portid", "")
                        protocol = port_node.get("protocol", "unknown").lower()
                        if not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65535:
                            continue
                        port_number = str(int(raw_port))
                        state_node = port_node.find("state")
                        state = (
                            state_node.get("state", "unknown").lower()
                            if state_node is not None
                            else "unknown"
                        )
                        if state not in {
                            "open",
                            "closed",
                            "filtered",
                            "unfiltered",
                            "open|filtered",
                            "closed|filtered",
                        }:
                            state = "unknown"
                        reason_port = (
                            state_node.get("reason", "")
                            if state_node is not None
                            else ""
                        )
                        (
                            service,
                            product,
                            version,
                            service_method,
                            service_confidence,
                        ) = _service_details(port_node)
                        identification = (
                            "unknown"
                            if service == "unknown"
                            else (
                                "confirmed"
                                if service_method == "probed"
                                else "inferred"
                            )
                        )
                        service_id = f"{host_id}:{protocol}:{port_number}"
                        observation = ServiceObservation(
                            service_id=service_id,
                            scan_id=scan_id,
                            scan_time=scan_time,
                            ip_address=ip,
                            addresses=addresses,
                            host_status=status.lower(),
                            port=port_number,
                            protocol=protocol,
                            state=state,
                            service=service or "unknown",
                            service_identification=identification,
                            product=product,
                            version=version,
                            service_method=service_method,
                            service_confidence=service_confidence,
                            reason=reason_port,
                        )
                        rows_by_endpoint[(ip, protocol, port_number)] = (
                            observation.to_record()
                        )
                node.clear()
    except DefusedXmlException as exc:
        raise ValueError(
            f"Cannot parse Nmap XML file '{file_path.name}': XML security policy rejected the input."
        ) from exc
    except ValueError:
        raise
    except (ET.ParseError, OSError, StopIteration, RecursionError) as exc:
        raise ValueError(
            f"Cannot parse Nmap XML file '{file_path.name}': {type(exc).__name__}."
        ) from exc
    if root.tag != "nmaprun":
        raise ValueError(f"'{file_path.name}' is not Nmap XML (expected <nmaprun>).")
    coverage = {protocol: sorted(ports) for protocol, ports in scan_coverage.items()}
    parsed = ScanInventory(
        scan_id=scan_id,
        scan_time=scan_time,
        rows=list(rows_by_endpoint.values()),
        hosts=list(hosts_by_ip.values()),
        source=str(file_path),
        source_kind="imported_nmap_xml",
        scanner=scanner,
        coverage=coverage,
        coverage_known=coverage_known,
        complete=complete,
    ).to_record()
    return set_scan_provenance(parsed, "imported_nmap_xml", file_path.name)


def _expand_port_list(value: str) -> set[int]:
    result: set[int] = set()
    for part in value.split(","):
        if not part:
            continue
        bounds = part.split("-")
        if len(bounds) == 1 and bounds[0].isdecimal():
            start = end = int(bounds[0])
        elif len(bounds) == 2 and all(bound.isdecimal() for bound in bounds):
            start, end = map(int, bounds)
        else:
            raise ValueError("Invalid scan coverage")
        if not (1 <= start <= end <= 65535):
            raise ValueError("Invalid scan coverage")
        result.update(range(start, end + 1))
    return result


def set_scan_provenance(
    parsed: dict[str, Any], source_kind: str, source_file: str | None = None
) -> dict[str, Any]:
    """Update the scan and its records with a safe, basename-only provenance label."""
    name = Path(source_file or parsed.get("source", "unknown")).name
    parsed["source_kind"] = source_kind
    for collection in (parsed.get("hosts", []), parsed.get("rows", [])):
        for item in collection:
            item["source_kind"] = source_kind
            item["source_file"] = name
    return parsed


def write_csv(path: str | Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    def write(handle) -> None:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {field: _csv_safe(row.get(field, "")) for field in fields} for row in rows
        )

    _atomic_write(path, write)


def csv_bytes(rows: list[dict[str, Any]], fields: list[str]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(
        {field: _csv_safe(row.get(field, "")) for field in fields} for row in rows
    )
    return handle.getvalue().encode("utf-8")


def write_html(
    path: str | Path,
    title: str,
    rows: list[dict[str, str]],
    fields: list[str],
    subtitle: str = "",
    findings: list[dict[str, str]] | None = None,
    hosts: list[dict[str, str]] | None = None,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    header_cells = "".join(
        f"<th>{html.escape(field.replace('_', ' ').title())}</th>" for field in fields
    )
    body_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape(str(row.get(field, '')))}</td>" for field in fields
        )
        state = str(row.get("state", row.get("change", ""))).lower().replace(" ", "-")
        body_rows.append(f'<tr class="{html.escape(state, quote=True)}">{cells}</tr>')
    if body_rows:
        body = "\n".join(body_rows)
    else:
        empty_message = (
            "No differences detected between these scans."
            if "change" in fields
            else "No rows found in this file."
        )
        body = f'<tr><td colspan="{len(fields)}">{empty_message}</td></tr>'
    safe_title, safe_subtitle = html.escape(title), html.escape(subtitle)
    finding_section = ""
    if findings:
        rendered = "".join(
            "<li><strong>"
            + html.escape(finding["severity"].upper() + " · " + finding["title"])
            + "</strong> — "
            + html.escape(finding["evidence"])
            + "<br>"
            + html.escape(finding["recommendation"])
            + "<br><small>Limitation: "
            + html.escape(finding.get("limitation", ""))
            + "</small></li>"
            for finding in findings
        )
        finding_section = f"<section><h2>Rule-based review signals</h2><p>These observations are not vulnerability confirmations.</p><ul>{rendered}</ul></section>"
    host_section = ""
    if hosts is not None:
        host_columns = ("ip_address", "hostname", "host_status", "address_type")
        host_head = "".join(
            f"<th>{html.escape(column.replace('_', ' ').title())}</th>"
            for column in host_columns
        )
        host_rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(host.get(column, '')))}</td>"
                for column in host_columns
            )
            + "</tr>"
            for host in hosts
        )
        if not host_rows:
            host_rows = (
                f'<tr><td colspan="{len(host_columns)}">No host records.</td></tr>'
            )
        host_section = f"<section><h2>Observed host inventory</h2><table><thead><tr>{host_head}</tr></thead><tbody>{host_rows}</tbody></table></section>"
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title><style>
:root{{--navy:#17365d;--blue:#dce6f1;--teal:#0f766e;--line:#cbd5e1;--ink:#172033;}}
body{{font-family:Arial,Helvetica,sans-serif;margin:28px;color:var(--ink);background:#f8fafc}}
header{{border-bottom:4px solid var(--teal);padding-bottom:14px;margin-bottom:22px}}
h1{{color:var(--navy);font-size:25px;margin:0 0 8px}}.subtitle{{color:#475569;font-size:13px}}
table{{width:100%;border-collapse:collapse;background:white;font-size:12px;table-layout:auto}}
th{{background:var(--navy);color:white;text-align:left;padding:10px 8px;position:sticky;top:0}}
td{{border:1px solid var(--line);padding:8px;overflow-wrap:anywhere}}tr:nth-child(even){{background:#eef3f8}}
tr.open{{border-left:4px solid #15803d}}tr.filtered{{border-left:4px solid #b45309}}tr.closed{{border-left:4px solid #b91c1c}}
footer{{margin-top:18px;font-size:11px;color:#64748b}}
</style></head><body><header><h1>{safe_title}</h1><div class="subtitle">{safe_subtitle}</div></header>
{host_section}<section><h2>Observed port records</h2><table><thead><tr>{header_cells}</tr></thead><tbody>{body}</tbody></table></section>{finding_section}
<footer>Generated by NetMap. Interpret results in the context of scan options, host state and filtering. Missing observations do not prove a host or service is offline or closed.</footer></body></html>"""
    _atomic_write(path, lambda handle: handle.write(document))


def build_network_graph(parsed: dict[str, Any]) -> dict[str, Any]:
    """Build only evidence-backed host-to-observed-service edges."""
    all_hosts = {host["ip_address"]: host for host in parsed.get("hosts", [])}
    hosts = dict(sorted(all_hosts.items())[:MAX_GRAPH_NODES_PER_KIND])
    nodes = [
        {
            "id": host["host_id"],
            "kind": "host",
            "label": host["ip_address"],
            "hostname": host.get("hostname", ""),
            "status": host.get("host_status", "unknown"),
        }
        for host in sorted(hosts.values(), key=lambda item: item["ip_address"])
    ]
    edges = []
    open_rows = [
        row for row in parsed.get("rows", []) if row.get("state", "").lower() == "open"
    ]
    open_rows.sort(
        key=lambda item: (item["ip_address"], item["protocol"], int(item["port"]))
    )
    visible_rows = open_rows[:MAX_GRAPH_NODES_PER_KIND]
    for row in visible_rows:
        if row["ip_address"] not in hosts:
            continue
        node_id = (
            row.get("service_id")
            or f"{row['ip_address']}:{row['protocol']}:{row['port']}"
        )
        nodes.append(
            {
                "id": node_id,
                "kind": "service",
                "label": f"{row['protocol'].upper()}/{row['port']}",
                "service": _service_label(row),
                "state": row["state"],
            }
        )
        edges.append(
            {
                "source": hosts[row["ip_address"]]["host_id"],
                "target": node_id,
                "evidence": f"Nmap observed {row['state']} {row['protocol']}/{row['port']}",
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "omitted_host_count": max(0, len(all_hosts) - len(hosts)),
        "omitted_service_count": max(0, len(open_rows) - len(edges)),
    }


def network_graph_dot(parsed: dict[str, Any]) -> str:
    """Serialize the observed graph as DOT, quoting all labels as string literals."""
    graph = build_network_graph(parsed)
    lines = [
        "digraph NetMap {",
        'graph [rankdir="LR", bgcolor="white", pad="0.3", nodesep="0.45", ranksep="0.8"];',
        'node [shape="box", style="rounded,filled", fontname="Arial", fontsize="10", color="#64748b"];',
        'edge [color="#94a3b8", arrowsize="0.7"];',
    ]
    for node in graph["nodes"]:
        label = node["label"]
        if node["kind"] == "host" and node.get("hostname"):
            label += "\\n" + node["hostname"]
        elif node["kind"] == "service":
            label += "\\n" + node.get("service", "unknown")
        node_id = json.dumps(node["id"])
        node_label = json.dumps(label, ensure_ascii=True)
        fill = "#dbeafe" if node["kind"] == "host" else "#dcfce7"
        lines.append(f"{node_id} [label={node_label}, fillcolor={json.dumps(fill)}];")
    for edge in graph["edges"]:
        lines.append(f"{json.dumps(edge['source'])} -> {json.dumps(edge['target'])};")
    lines.append("}")
    return "\n".join(lines)


def analyze_exposure(parsed: dict[str, Any]) -> list[dict[str, str]]:
    """Apply transparent heuristic rules; findings are not vulnerability claims."""
    findings = []
    for row in parsed.get("rows", []):
        if row.get("state", "").lower() != "open":
            continue
        service = row.get("service", "unknown").lower()
        port = row.get("port", "")
        rule = None
        if service == "telnet" or (port == "23" and service != "unknown"):
            rule = (
                "NETMAP-CLEAR-TEXT-TELNET",
                "medium",
                "Telnet service observed",
                "Telnet commonly sends session content without transport encryption.",
                "Restrict access and replace Telnet with a managed SSH configuration where feasible.",
            )
        elif service == "ftp" or (port == "21" and service != "unknown"):
            rule = (
                "NETMAP-CLEAR-TEXT-FTP",
                "medium",
                "FTP service observed",
                "Traditional FTP commonly sends credentials and data without transport encryption.",
                "Restrict access and prefer SFTP or FTPS with managed credentials.",
            )
        elif service in {
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            "ms-sql-s",
            "oracle",
        }:
            rule = (
                "NETMAP-DATABASE-REACHABLE",
                "medium",
                "Database service observed reachable",
                "The scan reports an open endpoint with a database service label; exposure scope needs owner review.",
                "Restrict database access to required application hosts and verify authentication and transport settings.",
            )
        if rule is None:
            continue
        rule_id, severity, title, description, recommendation = rule
        evidence = f"Nmap reported {row['protocol']}/{port} open; service={service}; method={row.get('service_method') or 'not recorded'}; confidence={row.get('service_confidence') or 'not recorded'}."
        findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "asset_id": row.get("service_id", ""),
                "host_id": hashlib.sha256(
                    row["ip_address"].lower().encode()
                ).hexdigest()[:16],
                "address": row["ip_address"],
                "port": port,
                "protocol": row["protocol"],
                "title": title,
                "description": description,
                "evidence": evidence,
                "explanation": "This rule records a service/configuration review signal from observed scan output. It does not establish a vulnerability or exploitability.",
                "limitation": "Service labels may be inferred; the rule does not confirm a CVE, vulnerability, exploitability, or whether the exposure is unintended.",
                "recommendation": recommendation,
                "timestamp": row.get("scan_time", "unknown"),
                "source": parsed.get("source_kind", "imported_nmap_xml"),
                "classification": "observed service; inferred review priority",
            }
        )
    return findings


def report_document(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "netmap.report.v1",
        "generated_at": parsed.get("scan_time", "unknown"),
        "scan": {
            "id": parsed.get("scan_id", "unknown"),
            "timestamp": parsed.get("scan_time", "unknown"),
            "source": Path(str(parsed.get("source", "unknown"))).name,
            "source_kind": parsed.get("source_kind", "imported_nmap_xml"),
            "scanner": parsed.get("scanner", "unknown"),
            "complete": parsed.get("complete"),
            "coverage": parsed.get("coverage", {}),
        },
        "summary": {
            "hosts": len(parsed.get("hosts", [])),
            "services": len(parsed.get("rows", [])),
            "open_services": sum(
                row.get("state") == "open" for row in parsed.get("rows", [])
            ),
            "findings": len(analyze_exposure(parsed)),
        },
        "hosts": parsed.get("hosts", []),
        "services": parsed.get("rows", []),
        "findings": analyze_exposure(parsed),
        "limitations": [
            "Findings are review signals, not vulnerability confirmations.",
            "An absent host or endpoint is not proof that it is offline or closed.",
            "Results depend on scan authorization, coverage, timing, and network filtering.",
        ],
    }


def write_json(path: str | Path, parsed: dict[str, Any]) -> None:
    data = (
        json.dumps(
            report_document(parsed), ensure_ascii=False, sort_keys=True, indent=2
        )
        + "\n"
    )
    _atomic_write(path, lambda handle: handle.write(data))


def write_findings_csv(path: str | Path, parsed: dict[str, Any]) -> None:
    findings = analyze_exposure(parsed)
    fields = [
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
    ]
    write_csv(path, findings, fields)


def write_network_svg(path: str | Path, parsed: dict[str, Any]) -> None:
    graph = build_network_graph(parsed)
    hosts = [node for node in graph["nodes"] if node["kind"] == "host"]
    services = [node for node in graph["nodes"] if node["kind"] == "service"]
    host_x, service_x, row_h, top = 180, 560, 76, 104
    height = max(160, top + row_h * max(len(hosts), len(services), 1) + 40)
    host_positions = {
        node["id"]: (host_x, top + i * row_h) for i, node in enumerate(hosts)
    }
    service_positions = {
        node["id"]: (service_x, top + i * row_h) for i, node in enumerate(services)
    }
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" viewBox="0 0 760 {height}">',
        '<title id="title">NetMap observed network inventory</title>',
        '<desc id="desc">Edges connect each host only to open services observed in the input scan. Missing hosts or endpoints are not proven offline or closed.</desc>',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text x="28" y="32" font-family="sans-serif" font-size="18" font-weight="700" fill="#172033">Observed hosts and open services</text>',
    ]
    provenance = f"{parsed.get('source_kind', 'imported_nmap_xml')} · {Path(str(parsed.get('source', 'unknown'))).name} · {parsed.get('scan_time', 'unknown')}"
    elements.append(
        f'<text x="28" y="54" font-family="sans-serif" font-size="11" fill="#475569">{html.escape(provenance)}</text>'
    )
    if graph["omitted_host_count"] or graph["omitted_service_count"]:
        note = f"Graph capped: {graph['omitted_host_count']} host(s), {graph['omitted_service_count']} service(s) omitted; use inventory export for all records."
        elements.append(
            f'<text x="28" y="52" font-family="sans-serif" font-size="11" fill="#475569">{html.escape(note)}</text>'
        )
    for edge in graph["edges"]:
        x1, y1 = host_positions[edge["source"]]
        x2, y2 = service_positions[edge["target"]]
        elements.append(
            f'<path d="M{x1 + 82} {y1} C340 {y1}, 400 {y2}, {x2 - 12} {y2}" fill="none" stroke="#94a3b8" stroke-width="2"/>'
        )
    for x, y, label, kind in [
        (
            *host_positions[n["id"]],
            n["label"] + (f" · {n['hostname']}" if n.get("hostname") else ""),
            "host",
        )
        for n in hosts
    ] + [
        (
            *service_positions[n["id"]],
            n["label"] + " · " + n.get("service", "unknown"),
            "service",
        )
        for n in services
    ]:
        fill = "#dbeafe" if kind == "host" else "#dcfce7"
        elements.append(
            f'<rect x="{x - 82}" y="{y - 20}" width="260" height="40" rx="9" fill="{fill}" stroke="#64748b"/>'
        )
        elements.append(
            f'<text x="{x - 70}" y="{y + 5}" font-family="sans-serif" font-size="13" fill="#172033">{html.escape(label)}</text>'
        )
    elements.append("</svg>")
    _atomic_write(path, lambda handle: handle.write("\n".join(elements)))


def _open_service_map(
    parsed: dict[str, Any],
) -> dict[tuple[str, str, str], dict[str, str]]:
    mapped = {}
    for row in parsed["rows"]:
        if row["state"].lower() == "open":
            mapped[(row["ip_address"], row["port"], row["protocol"])] = row
    return mapped


def _all_service_map(
    parsed: dict[str, Any],
) -> dict[tuple[str, str, str], dict[str, str]]:
    return {
        (row["ip_address"], row["port"], row["protocol"]): row
        for row in parsed.get("rows", [])
    }


def _coverage_contains(parsed: dict[str, Any], protocol: str, port: str) -> bool:
    try:
        return int(port) in parsed.get("coverage", {}).get(protocol, [])
    except (TypeError, ValueError):
        return False


def _service_label(row: dict[str, str]) -> str:
    parts = [
        row.get("service", "unknown"),
        row.get("product", ""),
        row.get("version", ""),
    ]
    return " ".join(part for part in parts if part).strip() or "unknown"


def compare_parsed_scans(
    before: dict[str, Any],
    after: dict[str, Any],
    before_name: str | None = None,
    after_name: str | None = None,
) -> list[dict[str, str]]:
    """Compare explicit endpoint observations without equating absence with closure."""
    old_rows, new_rows = _all_service_map(before), _all_service_map(after)
    before_name = before_name or Path(before.get("source", "baseline.xml")).name
    after_name = after_name or Path(after.get("source", "after.xml")).name
    metadata = {
        "baseline_scan": before_name,
        "baseline_timestamp": before["scan_time"],
        "after_scan": after_name,
        "after_timestamp": after["scan_time"],
    }
    changes: list[dict[str, str]] = []
    old_hosts = {host["ip_address"] for host in before.get("hosts", [])}
    new_hosts = {host["ip_address"] for host in after.get("hosts", [])}
    for address in sorted(new_hosts - old_hosts):
        changes.append(
            {
                "change": "host_newly_observed",
                "confidence": "low",
                "limitation": "This host appears in the later input; the baseline's scope and coverage do not establish when it became reachable.",
                "ip_address": address,
                "port": "",
                "protocol": "",
                **metadata,
                "before_service": "",
                "after_service": "",
                "before_state": "not observed",
                "after_state": "observed",
            }
        )
    for address in sorted(old_hosts - new_hosts):
        changes.append(
            {
                "change": "host_not_observed",
                "confidence": "low",
                "limitation": "The later scan did not record this host; this does not prove it is offline or removed.",
                "ip_address": address,
                "port": "",
                "protocol": "",
                **metadata,
                "before_service": "",
                "after_service": "",
                "before_state": "observed",
                "after_state": "not observed",
            }
        )
    for key in sorted(old_rows.keys() | new_rows.keys()):
        old, new = old_rows.get(key), new_rows.get(key)
        if old is None and new is not None and new["state"] == "open":
            changes.append(
                {
                    "change": "newly_observed_open",
                    "confidence": "low",
                    "limitation": "The baseline did not record this endpoint; baseline coverage or omission prevents claiming it was closed.",
                    "ip_address": key[0],
                    "port": key[1],
                    "protocol": key[2],
                    **metadata,
                    "before_service": "",
                    "after_service": _service_label(new),
                    "before_state": "not observed",
                    "after_state": "open",
                }
            )
        elif old is not None and new is None and old["state"] == "open":
            if key[0] not in new_hosts:
                change, confidence = "not_assessed", "low"
                limitation = "The later scan did not record the host; service availability cannot be inferred."
            elif after.get("complete") is True and _coverage_contains(
                after, key[2], key[1]
            ):
                change, confidence = "no_longer_observed", "moderate"
                limitation = "The later completed scan covered this endpoint but did not report it open; this is not proof of administrative closure."
            else:
                change, confidence = "not_assessed", "low"
                limitation = (
                    "Later scan coverage or completeness is unknown for this endpoint."
                )
            changes.append(
                {
                    "change": change,
                    "confidence": confidence,
                    "limitation": limitation,
                    "ip_address": key[0],
                    "port": key[1],
                    "protocol": key[2],
                    **metadata,
                    "before_service": _service_label(old),
                    "after_service": "",
                    "before_state": "open",
                    "after_state": "not observed",
                }
            )
        elif old is not None and new is not None:
            if old["state"] != new["state"]:
                changes.append(
                    {
                        "change": "state_changed",
                        "confidence": "moderate",
                        "limitation": "States are observations at two times and can be affected by filtering or transient network conditions.",
                        "ip_address": key[0],
                        "port": key[1],
                        "protocol": key[2],
                        **metadata,
                        "before_service": _service_label(old),
                        "after_service": _service_label(new),
                        "before_state": old["state"],
                        "after_state": new["state"],
                    }
                )
            elif old["state"] == "open" and _service_label(old) != _service_label(new):
                changes.append(
                    {
                        "change": "service_changed",
                        "confidence": "moderate",
                        "limitation": "Service fingerprints depend on probe coverage and may vary without a software change.",
                        "ip_address": key[0],
                        "port": key[1],
                        "protocol": key[2],
                        **metadata,
                        "before_service": _service_label(old),
                        "after_service": _service_label(new),
                        "before_state": old["state"],
                        "after_state": new["state"],
                    }
                )
    old_findings = {
        (item["rule_id"], item["address"], item["protocol"], item["port"]): item
        for item in analyze_exposure(before)
    }
    new_findings = {
        (item["rule_id"], item["address"], item["protocol"], item["port"]): item
        for item in analyze_exposure(after)
    }
    for key in sorted(old_findings.keys() | new_findings.keys()):
        old, new = old_findings.get(key), new_findings.get(key)
        if old is None and new is not None:
            change, evidence = "finding_new", new["evidence"]
        elif old is not None and new is None:
            change, evidence = "finding_no_longer_matches", old["evidence"]
        else:
            continue
        changes.append(
            {
                "change": change,
                "confidence": "moderate",
                "limitation": "This rule match changed with the observed service data; this does not prove remediation or confirm a vulnerability.",
                "rule_id": key[0],
                "evidence": evidence,
                "ip_address": key[1],
                "protocol": key[2],
                "port": key[3],
                **metadata,
                "before_service": _service_label(old) if old else "",
                "after_service": _service_label(new) if new else "",
                "before_state": "matched" if old else "not matched",
                "after_state": "matched" if new else "not matched",
            }
        )
    return changes


def compare_scans(
    before_path: str | Path, after_path: str | Path
) -> list[dict[str, str]]:
    """Compare XML observations without making absence imply offline or closed."""
    before, after = parse_scan(before_path), parse_scan(after_path)
    return compare_parsed_scans(
        before, after, Path(before_path).name, Path(after_path).name
    )


def _require_nmap() -> str:
    exe = shutil.which("nmap")
    if not exe:
        raise ValueError(
            "Nmap was not found. Install Nmap, then verify with: nmap --version"
        )
    return exe


def _validate_private_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(
            "Target must be a single private IP address (not a hostname or public IP)."
        ) from exc
    if (
        addr.version != 4
        or not (addr.is_private or addr.is_loopback)
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    ):
        raise ValueError(
            "For this lab tool, target must be a private or loopback IPv4 address (for example 192.168.56.101 or 127.0.0.1)."
        )
    return str(addr)


def _validate_private_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(
            "Network must be a CIDR range such as 192.168.56.0/24."
        ) from exc
    if (
        network.version != 4
        or not (network.is_private or network.is_loopback)
        or network.is_multicast
        or network.num_addresses > MAX_DISCOVERY_HOSTS
    ):
        raise ValueError(
            f"Use an IPv4 private or loopback lab range containing no more than {MAX_DISCOVERY_HOSTS} addresses."
        )
    return str(network)


def _validate_ports(value: str) -> str:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("Ports must look like 22,80,443 or 1-1000 (no spaces).")
    for chunk in value.split(","):
        parts = [int(part) for part in chunk.split("-")]
        if (
            any(p < 1 or p > 65535 for p in parts)
            or len(parts) == 2
            and parts[0] > parts[1]
        ):
            raise ValueError(f"Invalid port range: {chunk}")
    if len(_expand_port_list(value)) > MAX_PORTS_PER_SCAN:
        raise ValueError(f"A scan is limited to {MAX_PORTS_PER_SCAN} distinct ports.")
    return value


def _validate_timeout(value: int) -> int:
    if not 1 <= value <= MAX_SCAN_TIMEOUT:
        raise ValueError(f"Timeout must be between 1 and {MAX_SCAN_TIMEOUT} seconds.")
    return value


def _require_authorization(args: argparse.Namespace) -> None:
    if not getattr(args, "authorized_lab_target", False):
        raise ValueError(
            "Active scanning is disabled until you pass --authorized-lab-target to acknowledge you own or are authorized to test the target."
        )


def _run_nmap(command: list[str], timeout: int) -> int:
    print("Running an authorized, bounded Nmap operation.")
    try:
        result = subprocess.run(
            command, check=False, timeout=timeout, text=True, capture_output=True
        )
    except subprocess.TimeoutExpired:
        raise ValueError(
            f"Nmap timed out after {timeout} seconds. Try fewer ports or increase --timeout."
        )
    if result.returncode != 0:
        raise ValueError(
            f"Nmap exited with status {result.returncode}. Check permissions, target address, and installation."
        )
    return result.returncode


def cmd_check(args: argparse.Namespace) -> int:
    exe = _require_nmap()
    result = subprocess.run(
        [exe, "--version"], check=False, capture_output=True, text=True
    )
    print(result.stdout.splitlines()[0] if result.stdout else "Nmap is installed.")
    print("Python:", sys.version.split()[0])
    print("Nmap path:", exe)
    return 0 if result.returncode == 0 else 1


def cmd_discover(args: argparse.Namespace) -> int:
    _require_authorization(args)
    _validate_timeout(args.timeout)
    network = _validate_private_network(args.network)
    exe = _require_nmap()
    dest = Path(args.xml)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        exe,
        "-sn",
        "--max-rate",
        "100",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{args.timeout}s",
        "-oX",
        str(dest),
        network,
    ]
    _run_nmap(cmd, args.timeout)
    if not dest.exists():
        raise ValueError("Nmap finished but the requested XML file was not created.")
    data = parse_scan(dest)
    set_scan_provenance(data, "authorized_nmap_discovery", dest.name)
    up = sum(1 for h in data["hosts"] if h["host_status"] == "up")
    print(f"Discovery complete: {up} up host(s) recorded in {dest}")
    print(
        "Next: review the host-only subnet in Wireshark and scan only your known target IP."
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    _require_authorization(args)
    _validate_timeout(args.timeout)
    target = _validate_private_ip(args.target)
    ports = _validate_ports(args.ports)
    exe = _require_nmap()
    dest = Path(args.xml)
    dest.parent.mkdir(parents=True, exist_ok=True)
    scan_switch = "-sS" if args.scan_type == "syn" else "-sT"
    cmd = [
        exe,
        scan_switch,
        "-sV",
        "--reason",
        "--max-rate",
        "100",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{args.timeout}s",
        "-p",
        ports,
        "-oX",
        str(dest),
        target,
    ]
    _run_nmap(cmd, args.timeout)
    if not dest.exists():
        raise ValueError("Nmap finished but the requested XML file was not created.")
    parsed = parse_scan(dest)
    set_scan_provenance(parsed, "authorized_nmap_scan", dest.name)
    open_rows = [r for r in parsed["rows"] if r["state"] == "open"]
    print(
        f"Scan complete: {len(parsed['rows'])} port record(s), {len(open_rows)} open port(s). XML: {dest}"
    )
    print(
        f"Next: py netmap.py report {dest} --csv outputs/scan.csv --html outputs/scan.html"
    )
    if args.scan_type == "syn":
        print(
            "Note: SYN scans usually need elevated privileges. On Windows, run an approved elevated terminal if required; TCP connect is more portable."
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    parsed = parse_scan(args.xml)
    if "sample_data" in {part.casefold() for part in Path(args.xml).parts}:
        set_scan_provenance(parsed, "synthetic_demo", Path(args.xml).name)
    _reject_input_overwrite(
        [args.xml],
        [
            path
            for path in (
                args.csv,
                args.html,
                args.hosts_csv,
                args.json,
                args.findings_csv,
                args.svg,
            )
            if path
        ],
    )
    write_csv(args.csv, parsed["rows"], REPORT_FIELDS)
    synthetic = any(part.lower() == "sample_data" for part in Path(args.xml).parts)
    source_note = (
        "SYNTHETIC DEMONSTRATION DATA - NOT A LIVE SCAN"
        if synthetic
        else "Source: saved Nmap XML"
    )
    write_html(
        args.html,
        "NetMap Scan Report",
        parsed["rows"],
        REPORT_FIELDS,
        f"{source_note} | Source kind: {parsed['source_kind']} | Source file: {Path(args.xml).name} | Scan time: {parsed['scan_time']} | Hosts recorded: {len(parsed['hosts'])} | Port records: {len(parsed['rows'])}",
        analyze_exposure(parsed),
        parsed["hosts"],
    )
    if args.hosts_csv:
        write_csv(args.hosts_csv, parsed["hosts"], HOST_FIELDS)
    if args.json:
        write_json(args.json, parsed)
    if args.findings_csv:
        write_findings_csv(args.findings_csv, parsed)
    if args.svg:
        write_network_svg(args.svg, parsed)
    open_count = sum(1 for r in parsed["rows"] if r["state"] == "open")
    print(f"Scan time: {parsed['scan_time']}")
    print(
        f"Hosts recorded: {len(parsed['hosts'])}; port records: {len(parsed['rows'])}; open ports: {open_count}"
    )
    print(f"CSV report: {args.csv}\nHTML report: {args.html}")
    if args.hosts_csv:
        print(f"Host inventory CSV: {args.hosts_csv}")
    for label, path in (
        ("JSON report", args.json),
        ("Findings CSV", args.findings_csv),
        ("Network SVG", args.svg),
    ):
        if path:
            print(f"{label}: {path}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    changes = compare_scans(args.before, args.after)
    _reject_input_overwrite([args.before, args.after], [args.csv, args.html])
    write_csv(args.csv, changes, COMPARE_FIELDS)
    before_parts = {part.lower() for part in Path(args.before).parts}
    after_parts = {part.lower() for part in Path(args.after).parts}
    synthetic = "sample_data" in before_parts and "sample_data" in after_parts
    source_note = (
        "SYNTHETIC DEMONSTRATION DATA - NOT A LIVE EXPERIMENT | " if synthetic else ""
    )
    write_html(
        args.html,
        "NetMap Before/After Comparison",
        changes,
        COMPARE_FIELDS,
        f"{source_note}Before: {Path(args.before).name} | After: {Path(args.after).name} | Changes found: {len(changes)}",
    )
    counts = {
        name: sum(1 for row in changes if row["change"] == name)
        for name in (
            "newly_observed_open",
            "no_longer_observed",
            "not_assessed",
            "state_changed",
            "service_changed",
            "host_not_observed",
        )
    }
    print(f"Changes found: {len(changes)}")
    print(
        "Observed changes: "
        + "; ".join(f"{name}={count}" for name, count in counts.items())
    )
    print(f"CSV comparison: {args.csv}\nHTML comparison: {args.html}")
    if not changes:
        print("No differences in detected open endpoints and their service labels.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the deterministic end-to-end workflow over bundled synthetic XML only."""
    root = Path(__file__).resolve().parent
    before_path, after_path = (
        root / "sample_data" / "before.xml",
        root / "sample_data" / "after.xml",
    )
    output = Path(args.output)
    before, after = parse_scan(before_path), parse_scan(after_path)
    set_scan_provenance(before, "synthetic_demo", before_path.name)
    set_scan_provenance(after, "synthetic_demo", after_path.name)
    _reject_input_overwrite(
        [before_path, after_path],
        [
            output / name
            for name in (
                "baseline.json",
                "baseline.csv",
                "baseline-findings.csv",
                "baseline.html",
                "baseline.svg",
                "after.json",
                "after.csv",
                "after-findings.csv",
                "after.html",
                "after.svg",
                "comparison.csv",
                "comparison.html",
            )
        ],
    )
    for name, parsed in (("baseline", before), ("after", after)):
        write_json(output / f"{name}.json", parsed)
        write_csv(output / f"{name}.csv", parsed["rows"], REPORT_FIELDS)
        write_findings_csv(output / f"{name}-findings.csv", parsed)
        write_html(
            output / f"{name}.html",
            f"NetMap Synthetic {name.title()} Report",
            parsed["rows"],
            REPORT_FIELDS,
            "SYNTHETIC DEMONSTRATION DATA — NOT A LIVE SCAN",
            analyze_exposure(parsed),
            parsed["hosts"],
        )
        write_network_svg(output / f"{name}.svg", parsed)
    changes = compare_parsed_scans(before, after, "before.xml", "after.xml")
    write_csv(output / "comparison.csv", changes, COMPARE_FIELDS)
    write_html(
        output / "comparison.html",
        "NetMap Synthetic Comparison",
        changes,
        COMPARE_FIELDS,
        "SYNTHETIC DEMONSTRATION DATA — NOT A LIVE EXPERIMENT",
    )
    print(
        f"Synthetic demonstration complete. Generated baseline, after, comparison, findings, JSON and SVG reports in {output}."
    )
    print(
        f"Observed records: baseline hosts={len(before['hosts'])}, after hosts={len(after['hosts'])}, changes={len(changes)}."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NetMap lab tool: discover private lab hosts, scan, report and compare Nmap XML."
    )
    subs = parser.add_subparsers(dest="command", required=True)
    check = subs.add_parser("check", help="check that Nmap is installed")
    check.set_defaults(func=cmd_check)
    discovery = subs.add_parser(
        "discover", help="discover hosts in a small private host-only subnet"
    )
    discovery.add_argument("network", help="private CIDR, e.g. 192.168.56.0/24")
    discovery.add_argument(
        "--xml",
        default="scans/discovery.xml",
        help="XML output (default: scans/discovery.xml)",
    )
    discovery.add_argument(
        "--timeout", type=int, default=180, help="timeout seconds (1-600; default 180)"
    )
    discovery.add_argument(
        "--authorized-lab-target",
        action="store_true",
        help="acknowledge that you own or have explicit authorization to scan this private/loopback range",
    )
    discovery.set_defaults(func=cmd_discover)
    scan = subs.add_parser(
        "scan", help="scan a single private lab IP and save Nmap XML"
    )
    scan.add_argument(
        "target", help="single private lab IP, not a hostname or public address"
    )
    scan.add_argument(
        "--xml",
        default="scans/baseline.xml",
        help="XML output (default: scans/baseline.xml)",
    )
    scan.add_argument(
        "--ports", default="22,80,443,8080", help="ports such as 22,80,443 or 1-1000"
    )
    scan.add_argument(
        "--scan-type",
        choices=("syn", "connect"),
        default="connect",
        help="TCP connect is the portable default; SYN may need elevated privileges",
    )
    scan.add_argument(
        "--timeout", type=int, default=300, help="timeout seconds (1-600; default 300)"
    )
    scan.add_argument(
        "--authorized-lab-target",
        action="store_true",
        help="acknowledge that you own or have explicit authorization to scan this private/loopback IPv4 target",
    )
    scan.set_defaults(func=cmd_scan)
    report = subs.add_parser("report", help="export one Nmap XML file to CSV and HTML")
    report.add_argument("xml", help="input Nmap XML")
    report.add_argument("--csv", default="outputs/scan_report.csv")
    report.add_argument("--html", default="outputs/scan_report.html")
    report.add_argument(
        "--hosts-csv",
        default="outputs/host_inventory.csv",
        help="host inventory CSV; set to '' to disable",
    )
    report.add_argument(
        "--json",
        default="outputs/scan_report.json",
        help="schema-versioned JSON report",
    )
    report.add_argument(
        "--findings-csv",
        default="outputs/findings.csv",
        help="rule-based review findings CSV",
    )
    report.add_argument(
        "--svg",
        default="outputs/network_map.svg",
        help="observed host-to-service map SVG",
    )
    report.set_defaults(func=cmd_report)
    compare = subs.add_parser(
        "compare", help="compare open endpoints in two Nmap XML files"
    )
    compare.add_argument("before", help="baseline XML scan")
    compare.add_argument("after", help="later XML scan")
    compare.add_argument("--csv", default="outputs/comparison.csv")
    compare.add_argument("--html", default="outputs/comparison.html")
    compare.set_defaults(func=cmd_compare)
    demo = subs.add_parser(
        "demo", help="run the end-to-end demonstration using bundled synthetic XML only"
    )
    demo.add_argument(
        "--output",
        default="outputs/demo",
        help="output directory (default outputs/demo)",
    )
    demo.set_defaults(func=cmd_demo)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "report" and args.hosts_csv == "":
        args.hosts_csv = None
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"NetMap error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
