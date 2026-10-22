#!/usr/bin/env python3
"""NetMap - lab-only network discovery, Nmap XML reporting and scan comparison.

Use only on systems you own or have explicit permission to test. By design, active
commands accept private IP addresses/ranges rather than DNS hostnames/public targets.
Dependencies: Python 3.10+ standard library. Nmap is required for discover/scan.
"""
from __future__ import annotations
import argparse
import csv
import html
import ipaddress
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_FIELDS = ["scan_time", "ip_address", "addresses", "host_status", "port", "protocol", "state", "service", "product", "version", "service_method", "service_confidence", "reason"]
COMPARE_FIELDS = ["change", "ip_address", "port", "protocol", "before_service", "after_service", "before_state", "after_state", "baseline_scan", "baseline_timestamp", "after_scan", "after_timestamp"]
HOST_FIELDS = ["scan_time", "ip_address", "address_type", "addresses", "host_status", "reason", "hostname"]


def _scan_time(root: ET.Element) -> str:
    readable = root.get("startstr")
    if readable:
        return readable
    raw = root.get("start")
    if raw:
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc).astimezone().isoformat(timespec="seconds")
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
        selected = next((a for a in addresses if a.get("addrtype") == wanted and a.get("addr")), None)
        if selected is not None:
            break
    ip = selected.get("addr", "unknown") if selected is not None else "unknown"
    addr_type = selected.get("addrtype", "unknown") if selected is not None else "unknown"
    all_addresses = "; ".join(f"{address} ({kind})" for address, kind in present_addresses)
    status_node = host.find("status")
    status = status_node.get("state", "unknown") if status_node is not None else "unknown"
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
    """Parse Nmap XML into a timestamp, hosts, and normalized port rows."""
    file_path = Path(path)
    try:
        root = ET.parse(file_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Cannot read Nmap XML file '{file_path}': {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"'{file_path}' is not Nmap XML (expected <nmaprun>).")
    scan_time = _scan_time(root)
    rows: list[dict[str, str]] = []
    hosts: list[dict[str, str]] = []
    for host in root.findall("host"):
        ip, addr_type, addresses, status, reason, hostname = _host_details(host)
        hosts.append({"scan_time": scan_time, "ip_address": ip, "address_type": addr_type,
                      "addresses": addresses,
                      "host_status": status, "reason": reason, "hostname": hostname})
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port_node in ports_node.findall("port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            reason_port = state_node.get("reason", "") if state_node is not None else ""
            service, product, version, service_method, service_confidence = _service_details(port_node)
            rows.append({"scan_time": scan_time, "ip_address": ip, "addresses": addresses, "host_status": status,
                         "port": port_node.get("portid", "unknown"),
                         "protocol": port_node.get("protocol", "unknown"), "state": state,
                         "service": service, "product": product, "version": version,
                         "service_method": service_method, "service_confidence": service_confidence,
                         "reason": reason_port})
    return {"scan_time": scan_time, "rows": rows, "hosts": hosts, "source": str(file_path)}


def write_csv(path: str | Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_html(path: str | Path, title: str, rows: list[dict[str, str]], fields: list[str], subtitle: str = "") -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    header_cells = "".join(f"<th>{html.escape(field.replace('_', ' ').title())}</th>" for field in fields)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(str(row.get(field, '')))}</td>" for field in fields)
        state = str(row.get("state", row.get("change", ""))).lower().replace(" ", "-")
        body_rows.append(f'<tr class="{html.escape(state, quote=True)}">{cells}</tr>')
    if body_rows:
        body = "\n".join(body_rows)
    else:
        empty_message = "No differences detected between these scans." if "change" in fields else "No rows found in this file."
        body = f'<tr><td colspan="{len(fields)}">{empty_message}</td></tr>'
    safe_title, safe_subtitle = html.escape(title), html.escape(subtitle)
    document = f'''<!doctype html>
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
<table><thead><tr>{header_cells}</tr></thead><tbody>{body}</tbody></table>
<footer>Generated by NetMap. Interpret results in the context of scan options, host state and filtering.</footer></body></html>'''
    destination.write_text(document, encoding="utf-8")


def _open_service_map(parsed: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, str]]:
    mapped = {}
    for row in parsed["rows"]:
        if row["state"].lower() == "open":
            mapped[(row["ip_address"], row["port"], row["protocol"])] = row
    return mapped


def _service_label(row: dict[str, str]) -> str:
    parts = [row.get("service", "unknown"), row.get("product", ""), row.get("version", "")]
    return " ".join(part for part in parts if part).strip() or "unknown"


def compare_parsed_scans(
    before: dict[str, Any],
    after: dict[str, Any],
    before_name: str | None = None,
    after_name: str | None = None,
) -> list[dict[str, str]]:
    """Compare parsed open endpoints and retain each scan's identifying metadata."""
    old_map, new_map = _open_service_map(before), _open_service_map(after)
    before_name = before_name or Path(before.get("source", "baseline.xml")).name
    after_name = after_name or Path(after.get("source", "after.xml")).name
    metadata = {
        "baseline_scan": before_name,
        "baseline_timestamp": before["scan_time"],
        "after_scan": after_name,
        "after_timestamp": after["scan_time"],
    }
    changes: list[dict[str, str]] = []
    for key in sorted(new_map.keys() - old_map.keys()):
        row = new_map[key]
        changes.append({"change": "opened", "ip_address": key[0], "port": key[1], "protocol": key[2], **metadata,
                        "before_service": "", "after_service": _service_label(row),
                        "before_state": "not open", "after_state": "open"})
    for key in sorted(old_map.keys() - new_map.keys()):
        row = old_map[key]
        changes.append({"change": "no_longer_open", "ip_address": key[0], "port": key[1], "protocol": key[2], **metadata,
                        "before_service": _service_label(row), "after_service": "",
                        "before_state": "open", "after_state": "not open"})
    for key in sorted(old_map.keys() & new_map.keys()):
        old, new = old_map[key], new_map[key]
        if _service_label(old) != _service_label(new):
            changes.append({"change": "service_changed", "ip_address": key[0], "port": key[1], "protocol": key[2], **metadata,
                            "before_service": _service_label(old), "after_service": _service_label(new),
                            "before_state": "open", "after_state": "open"})
    return changes


def compare_scans(before_path: str | Path, after_path: str | Path) -> list[dict[str, str]]:
    """Compare open endpoints. 'no_longer_open' is deliberately not called 'closed'."""
    before, after = parse_scan(before_path), parse_scan(after_path)
    return compare_parsed_scans(before, after, Path(before_path).name, Path(after_path).name)


def _require_nmap() -> str:
    exe = shutil.which("nmap")
    if not exe:
        raise ValueError("Nmap was not found. Install Nmap, then verify with: nmap --version")
    return exe


def _validate_private_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Target must be a single private IP address (not a hostname or public IP).") from exc
    if not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise ValueError("For this lab tool, target must be a private lab IP address (for example 192.168.56.101).")
    return str(addr)


def _validate_private_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("Network must be a CIDR range such as 192.168.56.0/24.") from exc
    if not network.is_private or network.is_multicast or network.is_loopback or network.num_addresses > 4096:
        raise ValueError("Use a private, isolated lab subnet with no more than 4096 addresses (a /24 host-only subnet is typical).")
    return str(network)


def _validate_ports(value: str) -> str:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("Ports must look like 22,80,443 or 1-1000 (no spaces).")
    for chunk in value.split(","):
        parts = [int(part) for part in chunk.split("-")]
        if any(p < 1 or p > 65535 for p in parts) or len(parts) == 2 and parts[0] > parts[1]:
            raise ValueError(f"Invalid port range: {chunk}")
    return value


def _run_nmap(command: list[str], timeout: int) -> int:
    print("Running:", " ".join(command))
    try:
        result = subprocess.run(command, check=False, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        raise ValueError(f"Nmap timed out after {timeout} seconds. Try fewer ports or increase --timeout.")
    if result.returncode != 0:
        raise ValueError(f"Nmap exited with status {result.returncode}. Check permissions, target address, and installation.")
    return result.returncode


def cmd_check(args: argparse.Namespace) -> int:
    exe = _require_nmap()
    result = subprocess.run([exe, "--version"], check=False, capture_output=True, text=True)
    print(result.stdout.splitlines()[0] if result.stdout else "Nmap is installed.")
    print("Python:", sys.version.split()[0])
    print("Nmap path:", exe)
    return 0 if result.returncode == 0 else 1


def cmd_discover(args: argparse.Namespace) -> int:
    network = _validate_private_network(args.network)
    exe = _require_nmap()
    dest = Path(args.xml)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-sn", "-oX", str(dest), network]
    _run_nmap(cmd, args.timeout)
    if not dest.exists():
        raise ValueError("Nmap finished but the requested XML file was not created.")
    data = parse_scan(dest)
    up = sum(1 for h in data["hosts"] if h["host_status"] == "up")
    print(f"Discovery complete: {up} up host(s) recorded in {dest}")
    print("Next: review the host-only subnet in Wireshark and scan only your known target IP.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    target = _validate_private_ip(args.target)
    ports = _validate_ports(args.ports)
    exe = _require_nmap()
    dest = Path(args.xml)
    dest.parent.mkdir(parents=True, exist_ok=True)
    scan_switch = "-sS" if args.scan_type == "syn" else "-sT"
    cmd = [exe, scan_switch, "-sV", "--reason", "-p", ports, "-oX", str(dest), target]
    _run_nmap(cmd, args.timeout)
    if not dest.exists():
        raise ValueError("Nmap finished but the requested XML file was not created.")
    parsed = parse_scan(dest)
    open_rows = [r for r in parsed["rows"] if r["state"] == "open"]
    print(f"Scan complete: {len(parsed['rows'])} port record(s), {len(open_rows)} open port(s). XML: {dest}")
    print(f"Next: py netmap.py report {dest} --csv outputs/scan.csv --html outputs/scan.html")
    if args.scan_type == "syn":
        print("Note: SYN scans usually need elevated privileges. On Windows, run an approved elevated terminal if required; TCP connect is more portable.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    parsed = parse_scan(args.xml)
    write_csv(args.csv, parsed["rows"], REPORT_FIELDS)
    synthetic = any(part.lower() == "sample_data" for part in Path(args.xml).parts)
    source_note = "SYNTHETIC DEMONSTRATION DATA - NOT A LIVE SCAN" if synthetic else "Source: saved Nmap XML"
    write_html(args.html, "NetMap Scan Report", parsed["rows"], REPORT_FIELDS,
               f"{source_note} | Source file: {args.xml} | Scan time: {parsed['scan_time']} | Hosts recorded: {len(parsed['hosts'])} | Port records: {len(parsed['rows'])}")
    if args.hosts_csv:
        write_csv(args.hosts_csv, parsed["hosts"], HOST_FIELDS)
    open_count = sum(1 for r in parsed["rows"] if r["state"] == "open")
    print(f"Scan time: {parsed['scan_time']}")
    print(f"Hosts recorded: {len(parsed['hosts'])}; port records: {len(parsed['rows'])}; open ports: {open_count}")
    print(f"CSV report: {args.csv}\nHTML report: {args.html}")
    if args.hosts_csv:
        print(f"Host inventory CSV: {args.hosts_csv}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    changes = compare_scans(args.before, args.after)
    write_csv(args.csv, changes, COMPARE_FIELDS)
    before_parts = {part.lower() for part in Path(args.before).parts}
    after_parts = {part.lower() for part in Path(args.after).parts}
    synthetic = "sample_data" in before_parts and "sample_data" in after_parts
    source_note = "SYNTHETIC DEMONSTRATION DATA - NOT A LIVE EXPERIMENT | " if synthetic else ""
    write_html(args.html, "NetMap Before/After Comparison", changes, COMPARE_FIELDS,
               f"{source_note}Before: {args.before} | After: {args.after} | Changes found: {len(changes)}")
    counts = {name: sum(1 for row in changes if row["change"] == name)
              for name in ("opened", "no_longer_open", "service_changed")}
    print(f"Changes found: {len(changes)}")
    print(f"Newly open: {counts['opened']}; no longer open: {counts['no_longer_open']}; service changed: {counts['service_changed']}")
    print(f"CSV comparison: {args.csv}\nHTML comparison: {args.html}")
    if not changes:
        print("No differences in detected open endpoints and their service labels.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetMap lab tool: discover private lab hosts, scan, report and compare Nmap XML.")
    subs = parser.add_subparsers(dest="command", required=True)
    check = subs.add_parser("check", help="check that Nmap is installed")
    check.set_defaults(func=cmd_check)
    discovery = subs.add_parser("discover", help="discover hosts in a small private host-only subnet")
    discovery.add_argument("network", help="private CIDR, e.g. 192.168.56.0/24")
    discovery.add_argument("--xml", default="scans/discovery.xml", help="XML output (default: scans/discovery.xml)")
    discovery.add_argument("--timeout", type=int, default=180, help="timeout seconds (default 180)")
    discovery.set_defaults(func=cmd_discover)
    scan = subs.add_parser("scan", help="scan a single private lab IP and save Nmap XML")
    scan.add_argument("target", help="single private lab IP, not a hostname or public address")
    scan.add_argument("--xml", default="scans/baseline.xml", help="XML output (default: scans/baseline.xml)")
    scan.add_argument("--ports", default="22,80,443,8080", help="ports such as 22,80,443 or 1-1000")
    scan.add_argument("--scan-type", choices=("syn", "connect"), default="syn", help="SYN needs elevated privileges; connect is more portable")
    scan.add_argument("--timeout", type=int, default=300, help="timeout seconds (default 300)")
    scan.set_defaults(func=cmd_scan)
    report = subs.add_parser("report", help="export one Nmap XML file to CSV and HTML")
    report.add_argument("xml", help="input Nmap XML")
    report.add_argument("--csv", default="outputs/scan_report.csv")
    report.add_argument("--html", default="outputs/scan_report.html")
    report.add_argument("--hosts-csv", default="outputs/host_inventory.csv", help="host inventory CSV; set to '' to disable")
    report.set_defaults(func=cmd_report)
    compare = subs.add_parser("compare", help="compare open endpoints in two Nmap XML files")
    compare.add_argument("before", help="baseline XML scan")
    compare.add_argument("after", help="later XML scan")
    compare.add_argument("--csv", default="outputs/comparison.csv")
    compare.add_argument("--html", default="outputs/comparison.html")
    compare.set_defaults(func=cmd_compare)
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
