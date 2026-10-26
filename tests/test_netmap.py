import json
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import netmap
import netmap_store


class NetMapTests(unittest.TestCase):
    def setUp(self):
        self.before_path = ROOT / "sample_data" / "before.xml"
        self.after_path = ROOT / "sample_data" / "after.xml"
        self.before = netmap.parse_scan(self.before_path)
        self.after = netmap.parse_scan(self.after_path)

    def write_xml(self, folder, name, xml):
        path = Path(folder) / name
        path.write_text(xml, encoding="utf-8")
        return path

    def test_streaming_parser_normalizes_models_and_provenance(self):
        parsed = self.before
        self.assertTrue(netmap.is_bundled_synthetic(parsed))
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(parsed["hosts"][0]["ip_address"], "192.0.2.10")
        self.assertEqual(
            parsed["hosts"][0]["host_id"], self.after["hosts"][0]["host_id"]
        )
        self.assertTrue(
            all(row["service_id"] and row["scan_id"] for row in parsed["rows"])
        )
        self.assertEqual(parsed["coverage"]["tcp"], [22, 23, 80, 443])
        self.assertTrue(parsed["complete"])
        self.assertEqual(parsed["source_kind"], "imported_nmap_xml")
        self.assertEqual(
            next(row for row in parsed["rows"] if row["port"] == "23")[
                "service_identification"
            ],
            "confirmed",
        )

    def test_empty_malformed_non_nmap_duplicate_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            empty = self.write_xml(temp, "empty.xml", "<nmaprun></nmaprun>")
            self.assertEqual(netmap.parse_scan(empty)["rows"], [])
            malformed = self.write_xml(temp, "bad.xml", "<nmaprun>")
            with self.assertRaisesRegex(ValueError, "Cannot parse Nmap XML"):
                netmap.parse_scan(malformed)
            not_nmap = self.write_xml(temp, "other.xml", "<not-nmap/>")
            with self.assertRaisesRegex(ValueError, "not Nmap XML"):
                netmap.parse_scan(not_nmap)
            duplicate = self.write_xml(
                temp,
                "duplicate.xml",
                """<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><ports>
              <port protocol="TCP" portid="080"><state state="open"/></port><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
              <host><address addr="192.0.2.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>""",
            )
            parsed = netmap.parse_scan(duplicate)
            self.assertEqual(len(parsed["hosts"]), 1)
            self.assertEqual(len(parsed["rows"]), 1)
            self.assertEqual(parsed["rows"][0]["service"], "unknown")
            self.assertEqual(parsed["rows"][0]["service_identification"], "unknown")

    def test_entity_expansion_is_rejected_while_nmap_doctype_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            xml = '<!DOCTYPE nmaprun [<!ENTITY leak "expanded">]><nmaprun><host><hostnames><hostname name="&leak;"/></hostnames></host></nmaprun>'
            path = self.write_xml(temp, "entity.xml", xml)
            with self.assertRaisesRegex(ValueError, "Cannot parse Nmap XML"):
                netmap.parse_scan(path)

    def test_xml_size_limit_and_invalid_port_are_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            oversized = Path(temp) / "oversized.xml"
            with oversized.open("wb") as handle:
                handle.truncate(netmap.MAX_XML_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "input limit"):
                netmap.parse_scan(oversized)
            path = self.write_xml(
                temp,
                "bad-port.xml",
                '<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host></nmaprun>',
            )
            self.assertEqual(netmap.parse_scan(path)["rows"], [])

    def test_comparison_describes_observations_and_versions(self):
        changes = netmap.compare_parsed_scans(self.before, self.after)
        kinds = {change["change"] for change in changes}
        self.assertEqual(
            kinds,
            {
                "newly_observed_open",
                "state_changed",
                "service_changed",
                "finding_no_longer_matches",
            },
        )
        self.assertTrue(
            all(change["confidence"] and change["limitation"] for change in changes)
        )
        telnet = next(change for change in changes if change["port"] == "23")
        self.assertEqual(telnet["after_state"], "filtered")
        self.assertIn("filtering", telnet["limitation"])
        finding_change = next(
            change
            for change in changes
            if change["change"] == "finding_no_longer_matches"
        )
        self.assertEqual(finding_change["rule_id"], "NETMAP-CLEAR-TEXT-TELNET")
        self.assertIn("does not prove remediation", finding_change["limitation"])
        opened = next(change for change in changes if change["port"] == "8080")
        self.assertEqual(opened["confidence"], "low")
        self.assertIn("baseline", opened["limitation"])

    def test_missing_endpoint_never_means_closed_and_coverage_is_explicit(self):
        old = {
            "scan_time": "t1",
            "source": "a.xml",
            "hosts": [{"ip_address": "192.0.2.1"}],
            "rows": [
                {
                    "ip_address": "192.0.2.1",
                    "port": "443",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                }
            ],
        }
        new = {
            "scan_time": "t2",
            "source": "b.xml",
            "hosts": [{"ip_address": "192.0.2.1"}],
            "rows": [],
            "coverage": {"tcp": [443]},
            "complete": True,
        }
        changes = netmap.compare_parsed_scans(old, new)
        self.assertEqual(changes[0]["change"], "no_longer_observed")
        self.assertNotIn("closed", changes[0]["after_state"])
        new["coverage"] = {}
        self.assertEqual(
            netmap.compare_parsed_scans(old, new)[0]["change"], "not_assessed"
        )
        new["hosts"] = []
        changes = netmap.compare_parsed_scans(old, new)
        self.assertEqual(
            {change["change"] for change in changes},
            {"host_not_observed", "not_assessed"},
        )
        self.assertTrue(
            all(
                "offline" in change["limitation"]
                or "availability" in change["limitation"]
                for change in changes
            )
        )

    def test_rule_findings_are_explainable_and_do_not_claim_vulnerabilities(self):
        findings = netmap.analyze_exposure(self.before)
        self.assertEqual(
            [finding["rule_id"] for finding in findings], ["NETMAP-CLEAR-TEXT-TELNET"]
        )
        finding = findings[0]
        self.assertIn("tcp/23 open", finding["evidence"])
        self.assertIn("does not establish a vulnerability", finding["explanation"])
        self.assertTrue(finding["recommendation"])
        self.assertEqual(
            finding["classification"], "observed service; inferred review priority"
        )

    def test_graph_contains_only_observed_open_service_edges(self):
        graph = netmap.build_network_graph(self.before)
        self.assertEqual(
            sum(
                edge["source"] == self.before["hosts"][0]["host_id"]
                for edge in graph["edges"]
            ),
            3,
        )
        self.assertTrue(
            all("observed open" in edge["evidence"] for edge in graph["edges"])
        )
        self.assertNotIn(
            "443",
            [node["label"] for node in graph["nodes"] if node["kind"] == "service"],
        )
        dot = netmap.network_graph_dot(self.before)
        self.assertIn("digraph NetMap", dot)
        self.assertNotIn('-> "not-observed"', dot)

    def test_graph_caps_large_visual_and_reports_omissions(self):
        host = {
            "host_id": "host",
            "ip_address": "192.0.2.9",
            "hostname": "synthetic.test",
            "host_status": "up",
        }
        rows = [
            {
                "service_id": f"host:tcp:{port}",
                "ip_address": "192.0.2.9",
                "port": str(port),
                "protocol": "tcp",
                "state": "open",
                "service": "http",
            }
            for port in range(1, 252)
        ]
        graph = netmap.build_network_graph({"hosts": [host], "rows": rows})
        self.assertEqual(graph["omitted_service_count"], 1)
        self.assertEqual(len(graph["edges"]), netmap.MAX_GRAPH_NODES_PER_KIND)
        with tempfile.TemporaryDirectory() as temp:
            svg = Path(temp) / "large.svg"
            netmap.write_network_svg(svg, {"hosts": [host], "rows": rows})
            self.assertIn("Graph capped", svg.read_text(encoding="utf-8"))

    def test_exports_escape_html_svg_and_prevent_csv_formula_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            html_path, svg_path, csv_path, json_path = [
                Path(temp) / name
                for name in ("report.html", "map.svg", "findings.csv", "report.json")
            ]
            malicious = {
                "ip_address": "192.0.2.1",
                "port": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "<script>alert(1)</script>",
                "product": '=HYPERLINK("x")',
                "service_method": "probed",
            }
            parsed = {
                **self.before,
                "source": "private/path/scan.xml",
                "rows": [malicious],
                "hosts": [
                    {
                        "host_id": "abc",
                        "ip_address": "192.0.2.1",
                        "hostname": "<svg onload=alert(1)>",
                        "host_status": "up",
                    }
                ],
            }
            netmap.write_html(
                html_path,
                "<img src=x onerror=alert(1)>",
                [malicious],
                netmap.REPORT_FIELDS,
                "<unsafe>",
                netmap.analyze_exposure(parsed),
                parsed["hosts"],
            )
            netmap.write_network_svg(svg_path, parsed)
            netmap.write_findings_csv(csv_path, parsed)
            netmap.write_json(json_path, parsed)
            document = html_path.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", document)
            self.assertNotIn("<script>alert", document)
            svg = svg_path.read_text(encoding="utf-8")
            self.assertIn("&lt;svg onload=", svg)
            self.assertNotIn("<svg onload=", svg)
            self.assertTrue(csv_path.read_text(encoding="utf-8").startswith("rule_id,"))
            safe_csv = netmap.csv_bytes(
                [{"field": " \t=1+1"}, {"field": "+cmd"}, {"field": "normal"}],
                ["field"],
            ).decode()
            self.assertIn("' \t=1+1", safe_csv)
            self.assertIn("'+cmd", safe_csv)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "netmap.report.v1")
            self.assertEqual(report["scan"]["source"], "scan.xml")
            self.assertNotIn(str(ROOT), json_path.read_text(encoding="utf-8"))
            json_path_2 = Path(temp) / "report-again.json"
            netmap.write_json(json_path_2, parsed)
            self.assertEqual(json_path.read_bytes(), json_path_2.read_bytes())
            with self.assertRaisesRegex(ValueError, "cannot overwrite"):
                netmap._reject_input_overwrite([self.before_path], [self.before_path])

    def test_active_scans_require_ack_and_are_bounded_to_private_lab(self):
        with self.assertRaisesRegex(ValueError, "--authorized-lab-target"):
            netmap._require_authorization(Namespace())
        self.assertEqual(netmap._validate_private_ip("127.0.0.1"), "127.0.0.1")
        self.assertEqual(netmap._validate_private_ip("192.168.1.8"), "192.168.1.8")
        for target in ("example.com", "8.8.8.8", "2001:4860:4860::8888"):
            with self.assertRaises(ValueError):
                netmap._validate_private_ip(target)
        self.assertEqual(
            netmap._validate_private_network("192.168.56.0/24"), "192.168.56.0/24"
        )
        for network in ("192.168.0.0/16", "8.8.8.0/24", "2001:db8::/64"):
            with self.assertRaises(ValueError):
                netmap._validate_private_network(network)
        self.assertEqual(netmap._validate_ports("22,80,443"), "22,80,443")
        with self.assertRaises(ValueError):
            netmap._validate_ports("1-2049")
        with self.assertRaises(ValueError):
            netmap._validate_timeout(601)

    def test_cli_scan_uses_mocked_array_subprocess_and_never_starts_network(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scan.xml"
            args = Namespace(
                authorized_lab_target=True,
                timeout=30,
                target="127.0.0.1",
                ports="22,80",
                xml=str(output),
                scan_type="connect",
            )

            def fake_run(command, **kwargs):
                self.assertIsInstance(command, list)
                self.assertEqual(command[0], "nmap-test-double")
                self.assertEqual(command[command.index("--max-rate") + 1], "100")
                self.assertEqual(kwargs["timeout"], 30)
                self.assertTrue(kwargs["capture_output"])
                output.write_bytes(self.before_path.read_bytes())
                return SimpleNamespace(returncode=0)

            with (
                patch.dict(
                    os.environ,
                    {"NETMAP_DATA_DIR": str(Path(output).parent / "netmap-data")},
                ),
                patch.object(netmap.shutil, "which", return_value="nmap-test-double"),
                patch.object(netmap.subprocess, "run", side_effect=fake_run) as run,
            ):
                self.assertEqual(netmap.cmd_scan(args), 0)
                self.assertEqual(run.call_count, 1)

    def test_demo_runs_end_to_end_from_bundled_synthetic_data(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "demo"
            result = subprocess.run(
                [sys.executable, str(ROOT / "netmap.py"), "demo", "--output", str(out)],
                cwd=ROOT,
                env={**os.environ, "NETMAP_DATA_DIR": str(Path(temp) / "netmap-data")},
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("Synthetic demonstration complete", result.stdout)
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
            ):
                self.assertTrue((out / name).is_file(), name)
            self.assertIn(
                "SYNTHETIC DEMONSTRATION DATA",
                (out / "baseline.html").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                json.loads((out / "baseline.json").read_text(encoding="utf-8"))["scan"][
                    "source_kind"
                ],
                "synthetic_demo",
            )

    def test_cli_comparison_is_persisted_and_keeps_fixtures_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            args = Namespace(
                before=str(self.before_path),
                after=str(self.after_path),
                csv=str(output / "changes.csv"),
                html=str(output / "changes.html"),
            )
            with patch.dict(os.environ, {"NETMAP_DATA_DIR": str(output / "data")}):
                self.assertEqual(netmap.cmd_compare(args), 0)
                self.assertEqual(netmap_store.list_snapshots(), [])
                self.assertEqual(
                    len(
                        netmap_store.list_comparisons(
                            netmap_store.database_path(synthetic=True)
                        )
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
