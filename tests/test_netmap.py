import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import netmap


class NetMapTests(unittest.TestCase):
    def setUp(self):
        self.before = ROOT / "sample_data" / "before.xml"
        self.after = ROOT / "sample_data" / "after.xml"

    def test_parse_scan(self):
        parsed = netmap.parse_scan(self.before)
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(parsed["hosts"][0]["ip_address"], "192.168.56.101")
        self.assertEqual(len(parsed["rows"]), 3)
        self.assertEqual(parsed["rows"][0]["service"], "ssh")

    def test_compare(self):
        changes = netmap.compare_scans(self.before, self.after)
        kinds = {row["change"] for row in changes}
        self.assertIn("opened", kinds)
        self.assertIn("no_longer_open", kinds)
        self.assertIn("service_changed", kinds)
        self.assertEqual(len(changes), 3)
        self.assertTrue(all(row["baseline_timestamp"] and row["after_timestamp"] for row in changes))

    def test_parser_keeps_all_addresses_and_service_detection_metadata(self):
        xml = '''<nmaprun startstr="today"><host><status state="up" reason="syn-ack"/>
          <address addr="192.0.2.8" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/>
          <ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
          <service name="https" product="Example" version="1" method="probed" conf="10"/></port></ports>
          </host></nmaprun>'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "multi.xml"
            path.write_text(xml, encoding="utf-8")
            parsed = netmap.parse_scan(path)
        self.assertIn("192.0.2.8 (ipv4)", parsed["rows"][0]["addresses"])
        self.assertIn("00:11:22:33:44:55 (mac)", parsed["hosts"][0]["addresses"])
        self.assertEqual(parsed["rows"][0]["service_method"], "probed")
        self.assertEqual(parsed["rows"][0]["service_confidence"], "10")

    def test_empty_scan_is_valid_and_invalid_xml_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.xml"
            empty.write_text("<nmaprun></nmaprun>", encoding="utf-8")
            parsed = netmap.parse_scan(empty)
            self.assertEqual(parsed["rows"], [])
            self.assertEqual(parsed["hosts"], [])
            invalid = Path(tmp) / "invalid.xml"
            invalid.write_text("<nmaprun>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Cannot read Nmap XML"):
                netmap.parse_scan(invalid)
            other = Path(tmp) / "other.xml"
            other.write_text("<not-nmap/>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "is not Nmap XML"):
                netmap.parse_scan(other)

    def test_html_escapes_untrusted_values_and_labels_empty_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.html"
            netmap.write_html(report, "<unsafe>", [{"service": "<script>alert(1)</script>"}], ["service"])
            document = report.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", document)
            self.assertNotIn("<script>alert(1)</script>", document)
            comparison = Path(tmp) / "comparison.html"
            netmap.write_html(comparison, "Comparison", [], netmap.COMPARE_FIELDS)
            self.assertIn("No differences detected between these scans.", comparison.read_text(encoding="utf-8"))

    def test_comparison_uses_host_port_and_protocol(self):
        before = {"source": "before.xml", "scan_time": "t1", "rows": [
            {"ip_address": "192.0.2.1", "port": "53", "protocol": "tcp", "state": "open", "service": "dns"}
        ]}
        after = {"source": "after.xml", "scan_time": "t2", "rows": [
            {"ip_address": "192.0.2.1", "port": "53", "protocol": "udp", "state": "open", "service": "dns"},
            {"ip_address": "192.0.2.2", "port": "53", "protocol": "tcp", "state": "open", "service": "dns"},
        ]}
        changes = netmap.compare_parsed_scans(before, after)
        self.assertEqual(len(changes), 3)
        self.assertEqual({(row["change"], row["ip_address"], row["protocol"]) for row in changes}, {
            ("no_longer_open", "192.0.2.1", "tcp"),
            ("opened", "192.0.2.1", "udp"),
            ("opened", "192.0.2.2", "tcp"),
        })

    def test_private_target_validation(self):
        self.assertEqual(netmap._validate_private_ip("192.168.56.101"), "192.168.56.101")
        with self.assertRaises(ValueError):
            netmap._validate_private_ip("example.com")
        with self.assertRaises(ValueError):
            netmap._validate_private_ip("8.8.8.8")

    def test_private_network_validation(self):
        self.assertEqual(netmap._validate_private_network("192.168.56.0/24"), "192.168.56.0/24")
        with self.assertRaises(ValueError):
            netmap._validate_private_network("8.8.8.0/24")
        with self.assertRaises(ValueError):
            netmap._validate_private_network("192.168.0.0/16")

    def test_port_validation(self):
        self.assertEqual(netmap._validate_ports("22,80,443"), "22,80,443")
        with self.assertRaises(ValueError):
            netmap._validate_ports("0,70000")

    def test_report_from_fixture_is_explicitly_labelled_synthetic(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "report.csv"
            html_path = Path(tmp) / "report.html"
            hosts_path = Path(tmp) / "hosts.csv"
            subprocess.run(
                [sys.executable, str(ROOT / "netmap.py"), "report", str(self.before),
                 "--csv", str(csv_path), "--html", str(html_path), "--hosts-csv", str(hosts_path)],
                cwd=ROOT, check=True, capture_output=True, text=True,
            )
            self.assertIn("SYNTHETIC DEMONSTRATION DATA - NOT A LIVE SCAN", html_path.read_text(encoding="utf-8"))
            self.assertTrue(csv_path.exists())
            self.assertTrue(hosts_path.exists())

    def test_comparison_of_fixtures_is_explicitly_labelled_synthetic(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "changes.csv"
            html_path = Path(tmp) / "changes.html"
            subprocess.run(
                [sys.executable, str(ROOT / "netmap.py"), "compare", str(self.before), str(self.after),
                 "--csv", str(csv_path), "--html", str(html_path)],
                cwd=ROOT, check=True, capture_output=True, text=True,
            )
            self.assertIn("SYNTHETIC DEMONSTRATION DATA - NOT A LIVE EXPERIMENT", html_path.read_text(encoding="utf-8"))
            self.assertIn("Baseline Timestamp", html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
