import sys
import unittest
from pathlib import Path

from streamlit import dataframe_util
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import netmap


def control(app, collection, label):
    return next(item for item in getattr(app, collection) if item.label == label)


def assert_real_overview(test, app, filename):
    metrics = {metric.label: metric.value for metric in app.metric}
    test.assertEqual(metrics["Discovered hosts"], "1")
    test.assertEqual(metrics["Open ports"], "4")
    test.assertEqual(metrics["Services detected"], "4")
    test.assertEqual(metrics["Port records"], "4")
    test.assertTrue(any("REAL NMAP XML SCAN" in item.value and filename in item.value for item in app.markdown))
    parsed = netmap.parse_scan(ROOT / "scans" / filename)
    test.assertTrue(any(filename in item.value and parsed["scan_time"] in item.value for item in app.caption))
    chart = dataframe_util.convert_arrow_bytes_to_pandas_df(app.get("vega_lite_chart")[0].proto.datasets[0].data.data)
    test.assertEqual(dict(zip(chart["Port state"], chart["Records"])), {"open": 4})
    ports = next(frame.value for frame in app.dataframe if "port" in frame.value.columns)
    test.assertEqual(set(ports["port"]), {"135", "139", "445", "8080"})
    test.assertEqual(set(ports["scan_time"]), {parsed["scan_time"]})
    test.assertFalse(any("synthetic" in item.value.lower() or "demo" in item.value.lower() for item in app.markdown))


class DashboardInputTests(unittest.TestCase):
    def start(self):
        return AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30).run()

    def load_saved(self, app, filename="live_scan.xml"):
        control(app, "selectbox", "Saved Nmap XML scan").set_value(filename).run()
        control(app, "button", "Load Scan").click().run()
        self.assertFalse(app.exception)

    def test_fresh_session_requires_scan_and_saved_xml_loads(self):
        app = self.start()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.metric), 0)
        self.assertEqual(len(app.dataframe), 0)
        self.assertEqual(len(app.get("vega_lite_chart")), 0)
        self.assertTrue(any("Network Discovery Dashboard" in item.value for item in app.markdown))
        options = control(app, "selectbox", "Saved Nmap XML scan").options
        self.assertIn("live_scan.xml", options)
        self.assertIn("live_scan_after.xml", options)
        self.assertFalse(any("synthetic" in item.value.lower() or "demo" in item.value.lower() for item in app.markdown))

        self.load_saved(app)
        assert_real_overview(self, app, "live_scan.xml")
        self.assertEqual(len(app.download_button), 3)

    def test_upload_real_xml_and_changing_scan_replaces_overview_source(self):
        app = self.start()
        control(app, "radio", "Scan input").set_value("Upload a scan").run()
        xml_path = ROOT / "scans" / "live_scan.xml"
        control(app, "file_uploader", "Upload an Nmap XML file").set_value(
            (xml_path.name, xml_path.read_bytes(), "application/xml")
        ).run()
        control(app, "button", "Load Scan").click().run()
        self.assertFalse(app.exception)
        assert_real_overview(self, app, "live_scan.xml")
        original_export_urls = [button.proto.url for button in app.download_button]

        control(app, "button", "Change scan").click().run()
        self.assertEqual(len(app.metric), 0)
        self.load_saved(app, "live_scan_after.xml")
        assert_real_overview(self, app, "live_scan_after.xml")
        changed_export_urls = [button.proto.url for button in app.download_button]
        self.assertEqual(len(original_export_urls), 3)
        self.assertTrue(all(old_url != new_url for old_url, new_url in zip(original_export_urls, changed_export_urls)))

    def test_invalid_upload_shows_error_and_valid_empty_scan_has_empty_states(self):
        app = self.start()
        control(app, "radio", "Scan input").set_value("Upload a scan").run()
        uploader = control(app, "file_uploader", "Upload an Nmap XML file")
        uploader.set_value(("invalid.xml", b"<not-nmap", "application/xml")).run()
        control(app, "button", "Load Scan").click().run()
        self.assertTrue(app.error)
        self.assertEqual(len(app.metric), 0)
        self.assertEqual(len(app.dataframe), 0)

        control(app, "file_uploader", "Upload an Nmap XML file").set_value(
            ("empty-valid.xml", b'<nmaprun startstr="empty scan"></nmaprun>', "application/xml")
        ).run()
        control(app, "button", "Load Scan").click().run()
        self.assertFalse(app.exception)
        self.assertEqual({metric.label: metric.value for metric in app.metric}["Open ports"], "0")
        self.assertEqual({metric.label: metric.value for metric in app.metric}["Port records"], "0")
        self.assertTrue(any("no host records" in item.value.lower() for item in app.info))
        self.assertTrue(any("No port records" in item.value for item in app.info))

    def test_comparison_requires_two_valid_real_xml_uploads_and_exports(self):
        app = self.start()
        self.load_saved(app)
        control(app, "radio", "Workspace").set_value("Comparison").run()
        control(app, "radio", "Comparison inputs").set_value("Upload two scans").run()
        baseline = ROOT / "scans" / "live_scan.xml"
        after = ROOT / "scans" / "live_scan_after.xml"
        control(app, "file_uploader", "Baseline scan (original scan)").set_value(
            (baseline.name, baseline.read_bytes(), "application/xml")
        ).run()
        self.assertTrue(any("Two valid Nmap XML files are required" in item.value for item in app.info))
        self.assertEqual(len(app.metric), 0)

        control(app, "file_uploader", "After scan (later scan)").set_value(
            (after.name, after.read_bytes(), "application/xml")
        ).run()
        control(app, "button", "Compare uploaded scans").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("No differences were detected" in item.value for item in app.success))
        self.assertEqual(len(app.download_button), 2)
        self.assertTrue(any(baseline.name in item.value and after.name in item.value for item in app.caption))


if __name__ == "__main__":
    unittest.main(verbosity=2)
