import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import netmap_store


def control(app, collection, label):
    return next(item for item in getattr(app, collection) if item.label == label)


class DashboardInputTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.TemporaryDirectory(prefix="netmap-dashboard-test-")
        self.env = patch.dict(os.environ, {"NETMAP_DATA_DIR": self.data_dir.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.data_dir.cleanup()

    def start(self):
        return AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=60).run()

    def load_synthetic(self, app):
        control(app, "button", "Load synthetic demonstration").click().run()
        self.assertFalse(app.exception)

    def test_new_session_is_empty_and_explicit_synthetic_demo_is_labeled(self):
        app = self.start()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.metric), 0)
        self.assertEqual(len(app.dataframe), 0)
        self.assertTrue(
            any("Network Discovery Dashboard" in item.value for item in app.markdown)
        )
        self.assertTrue(
            any("synthetic" in item.label.casefold() for item in app.button)
        )
        self.load_synthetic(app)
        self.assertEqual(app.session_state["active_scan"]["kind"], "synthetic_demo")
        self.assertTrue(
            any("SYNTHETIC DEMONSTRATION DATA" in item.value for item in app.markdown)
        )
        self.assertTrue(
            any(
                "NETMAP-CLEAR-TEXT-TELNET" in str(frame.value)
                for frame in app.dataframe
            )
        )
        self.assertGreaterEqual(len(app.download_button), 6)

    def test_searchable_inventory_view_uses_current_fixture_data(self):
        app = self.start()
        self.load_synthetic(app)
        control(app, "radio", "Workspace").set_value("Ports & Services").run()
        self.assertFalse(app.exception)
        search = control(app, "text_input", "Search address, port, service or product")
        search.set_value("telnet").run()
        self.assertTrue(
            any("telnet" in frame.value.to_string().lower() for frame in app.dataframe)
        )

    def test_local_inventory_assets_and_triage_pages(self):
        app = self.start()
        control(app, "radio", "Workspace").set_value("Data Management").run()
        self.assertFalse(app.exception)
        self.load_synthetic(app)
        control(app, "radio", "Workspace").set_value("Assets").run()
        self.assertFalse(app.exception)
        self.assertTrue(app.dataframe)
        control(app, "radio", "Workspace").set_value("Finding Triage").run()
        self.assertFalse(app.exception)
        self.assertTrue(any(item.label == "Save triage" for item in app.button))

    def test_comparison_uploads_are_separate_and_use_coverage_aware_changes(self):
        app = self.start()
        self.load_synthetic(app)
        control(app, "radio", "Workspace").set_value("Comparison").run()
        control(app, "radio", "Comparison inputs").set_value("Upload two scans").run()
        baseline, after = (
            ROOT / "sample_data" / "before.xml",
            ROOT / "sample_data" / "after.xml",
        )
        control(app, "file_uploader", "Baseline scan (original scan)").set_value(
            (baseline.name, baseline.read_bytes(), "application/xml")
        ).run()
        control(app, "file_uploader", "After scan (later scan)").set_value(
            (after.name, after.read_bytes(), "application/xml")
        ).run()
        control(app, "button", "Compare uploaded scans").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(
            any("Newly observed open endpoints" in item.value for item in app.markdown)
        )
        self.assertTrue(
            any(
                "low" in frame.value.to_string().lower()
                and "baseline" in frame.value.to_string().lower()
                for frame in app.dataframe
            )
        )
        self.assertEqual(len(app.download_button), 2)
        self.assertEqual(netmap_store.list_snapshots(netmap_store.database_path()), [])
        self.assertGreaterEqual(
            len(
                netmap_store.list_snapshots(netmap_store.database_path(synthetic=True))
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
