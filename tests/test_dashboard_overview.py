import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class DashboardSmokeTests(unittest.TestCase):
    def test_dashboard_starts_without_saved_scan_artifacts(self):
        dashboard = Path(__file__).resolve().parents[1] / "dashboard.py"
        app = AppTest.from_file(str(dashboard)).run()
        self.assertFalse(app.exception)


if __name__ == "__main__":
    unittest.main()
