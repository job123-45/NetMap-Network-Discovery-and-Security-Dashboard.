import csv
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import netmap_store


class PersistentCliWorkflowTests(unittest.TestCase):
    def test_import_compare_triage_export_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="netmap-e2e-") as temp:
            root = Path(temp)
            data_dir = root / "data"
            env = {**os.environ, "NETMAP_DATA_DIR": str(data_dir)}

            def cli(*arguments):
                return subprocess.run(
                    [sys.executable, str(ROOT / "netmap.py"), *arguments],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True,
                )

            cli("db", "init")
            before = ROOT / "sample_data" / "before.xml"
            after = ROOT / "sample_data" / "after.xml"
            first_import = cli("db", "import", str(before))
            second_import = cli("db", "import", str(after))
            self.assertIn("Snapshot stored", first_import.stdout)
            self.assertIn("Snapshot stored", second_import.stdout)

            first_id = first_import.stdout.strip().split()[-1]
            duplicate = cli("db", "import", str(before))
            self.assertIn("already stored", duplicate.stdout)
            cli(
                "compare",
                str(before),
                str(after),
                "--csv",
                str(root / "comparison.csv"),
                "--html",
                str(root / "comparison.html"),
            )
            cli(
                "report",
                str(before),
                "--csv",
                str(root / "services.csv"),
                "--hosts-csv",
                str(root / "hosts.csv"),
                "--html",
                str(root / "report.html"),
                "--json",
                str(root / "report.json"),
                "--findings-csv",
                str(root / "findings.csv"),
                "--svg",
                str(root / "report.svg"),
            )

            demo_db = data_dir / "demo.sqlite3"
            operational_db = data_dir / "netmap.sqlite3"
            self.assertEqual(netmap_store.list_snapshots(operational_db), [])
            snapshots = netmap_store.list_snapshots(demo_db)
            self.assertEqual(len(snapshots), 2)
            self.assertEqual(len(netmap_store.list_assets(demo_db)), 1)
            self.assertEqual(len(netmap_store.list_comparisons(demo_db)), 1)

            with (root / "comparison.csv").open(newline="", encoding="utf-8") as handle:
                changes = list(csv.DictReader(handle))
            kinds = {item["change"] for item in changes}
            self.assertIn("newly_observed_open", kinds)
            self.assertIn("state_changed", kinds)
            self.assertIn("service_changed", kinds)
            self.assertTrue((root / "comparison.html").is_file())
            self.assertTrue((root / "findings.csv").is_file())
            with (root / "findings.csv").open(newline="", encoding="utf-8") as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 1)
            finding = netmap_store.list_findings(demo_db)[0]
            netmap_store.update_finding(
                finding["finding_id"],
                "in_progress",
                investigation_note="Synthetic end-to-end review",
                path=demo_db,
            )

            # A fresh CLI process and new SQLite connections represent an app restart.
            listed = cli("db", "list", "--synthetic")
            self.assertIn(first_id, listed.stdout)
            persisted = netmap_store.list_findings(demo_db)[0]
            self.assertEqual(persisted["status"], "in_progress")
            self.assertEqual(
                persisted["investigation_note"], "Synthetic end-to-end review"
            )
            self.assertEqual(
                netmap_store.finding_history(persisted["finding_id"], demo_db)[-1][
                    "to_status"
                ],
                "in_progress",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
