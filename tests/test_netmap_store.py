import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netmap_store


def sample_snapshot(digest="a" * 64):
    host = {
        "host_id": "host-1",
        "ip_address": "192.0.2.10",
        "hostname": "example.test",
        "host_status": "up",
        "scan_time": "2025-01-01T00:00:00Z",
    }
    service = {
        "service_id": "host-1:tcp:23",
        "host_id": "host-1",
        "ip_address": "192.0.2.10",
        "port": 23,
        "protocol": "tcp",
        "state": "open",
        "service": "telnet",
    }
    return {
        "scan_id": "scan-1",
        "scan_time": "2025-01-01T00:00:00Z",
        "source": "fixture.xml",
        "source_kind": "imported_nmap_xml",
        "scanner": "nmap",
        "complete": True,
        "coverage_known": True,
        "coverage": {"tcp": [23]},
        "hosts": [host],
        "rows": [service],
        "content_sha256": digest,
    }


def sample_finding():
    return {
        "rule_id": "NETMAP-TEST",
        "asset_id": "asset-1",
        "host_id": "host-1",
        "address": "192.0.2.10",
        "port": 23,
        "protocol": "tcp",
        "severity": "high",
        "title": "Review service",
        "description": "Synthetic test finding",
        "evidence": "Synthetic fixture",
        "explanation": "Test only",
        "limitation": "No exploitability claim",
        "recommendation": "Review",
        "timestamp": "2025-01-01T00:00:00Z",
        "source": "test",
        "classification": "review_signal",
    }


class NetMapStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "netmap.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_schema_import_dedup_and_persistence(self):
        netmap_store.initialize(self.db)
        snapshot_id, duplicate = netmap_store.store_snapshot(
            sample_snapshot(), [sample_finding()], path=self.db
        )
        again, was_duplicate = netmap_store.store_snapshot(
            sample_snapshot(), [sample_finding()], path=self.db
        )
        self.assertFalse(duplicate)
        self.assertTrue(was_duplicate)
        self.assertEqual(snapshot_id, again)
        self.assertEqual(len(netmap_store.list_snapshots(self.db)), 1)
        self.assertEqual(len(netmap_store.list_assets(self.db)), 1)
        self.assertEqual(
            netmap_store.load_snapshot(snapshot_id, self.db)["scan_id"], "scan-1"
        )

    def test_triage_requires_reason_and_records_history(self):
        netmap_store.store_snapshot(sample_snapshot(), [sample_finding()], path=self.db)
        finding = netmap_store.list_findings(self.db)[0]
        with self.assertRaises(ValueError):
            netmap_store.update_finding(
                finding["finding_id"], "accepted_risk", path=self.db
            )
        netmap_store.update_finding(
            finding["finding_id"], "accepted_risk", reason="Approved test", path=self.db
        )
        self.assertEqual(
            netmap_store.list_findings(self.db)[0]["status"], "accepted_risk"
        )
        self.assertEqual(
            netmap_store.finding_history(finding["finding_id"], self.db)[-1][
                "to_status"
            ],
            "accepted_risk",
        )

    def test_comparison_backup_restore_and_delete(self):
        first, _ = netmap_store.store_snapshot(sample_snapshot("a" * 64), path=self.db)
        second, _ = netmap_store.store_snapshot(sample_snapshot("b" * 64), path=self.db)
        netmap_store.save_comparison(first, second, [{"change": "none"}], self.db)
        self.assertEqual(len(netmap_store.list_comparisons(self.db)), 1)
        backup = Path(self.temp.name) / "backup.sqlite3"
        netmap_store.backup_database(backup, self.db)
        restored = Path(self.temp.name) / "restored.sqlite3"
        with self.assertRaises(ValueError):
            netmap_store.restore_database(backup, restored)
        netmap_store.restore_database(backup, restored, confirmed=True)
        self.assertEqual(len(netmap_store.list_snapshots(restored)), 2)
        netmap_store.delete_snapshot(first, self.db)
        self.assertEqual(len(netmap_store.list_snapshots(self.db)), 1)
        self.assertEqual(netmap_store.list_comparisons(self.db), [])

    def test_synthetic_database_path_is_separate(self):
        with patch.dict(os.environ, {"NETMAP_DATA_DIR": self.temp.name}):
            self.assertNotEqual(
                netmap_store.database_path(), netmap_store.database_path(synthetic=True)
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
