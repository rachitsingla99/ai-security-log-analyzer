
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import package_generator


class TestPackageGenerator(unittest.TestCase):

    def setUp(self):

        # Create a temporary, isolated test workspace
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.alerts_dir = self.root / "alerts"
        self.logs_dir = self.root / "logs"
        self.packages_dir = self.root / "investigation_packages"

        self.alerts_dir.mkdir()
        self.logs_dir.mkdir()
        self.packages_dir.mkdir()

        self.log_file = self.logs_dir / "auth.log"

        self.log_file.write_text(
            "2026-09-25T11:00:00 user=john "
            "src_ip=198.51.100.23 "
            "event=LOGIN status=FAILED\n"
            "2026-09-25T11:00:15 user=alice "
            "src_ip=198.51.100.23 "
            "event=LOGIN status=FAILED\n"
            "2026-09-25T11:00:30 user=bob "
            "src_ip=192.0.2.10 "
            "event=LOGIN status=SUCCESS\n",
            encoding="utf-8"
        )

        self.alert_path = self.alerts_dir / "ALERT-TEST.json"

        self.alert_data = {
            "alert_id": "ALERT-TEST",
            "status": "OPEN",
            "alert": {
                "type": "PASSWORD_SPRAY",
                "source_ip": "198.51.100.23",
                "severity": "HIGH"
            }
        }

        self.save_test_alert()

        # Redirect the generator to temporary folders
        self.patchers = [
            patch.object(
                package_generator,
                "ALERTS_DIR",
                self.alerts_dir
            ),
            patch.object(
                package_generator,
                "LOG_FILE",
                self.log_file
            ),
            patch.object(
                package_generator,
                "PACKAGES_DIR",
                self.packages_dir
            )
        ]

        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):

        for patcher in reversed(self.patchers):
            patcher.stop()

        self.temp_dir.cleanup()

    def save_test_alert(self):

        self.alert_path.write_text(
            json.dumps(self.alert_data),
            encoding="utf-8"
        )

    # Test 1: A package contains all four required files
    def test_package_creation(self):

        folder = package_generator.create_investigation_package(
            self.alert_path
        )

        self.assertTrue((folder / "alert.json").exists())
        self.assertTrue((folder / "evidence.log").exists())
        self.assertTrue(
            (folder / "investigation_context.json").exists()
        )
        self.assertTrue(
            (folder / "investigation_prompt.md").exists()
        )

    # Test 2: Extract only log entries from the matching IP
    def test_evidence_filtering(self):

        folder = package_generator.create_investigation_package(
            self.alert_path
        )

        evidence = (folder / "evidence.log").read_text(
            encoding="utf-8"
        )

        self.assertEqual(len(evidence.splitlines()), 2)
        self.assertIn("198.51.100.23", evidence)
        self.assertNotIn("192.0.2.10", evidence)

    # Test 3: Validate investigation context
    def test_context_metadata(self):

        folder = package_generator.create_investigation_package(
            self.alert_path
        )

        context = json.loads(
            (folder / "investigation_context.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(context["alert_id"], "ALERT-TEST")
        self.assertEqual(context["detection_type"], "PASSWORD_SPRAY")
        self.assertEqual(context["matching_log_events"], 2)
        self.assertEqual(
            context["investigation_status"],
            "PENDING_REVIEW"
        )

    # Test 4: Reject alerts without a source IP
    def test_missing_source_ip(self):

        self.alert_data["alert"].pop("source_ip")
        self.save_test_alert()

        with self.assertRaises(ValueError):
            package_generator.create_investigation_package(
                self.alert_path
            )

    # Test 5: Repeated runs must not overwrite packages
    def test_unique_package_folders(self):

        first = package_generator.create_investigation_package(
            self.alert_path
        )

        second = package_generator.create_investigation_package(
            self.alert_path
        )

        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())


if __name__ == "__main__":
    unittest.main()
