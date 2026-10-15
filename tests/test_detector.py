
import unittest
import sys
from pathlib import Path

# Allow tests to import files from the src folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detector import (
    detect_brute_force,
    detect_password_spray,
    detect_privilege_change
)


class TestSecurityDetector(unittest.TestCase):

    def make_event(self, timestamp, user, ip, status):
        return {
            "timestamp": timestamp,
            "user": user,
            "src_ip": ip,
            "event": "LOGIN",
            "status": status
        }

    # Test 1: Five failures followed by success
    def test_brute_force_detected(self):

        events = []

        for second in range(5):
            events.append(
                self.make_event(
                    f"2026-09-25T10:00:0{second}",
                    "admin",
                    "192.0.2.10",
                    "FAILED"
                )
            )

        events.append(
            self.make_event(
                "2026-09-25T10:00:10",
                "admin",
                "192.0.2.10",
                "SUCCESS"
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "BRUTE_FORCE_SUCCESS"
        )

    # Test 2: Two failures should not trigger an alert
    def test_normal_failed_logins(self):

        events = [
            self.make_event(
                "2026-09-25T10:00:00",
                "john",
                "192.0.2.20",
                "FAILED"
            ),
            self.make_event(
                "2026-09-25T10:00:10",
                "john",
                "192.0.2.20",
                "FAILED"
            ),
            self.make_event(
                "2026-09-25T10:00:20",
                "john",
                "192.0.2.20",
                "SUCCESS"
            )
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # Test 3: Failures outside 10-minute window
    def test_brute_force_time_window(self):

        events = [
            self.make_event(
                f"2026-09-25T10:00:0{i}",
                "admin",
                "192.0.2.30",
                "FAILED"
            )
            for i in range(5)
        ]

        events.append(
            self.make_event(
                "2026-09-25T10:20:00",
                "admin",
                "192.0.2.30",
                "SUCCESS"
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # Test 4: Detect password spraying
    def test_password_spray_detected(self):

        events = []

        users = ["john", "alice", "bob", "charlie"]

        for index, user in enumerate(users):
            events.append(
                self.make_event(
                    f"2026-09-25T11:00:0{index}",
                    user,
                    "198.51.100.23",
                    "FAILED"
                )
            )

        alerts = detect_password_spray(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "PASSWORD_SPRAY"
        )
        self.assertEqual(
            alerts[0]["unique_accounts"],
            4
        )

    # Test 5: Detect successful privilege change
    def test_privilege_change_detected(self):

        events = [
            {
                "timestamp": "2026-09-25T12:00:00",
                "user": "admin",
                "src_ip": "10.0.0.10",
                "event": "PRIVILEGE_CHANGE",
                "target_user": "alice",
                "action": "GRANT_ADMIN",
                "status": "SUCCESS"
            }
        ]

        alerts = detect_privilege_change(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["target_user"],
            "alice"
        )

    # Test 6: Normal successful login
    def test_normal_login(self):

        events = [
            self.make_event(
                "2026-09-25T13:00:00",
                "john",
                "192.0.2.40",
                "SUCCESS"
            )
        ]

        alerts = []
        alerts.extend(detect_brute_force(events))
        alerts.extend(detect_password_spray(events))
        alerts.extend(detect_privilege_change(events))

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
