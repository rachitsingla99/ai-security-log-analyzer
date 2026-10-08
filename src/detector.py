
from collections import defaultdict
from datetime import datetime, timedelta

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def detect_brute_force(events):
    login_history = defaultdict(list)
    alerts = []

    # Sort events by their timestamps
    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    for event in sorted_events:

        if event.get("event") != "LOGIN":
            continue

        ip = event.get("src_ip")
        user = event.get("user")
        status = event.get("status")

        if not ip or not user:
            continue

        timestamp = datetime.fromisoformat(
            event["timestamp"]
        )

        # Track each IP and username combination
        key = (ip, user)

        if status == "FAILED":
            login_history[key].append(timestamp)

        elif status == "SUCCESS":

            # Only count failures in the last 10 minutes
            window_start = timestamp - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            recent_failures = [
                failure_time
                for failure_time in login_history[key]
                if window_start <= failure_time < timestamp
            ]

            if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

                alerts.append({
                    "type": "BRUTE_FORCE_SUCCESS",
                    "source_ip": ip,
                    "username": user,
                    "failed_attempts": len(recent_failures),
                    "successful_login": event["timestamp"],
                    "severity": "HIGH",
                    "description": (
                        "Multiple failed login attempts "
                        "followed by a successful login"
                    )
                })

            # Reset failures after a successful login
            login_history[key] = []

    return alerts


def detect_password_spray(events):
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:

        if (
            event.get("event") == "LOGIN"
            and event.get("status") == "FAILED"
        ):
            ip = event.get("src_ip")
            username = event.get("user")
            timestamp = event.get("timestamp")

            if ip and username and timestamp:
                failed_logins[ip].append({
                    "username": username,
                    "timestamp": datetime.fromisoformat(timestamp)
                })

    for ip, attempts in failed_logins.items():

        attempts.sort(key=lambda item: item["timestamp"])

        for index, attempt in enumerate(attempts):

            window_start = attempt["timestamp"]
            window_end = window_start + timedelta(minutes=10)

            recent_attempts = [
                item for item in attempts
                if window_start <= item["timestamp"] <= window_end
            ]

            unique_users = set(
                item["username"] for item in recent_attempts
            )

            if len(unique_users) >= 3:

                alerts.append({
                    "type": "PASSWORD_SPRAY",
                    "source_ip": ip,
                    "targeted_accounts": sorted(unique_users),
                    "unique_accounts": len(unique_users),
                    "severity": "HIGH",
                    "description": (
                        "Multiple user accounts experienced "
                        "failed logins from the same IP "
                        "within 10 minutes"
                    )
                })

                break

    return alerts

def detect_privilege_change(events):
    alerts = []

    for event in events:

        if (
            event.get("event") == "PRIVILEGE_CHANGE"
            and event.get("status") == "SUCCESS"
        ):

            alerts.append({
                "type": "PRIVILEGE_CHANGE",
                "source_ip": event.get("src_ip"),
                "performed_by": event.get("user"),
                "target_user": event.get("target_user"),
                "action": event.get("action"),
                "timestamp": event.get("timestamp"),
                "severity": "MEDIUM",
                "description": (
                    "Successful privilege change detected. "
                    "Review whether the change was authorized."
                )
            })

    return alerts
