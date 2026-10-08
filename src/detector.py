
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
