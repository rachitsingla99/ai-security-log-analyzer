from pathlib import Path
from detector import (
    detect_brute_force,
    detect_password_spray,
    detect_privilege_change
)
from incident_creator import save_alerts


LOG_FILE = Path("logs/auth.log")


def parse_log_line(line):
    parts = line.strip().split()

    timestamp = parts[0]

    data = {
        "timestamp": timestamp
    }

    for part in parts[1:]:
        key, value = part.split("=", 1)
        data[key] = value

    return data


def read_logs():
    events = []

    with LOG_FILE.open("r") as file:
        for line in file:
            if line.strip():
                events.append(parse_log_line(line))

    return events



if __name__ == "__main__":

    events = read_logs()

    print(f"Total events: {len(events)}")

    
    alerts = []

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_password_spray(events))
    alerts.extend(detect_privilege_change(events))


    print(f"Security alerts detected: {len(alerts)}")

    for alert in alerts:
        print(alert)

    if alerts:
        print("\nSaving security alerts...")
        save_alerts(alerts)
    else:
        print("No suspicious activity detected.")
