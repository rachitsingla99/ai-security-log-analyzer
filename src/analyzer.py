from pathlib import Path
from detector import detect_brute_force


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

    alerts = detect_brute_force(events)

    print("\nSecurity Alerts:")

    for alert in alerts:
        print(alert)