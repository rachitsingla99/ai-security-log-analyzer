
import json
from pathlib import Path
from datetime import datetime, timezone


ALERTS_FOLDER = Path("alerts")


def save_alerts(alerts):

    # Create alerts directory if it doesn't exist
    ALERTS_FOLDER.mkdir(exist_ok=True)

    saved_files = []

    for index, alert in enumerate(alerts, start=1):

        alert_id = f"ALERT-{index:03d}"

        alert_data = {
            "alert_id": alert_id,
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "status": "OPEN",
            "alert": alert
        }

        file_path = ALERTS_FOLDER / f"{alert_id}.json"

        with file_path.open("w", encoding="utf-8") as file:
            json.dump(alert_data, file, indent=4)

        saved_files.append(file_path)

        print(f"Alert saved: {file_path}")

    return saved_files
