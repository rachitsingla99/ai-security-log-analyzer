
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERTS_FOLDER = PROJECT_ROOT / "alerts"


def save_alerts(alerts):

    # Create alerts directory if it does not exist
    ALERTS_FOLDER.mkdir(parents=True, exist_ok=True)

    saved_files = []

    for alert in alerts:

        # Generate a unique alert identifier
        alert_id = f"ALERT-{uuid.uuid4().hex[:12].upper()}"

        # Record the time when the alert was generated
        created_at = datetime.now(timezone.utc).isoformat()

        # Build the structured security alert
        alert_data = {
            "alert_id": alert_id,
            "created_at": created_at,
            "status": "OPEN",
            "alert": alert
        }

        # Build the destination filename
        file_path = ALERTS_FOLDER / f"{alert_id}.json"

        # Open in exclusive creation mode
        with file_path.open("x", encoding="utf-8") as file:
            json.dump(alert_data, file, indent=4)

        saved_files.append(file_path)

        print(f"Alert saved: {file_path.name}")

    return saved_files
