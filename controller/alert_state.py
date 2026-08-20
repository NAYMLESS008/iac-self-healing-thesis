import json
import sys
from pathlib import Path


CONTROLLER_DIR = Path(__file__).resolve().parent
PROCESSED_FILE = CONTROLLER_DIR / "processed_alerts.json"
SELECTED_FILE = CONTROLLER_DIR / "selected_alerts.json"


def read_json(path):
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def write_json(path, data):
    temporary_path = path.with_suffix(path.suffix + ".tmp")

    temporary_path.write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8"
    )

    temporary_path.replace(path)


def get_processed_alert_id(scenario):
    return read_json(PROCESSED_FILE).get(scenario)


def is_alert_processed(scenario, alert_id):
    return get_processed_alert_id(scenario) == alert_id


def save_selected_alert(scenario, alert_id):
    selected = read_json(SELECTED_FILE)
    selected[scenario] = alert_id
    write_json(SELECTED_FILE, selected)


def get_selected_alert_id(scenario):
    return read_json(SELECTED_FILE).get(scenario)


def mark_selected_alert_processed(scenario):
    alert_id = get_selected_alert_id(scenario)

    if not alert_id:
        print(
            f"[WARNING] No selected alert ID exists for scenario: "
            f"{scenario}"
        )
        return False

    processed = read_json(PROCESSED_FILE)
    processed[scenario] = alert_id
    write_json(PROCESSED_FILE, processed)

    selected = read_json(SELECTED_FILE)
    selected.pop(scenario, None)
    write_json(SELECTED_FILE, selected)

    print(
        f"[STATE] Alert {alert_id} marked as processed "
        f"for {scenario}."
    )
    return True


def show_state():
    print("=== PROCESSED ALERTS ===")
    print(json.dumps(read_json(PROCESSED_FILE), indent=2))

    print("=== SELECTED ALERTS ===")
    print(json.dumps(read_json(SELECTED_FILE), indent=2))


def main():
    if len(sys.argv) < 2:
        show_state()
        return 0

    command = sys.argv[1]

    if command == "show":
        show_state()
        return 0

    if command == "mark" and len(sys.argv) == 3:
        scenario = sys.argv[2]
        return 0 if mark_selected_alert_processed(scenario) else 1

    print(
        "Usage:\n"
        "  python -m controller.alert_state show\n"
        "  python -m controller.alert_state mark <scenario>"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
