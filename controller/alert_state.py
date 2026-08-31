import json
import sys
from pathlib import Path


# --- Alert-state files used by the controller ---
# processed_alerts.json remembers alerts that already completed recovery.
# selected_alerts.json stores the alert currently being handled per scenario.
CONTROLLER_DIR = Path(__file__).resolve().parent
PROCESSED_FILE = CONTROLLER_DIR / "processed_alerts.json"
SELECTED_FILE = CONTROLLER_DIR / "selected_alerts.json"


# --- Read controller state safely ---
def read_json(path):
    # A missing or unreadable state file is treated as empty state.
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


# --- Write controller state atomically ---
def write_json(path, data):
    # Write to a temporary file first, then replace the real file.
    # This reduces the chance of leaving a partially written JSON file.
    temporary_path = path.with_suffix(path.suffix + ".tmp")

    temporary_path.write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8"
    )

    temporary_path.replace(path)


# --- Look up the last successfully processed alert for a scenario ---
def get_processed_alert_id(scenario):
    return read_json(PROCESSED_FILE).get(scenario)


# --- Prevent the same alert from triggering recovery again ---
def is_alert_processed(scenario, alert_id):
    return get_processed_alert_id(scenario) == alert_id


# --- Remember the exact alert selected for the current recovery ---
def save_selected_alert(scenario, alert_id):
    selected = read_json(SELECTED_FILE)
    selected[scenario] = alert_id
    write_json(SELECTED_FILE, selected)


# --- Retrieve the alert currently selected for a scenario ---
def get_selected_alert_id(scenario):
    return read_json(SELECTED_FILE).get(scenario)


# --- Mark an alert processed only after the recovery workflow succeeds ---
def mark_selected_alert_processed(scenario):
    alert_id = get_selected_alert_id(scenario)

    if not alert_id:
        print(
            f"[WARNING] No selected alert ID exists for scenario: "
            f"{scenario}"
        )
        return False

    # Move the alert ID into processed state so it cannot be reused.
    processed = read_json(PROCESSED_FILE)
    processed[scenario] = alert_id
    write_json(PROCESSED_FILE, processed)

    # Remove it from selected state because the workflow is complete.
    selected = read_json(SELECTED_FILE)
    selected.pop(scenario, None)
    write_json(SELECTED_FILE, selected)

    print(
        f"[STATE] Alert {alert_id} marked as processed "
        f"for {scenario}."
    )
    return True


# --- Print the current selected/processed alert state ---
def show_state():
    print("=== PROCESSED ALERTS ===")
    print(json.dumps(read_json(PROCESSED_FILE), indent=2))

    print("=== SELECTED ALERTS ===")
    print(json.dumps(read_json(SELECTED_FILE), indent=2))


# --- Small command-line interface for inspecting or updating alert state ---
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
