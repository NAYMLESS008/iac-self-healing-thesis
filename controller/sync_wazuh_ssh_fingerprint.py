import base64
import json
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = (
    PROJECT_ROOT
    / "controller"
    / "ssh_rotation_state.json"
)

WAZUH_SSH_ALIAS = "thesis-wazuh-iap-quiet"
RULE_ID = "100002"


def get_current_fingerprint():
    if not STATE_FILE.exists():
        raise FileNotFoundError(
            f"Rotation state not found: {STATE_FILE}"
        )

    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8")
    )

    public_key_value = state.get("new_public_key")

    if not public_key_value:
        raise KeyError(
            "new_public_key is missing from rotation state."
        )

    public_key = Path(public_key_value)

    if not public_key.exists():
        raise FileNotFoundError(
            f"Trusted public key not found: {public_key}"
        )

    result = subprocess.run(
        [
            "ssh-keygen",
            "-lf",
            str(public_key),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
        )

    for part in result.stdout.split():
        if part.startswith("SHA256:"):
            return part

    raise RuntimeError(
        "No SHA256 fingerprint found."
    )


def update_manager_rule(fingerprint):
    remote_python = f'''
import re
from pathlib import Path

path = Path(
    "/var/ossec/etc/rules/local_rules.xml"
)

text = path.read_text(encoding="utf-8")

pattern = (
    r'(<rule id="{RULE_ID}"[^>]*>'
    r'[\\s\\S]*?'
    r'<match type="pcre2">'
    r'Accepted publickey\\.\\*SHA256:)'
    r'.*?'
    r'(</match>)'
)

replacement = (
    r'\\g<1>'
    + re.escape(
        {fingerprint!r}.replace(
            "SHA256:",
            ""
        )
    )
    + r'\\g<2>'
)

updated, count = re.subn(
    pattern,
    replacement,
    text,
    count=1,
)

if count != 1:
    raise SystemExit(
        "RULE_100002_MATCH_NOT_FOUND"
    )

path.write_text(
    updated,
    encoding="utf-8",
)

print("RULE_100002_UPDATED")
'''

    encoded_script = base64.b64encode(
        remote_python.encode("utf-8")
    ).decode("ascii")

    remote_command = (
        f"echo {encoded_script} | "
        "base64 -d | "
        "sudo python3 && "
        "sudo /var/ossec/bin/"
        "wazuh-analysisd -t && "
        "sudo systemctl restart "
        "wazuh-manager && "
        "sudo systemctl is-active "
        "wazuh-manager && "
        "sudo grep -n -A4 -B2 "
        f"'id=\"{RULE_ID}\"' "
        "/var/ossec/etc/rules/"
        "local_rules.xml"
    )

    result = subprocess.run(
        [
            "ssh",
            WAZUH_SSH_ALIAS,
            remote_command,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            "Failed to update Wazuh rule "
            f"{RULE_ID}."
        )


def main():
    fingerprint = get_current_fingerprint()

    print(
        "[INFO] Current trusted key fingerprint:"
    )
    print(fingerprint)

    update_manager_rule(fingerprint)

    print(
        "[SUCCESS] Wazuh rule "
        f"{RULE_ID} now matches "
        f"{fingerprint}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
