import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TFVARS_FILE = PROJECT_ROOT / "Terraform" / "terraform.tfvars"
SSH_DIR = Path.home() / ".ssh"
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"

INITIAL_PRIVATE_KEY = (
    SSH_DIR / "gcp_thesis_vm_rotated_run1_new"
)


def get_current_private_key():
    """
    Return the private key currently trusted by Terraform.

    After the first rotation, the latest trusted key is stored
    in ssh_rotation_state.json as new_private_key.
    """
    if STATE_FILE.exists():
        try:
            state = json.loads(
                STATE_FILE.read_text(encoding="utf-8")
            )

            stored_key = state.get("new_private_key")

            if stored_key:
                current_key = Path(stored_key)

                if current_key.exists():
                    print(
                        "[INFO] Current trusted key loaded "
                        f"from rotation state: {current_key}"
                    )
                    return current_key

                raise FileNotFoundError(
                    "Trusted key recorded in rotation state "
                    f"does not exist: {current_key}"
                )

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Invalid rotation state JSON: {STATE_FILE}"
            ) from exc

    print(
        "[INFO] No previous rotation state found; "
        f"using initial key: {INITIAL_PRIVATE_KEY}"
    )
    return INITIAL_PRIVATE_KEY


def run_command(command):
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout.strip())

    if result.stderr:
        print(result.stderr.strip())

    return result


def preserve_compromised_key(timestamp):
    compromised_private = (
        SSH_DIR / f"gcp_thesis_vm_compromised_{timestamp}"
    )
    compromised_public = Path(
        f"{compromised_private}.pub"
    )

    current_private_key = get_current_private_key()

    current_public = Path(
        f"{current_private_key}.pub"
    )

    if not current_private_key.exists():
        raise FileNotFoundError(
            f"Current private key not found: "
            f"{current_private_key}"
        )

    if not current_public.exists():
        raise FileNotFoundError(
            f"Current public key not found: "
            f"{current_public}"
        )

    shutil.copy2(
        current_private_key,
        compromised_private,
    )
    shutil.copy2(
        current_public,
        compromised_public,
    )

    print(
        "[OK] Preserved compromised private key:",
        compromised_private,
    )

    return compromised_private


def generate_new_key(timestamp):
    new_private = (
        SSH_DIR / f"gcp_thesis_vm_rotated_{timestamp}"
    )
    new_public = Path(f"{new_private}.pub")

    result = run_command([
        "ssh-keygen",
        "-t", "ed25519",
        "-f", str(new_private),
        "-N", "",
        "-C", f"thesis-rotation-{timestamp}",
    ])

    if result.returncode != 0:
        raise RuntimeError(
            "Failed to generate new SSH key pair."
        )

    if not new_private.exists() or not new_public.exists():
        raise RuntimeError(
            "New SSH key files were not created."
        )

    print("[OK] New private key:", new_private)
    print("[OK] New public key:", new_public)

    return new_private, new_public


def update_tfvars(new_public):
    original = TFVARS_FILE.read_text(
        encoding="utf-8"
    )

    terraform_path = str(
        new_public
    ).replace("\\", "/")

    updated, replacements = re.subn(
        r'public_key_path\s*=\s*"[^"]+"',
        f'public_key_path = "{terraform_path}"',
        original,
        count=1,
    )

    if replacements != 1:
        raise RuntimeError(
            "Could not update public_key_path "
            "in terraform.tfvars."
        )

    TFVARS_FILE.write_text(
        updated,
        encoding="utf-8",
    )

    print(
        "[OK] terraform.tfvars now uses:",
        terraform_path,
    )


def write_state(
    compromised_private,
    new_private,
    new_public,
):
    import json

    state = {
        "compromised_private_key": str(
            compromised_private
        ),
        "new_private_key": str(new_private),
        "new_public_key": str(new_public),
    }

    STATE_FILE.write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )

    print("[OK] Rotation state saved:", STATE_FILE)


def main():
    print(
        "[START] Preparing SSH credential rotation"
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    try:
        compromised_private = (
            preserve_compromised_key(timestamp)
        )

        new_private, new_public = (
            generate_new_key(timestamp)
        )

        update_tfvars(new_public)

        write_state(
            compromised_private,
            new_private,
            new_public,
        )

    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1

    print(
        "[SUCCESS] New trusted SSH key prepared "
        "for Terraform replacement."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
