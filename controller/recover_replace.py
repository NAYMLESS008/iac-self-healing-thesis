import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_DIR = PROJECT_ROOT / "Terraform"


def run_command(command):
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode


def get_external_ip():
    result = subprocess.run(
        ["terraform", "-chdir=Terraform", "output", "-raw", "external_ip"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


def main():
    print("[1] Starting Terraform replacement recovery for target VM only...")

    command = [
        "terraform",
        "-chdir=Terraform",
        "apply",
        "-replace=google_compute_instance.vm",
        "-auto-approve"
    ]

    code = run_command(command)

    if code != 0:
        print("[ERROR] Terraform replacement failed.")
        raise SystemExit(1)

    new_ip = get_external_ip()

    print("[2] Terraform replacement completed.")
    print(f"[OK] New target VM external IP: {new_ip}")
    print("[NEXT] Wait for startup script to install Wazuh agent, then validate.")


if __name__ == "__main__":
    main()
