# Terraform + Google provider setup
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

# Google Cloud project/location settings
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Firewall rule: allow SSH only from my IP
resource "google_compute_firewall" "allow_ssh" {
  name    = "thesis-allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.allowed_ssh_cidr]
  target_tags   = ["thesis-vm"]
}

# Main test VM for the self-healing experiment
resource "google_compute_instance" "vm" {
  name         = "thesis-self-healing-vm"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["thesis-vm"]

  # Ubuntu boot disk
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 10
      type  = "pd-standard"
    }
  }

  # Network + external IP for SSH
  network_interface {
    network = "default"

    access_config {
      # Gives the VM a public IP
    }
  }

  # Trusted SSH key added during VM creation
  metadata = {
    block-project-ssh-keys = "true"
    ssh-keys               = "${var.ssh_user}:${file(var.public_key_path)}"

    # --- Bootstrap the replacement VM into the expected monitoring baseline ---
    # This startup script is rerun when Terraform creates a replacement target.
    startup-script = <<-EOT
      #!/bin/bash
      set -e

      echo "[STARTUP] Installing Wazuh agent" > /var/log/thesis-startup.log

      # Install the Wazuh agent and point it at the separate trusted manager.
      curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb
      WAZUH_MANAGER="${var.wazuh_manager_ip}" dpkg -i ./wazuh-agent_4.14.5-1_amd64.deb

            # Enable real-time FIM and report file-content changes for the monitored system paths.
            sed -i 's|<directories>/etc,/usr/bin,/usr/sbin</directories>|<directories check_all="yes" realtime="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>|' /var/ossec/etc/ossec.conf

      # Wait for Google/SSH provisioning to create the user's authorized_keys file.
      for i in $(seq 1 30); do
        if [ -f /home/${var.ssh_user}/.ssh/authorized_keys ]; then
          break
        fi
        sleep 2
      done

      # Add authorized_keys to Wazuh FIM so unauthorized key insertion can be detected.
      if [ -f /home/${var.ssh_user}/.ssh/authorized_keys ]; then
        grep -q "/home/${var.ssh_user}/.ssh/authorized_keys" /var/ossec/etc/ossec.conf || sed -i '/<\/syscheck>/i\    <directories check_all="yes" realtime="yes" report_changes="yes">/home/${var.ssh_user}/.ssh/authorized_keys</directories>' /var/ossec/etc/ossec.conf
      fi

      echo "[STARTUP] Configuring Wazuh auth-log collection" >> /var/log/thesis-startup.log

      # Collect SSH authentication events so key/fingerprint rules can inspect auth.log.
      if ! grep -q '<location>/var/log/auth.log</location>' /var/ossec/etc/ossec.conf; then
        cat >> /var/ossec/etc/ossec.conf <<'WAZUH_AUTH_LOG'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
WAZUH_AUTH_LOG
      fi

      echo "[STARTUP] Configuring listening-port command monitoring" >> /var/log/thesis-startup.log

      # Wazuh command monitoring requires remote command collection to be enabled.
      touch /var/ossec/etc/local_internal_options.conf

      grep -q '^logcollector.remote_commands=1$' /var/ossec/etc/local_internal_options.conf ||         echo 'logcollector.remote_commands=1' >> /var/ossec/etc/local_internal_options.conf

      # Replace Wazuh's existing listening-port command with a stable ss-based command
      # and shorten its collection interval to ten seconds for this experiment.
      python3 - <<'PY'
from pathlib import Path
import re

path = Path("/var/ossec/etc/ossec.conf")
text = path.read_text()

text, command_count = re.subn(
    r"(?m)^[ \t]*<command>netstat .*?</command>$",
    """    <command>ss -H -lnt | awk '{print $4}' | sort -u</command>""",
    text,
    count=1,
)

text, frequency_count = re.subn(
    r"(<alias>netstat listening ports</alias>\s*<frequency>)\d+(</frequency>)",
    r"\g<1>10\g<2>",
    text,
    count=1,
)

# Refuse to continue if the expected Wazuh configuration was not changed exactly once.
if command_count != 1:
    raise SystemExit(
        f"Expected one netstat command, replaced {command_count}."
    )

if frequency_count != 1:
    raise SystemExit(
        f"Expected one listener frequency, replaced {frequency_count}."
    )

path.write_text(text)
PY

      echo "[STARTUP] Configuring explicit thesis listener detection" >> /var/log/thesis-startup.log

      # Add the experiment-specific port-4444 command source if it is not already configured.
      if ! grep -q '<alias>thesis unexpected listener</alias>' /var/ossec/etc/ossec.conf; then
        cat >> /var/ossec/etc/ossec.conf <<'WAZUH_THESIS_LISTENER'
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>if ss -H -lnt 'sport = :4444' | grep -q .; then echo 'THESIS_UNEXPECTED_LISTENER port=4444'; else echo 'THESIS_LISTENER_CLEAN'; fi</command>
    <alias>thesis unexpected listener</alias>
    <frequency>10</frequency>
  </localfile>
</ossec_config>
WAZUH_THESIS_LISTENER
      fi

      echo "[STARTUP] Enabling verbose SSH authentication logging" >> /var/log/thesis-startup.log

      # VERBOSE SSH logging includes public-key fingerprints used by the custom Wazuh rule.
      if grep -qE '^[[:space:]]*LogLevel[[:space:]]+' /etc/ssh/sshd_config; then
        sed -i 's/^[[:space:]]*LogLevel[[:space:]].*/LogLevel VERBOSE/' /etc/ssh/sshd_config
      else
        echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config
      fi

      # Validate SSH configuration before restarting the service.
      sshd -t
      systemctl restart ssh

      # Start the freshly configured Wazuh agent on the replacement target.
      systemctl daemon-reload
      systemctl enable wazuh-agent
      systemctl start wazuh-agent

      echo "[STARTUP] Wazuh agent installed and started" >> /var/log/thesis-startup.log
    EOT
  }

  # Labels for identifying thesis resources
  labels = {
    project = "msc-thesis"
    role    = "self-healing-test"
  }
}


