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

    startup-script = <<-EOT
      #!/bin/bash
      set -e

      echo "[STARTUP] Installing Wazuh agent" > /var/log/thesis-startup.log

      curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb
      WAZUH_MANAGER="${var.wazuh_manager_ip}" dpkg -i ./wazuh-agent_4.14.5-1_amd64.deb

            sed -i 's|<directories>/etc,/usr/bin,/usr/sbin</directories>|<directories check_all="yes" realtime="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>|' /var/ossec/etc/ossec.conf

      for i in $(seq 1 30); do
        if [ -f /home/${var.ssh_user}/.ssh/authorized_keys ]; then
          break
        fi
        sleep 2
      done

      if [ -f /home/${var.ssh_user}/.ssh/authorized_keys ]; then
        grep -q "/home/${var.ssh_user}/.ssh/authorized_keys" /var/ossec/etc/ossec.conf || sed -i '/<\/syscheck>/i\    <directories check_all="yes" realtime="yes" report_changes="yes">/home/${var.ssh_user}/.ssh/authorized_keys</directories>' /var/ossec/etc/ossec.conf
      fi

      echo "[STARTUP] Configuring Wazuh auth-log collection" >> /var/log/thesis-startup.log

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

      echo "[STARTUP] Enabling verbose SSH authentication logging" >> /var/log/thesis-startup.log

      if grep -qE '^[[:space:]]*LogLevel[[:space:]]+' /etc/ssh/sshd_config; then
        sed -i 's/^[[:space:]]*LogLevel[[:space:]].*/LogLevel VERBOSE/' /etc/ssh/sshd_config
      else
        echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config
      fi

      sshd -t
      systemctl restart ssh

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


