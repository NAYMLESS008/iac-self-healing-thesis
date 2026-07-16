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


