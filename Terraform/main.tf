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
    ssh-keys = "${var.ssh_user}:${file(var.public_key_path)}"
  }

  # Labels for identifying thesis resources
  labels = {
    project = "msc-thesis"
    role    = "self-healing-test"
  }
}