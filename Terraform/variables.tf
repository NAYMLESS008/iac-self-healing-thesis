# Google Cloud project ID
variable "project_id" {
  type = string
}

# Google Cloud region used by the evaluated environment
variable "region" {
  type    = string
  default = "europe-west1"
}

# Google Cloud zone used by the evaluated environment
variable "zone" {
  type    = string
  default = "europe-west1-b"
}

# VM size/type
variable "machine_type" {
  type    = string
  default = "e2-micro"
}

# Linux username for SSH access
variable "ssh_user" {
  type    = string
  default = "thesisadmin"
}

# Path to the trusted SSH public key
variable "public_key_path" {
  type = string
}

# IP range allowed to SSH into the VM
variable "allowed_ssh_cidr" {
  type = string
}

# Internal IP address of the separate Wazuh Manager VM
variable "wazuh_manager_ip" {
  type        = string
  description = "Internal IP address of the Wazuh Manager used by the target VM startup script."
}
