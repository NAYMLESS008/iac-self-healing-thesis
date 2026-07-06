# Google Cloud project ID
variable "project_id" {
  type = string
}

# Google Cloud region
variable "region" {
  type    = string
  default = "us-central1"
}

# Google Cloud zone
variable "zone" {
  type    = string
  default = "us-central1-a"
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
