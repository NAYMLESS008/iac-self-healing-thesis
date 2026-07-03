# Prints the VM public IP after Terraform apply
output "external_ip" {
  value = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip
}

# Prints a ready-to-use SSH command for connecting to the VM
output "ssh_command" {
  value = "ssh -i ~/.ssh/gcp_thesis_vm ${var.ssh_user}@${google_compute_instance.vm.network_interface[0].access_config[0].nat_ip}"
}