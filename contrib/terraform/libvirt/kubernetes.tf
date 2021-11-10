resource "null_resource" "deploy_kubernetes" {
  depends_on = [
    null_resource.control_plane_reboot,
    null_resource.worker_reboot
  ]
  count = 1

  provisioner "local-exec" {
    environment = {
      TR_STACK      = var.stack_name
      TR_USERNAME   = var.username
      TR_MASTER_IPS = join(" ", libvirt_domain.control_plane.*.network_interface.0.addresses.0)
      TR_WORKER_IPS = join(" ", libvirt_domain.worker.*.network_interface.0.addresses.0)
    }

    command = "bash deploy-kubernetes.sh"
  }
}
