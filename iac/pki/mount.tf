# The intermediate PKI mount.
#
# In "rekey" mode the mount is kept and only the intermediate key is rotated.
# In "recreate" mode rotate.sh adds -replace=vault_mount.pki_int, which wipes
# the mount's certificate records and recreates the role along with it.

resource "vault_mount" "pki_int" {
  path                      = module.config.pki_mount
  type                      = "pki"
  description               = "YubiVault intermediate CA (managed by IaC)"
  default_lease_ttl_seconds = var.mount_default_lease_ttl_seconds
  max_lease_ttl_seconds     = var.mount_max_lease_ttl_seconds
}
