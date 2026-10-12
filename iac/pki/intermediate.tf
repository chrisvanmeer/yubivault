# Intermediate key material.
#
# Flow (offline root):
#   1. terraform apply              -> creates the mount and the CSR below.
#   2. sign generated/intermediate.csr on the airgapped root.
#   3. save the signed certificate as generated/intermediate-signed.pem.
#   4. terraform apply              -> imports it and creates the role.

# Replaced when rotation_token changes: rotates the intermediate key in place
# while the mount is kept. In "recreate" mode the whole mount is replaced
# instead (see rotate.sh), which recreates this resource as a dependency.
resource "terraform_data" "rekey" {
  triggers_replace = {
    token = var.rotation_token
  }
}

resource "vault_pki_secret_backend_intermediate_cert_request" "intermediate" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = var.intermediate_common_name
  key_type    = var.intermediate_key_type
  key_bits    = var.intermediate_key_bits

  lifecycle {
    replace_triggered_by = [terraform_data.rekey]
  }
}

# Writes the CSR to disk for the offline signing step.
resource "local_file" "csr" {
  filename        = local.csr_abs
  content         = vault_pki_secret_backend_intermediate_cert_request.intermediate.csr
  file_permission = "0644"
}

# Imports the signed intermediate. Vault verifies that the certificate matches
# the private key on the mount, so a stale certificate fails loudly.
resource "vault_pki_secret_backend_intermediate_set_signed" "signed" {
  count = local.signed_available ? 1 : 0

  backend     = vault_mount.pki_int.path
  certificate = file(local.signed_abs)
}
