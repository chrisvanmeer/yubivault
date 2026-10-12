# Normalise the config.yaml path (relative to this stack) and read the shared
# configuration, then resolve the rotation artefact paths.

locals {
  config_abs  = abspath("${path.root}/${var.config_file}")
  config_file = fileexists(local.config_abs) ? local.config_abs : null

  csr_abs    = abspath("${path.root}/${var.csr_output_file}")
  signed_abs = abspath("${path.root}/${var.signed_intermediate_file}")

  # The role and the signed intermediate are only managed once a signed
  # certificate is present. Until then the stack creates the mount and the CSR
  # and waits for the offline signature.
  signed_available = fileexists(local.signed_abs)
}

module "config" {
  source = "../modules/config"

  config_file   = local.config_file
  vault_address = var.vault_address
  pki_mount     = var.pki_mount
  pki_role      = var.pki_role
  cert_ttl      = var.cert_ttl
  cert_ttl_max  = var.cert_ttl_max
}
