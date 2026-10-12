# Normalise the config.yaml path to an absolute one (relative to this stack)
# and read the shared configuration.

locals {
  config_abs  = abspath("${path.root}/${var.config_file}")
  config_file = fileexists(local.config_abs) ? local.config_abs : null
}

module "config" {
  source = "../modules/config"

  config_file     = local.config_file
  vault_address   = var.vault_address
  pki_mount       = var.pki_mount
  pki_role        = var.pki_role
  auth_mount      = var.auth_mount
  auth_role       = var.auth_role
  approle_mount   = var.approle_mount
  revoke_existing = var.revoke_existing
  oidc_issuer     = var.oidc_issuer
  oidc_client_id  = var.oidc_client_id
  allowed_groups  = var.allowed_groups
}

locals {
  # One signing policy per allowed OIDC group (README example: pol-testers),
  # or a single fallback policy when no groups are configured.
  sign_policy_names = length(module.config.allowed_groups) > 0 ? [
    for g in module.config.allowed_groups : "${var.sign_policy_prefix}${g}"
  ] : [var.fallback_sign_policy_name]
}
