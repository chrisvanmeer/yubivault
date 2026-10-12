# Reads YubiVault's config.yaml and exposes normalised values to the stacks.
#
# Precedence for every value: explicit variable override > config.yaml > default.
# Secrets in config.yaml (session_secret, approle_secret_id, oidc.client_secret)
# are intentionally never read.

locals {
  cfg = var.config_file != null ? try(yamldecode(file(var.config_file)), null) : null

  vault_address   = var.vault_address != null ? var.vault_address : try(local.cfg.vault.address, null)
  pki_mount       = coalesce(var.pki_mount, try(local.cfg.vault.pki_mount, null), "pki_int")
  pki_role        = coalesce(var.pki_role, try(local.cfg.vault.pki_role, null), "yubivault")
  auth_mount      = coalesce(var.auth_mount, try(local.cfg.vault.auth_mount, null), "jwt-yubivault")
  auth_role       = coalesce(var.auth_role, try(local.cfg.vault.auth_role, null), "yubivault-middleware")
  approle_mount   = coalesce(var.approle_mount, try(local.cfg.vault.approle_mount, null), "approle")
  revoke_existing = var.revoke_existing != null ? var.revoke_existing : try(local.cfg.vault.revoke_existing, false)

  oidc_issuer    = coalesce(var.oidc_issuer, try(local.cfg.oidc.issuer, null), "https://idp.example.com/realms/master")
  oidc_client_id = coalesce(var.oidc_client_id, try(local.cfg.oidc.client_id, null), "yubivault")
  allowed_groups = var.allowed_groups != null ? var.allowed_groups : try(tolist(local.cfg.oidc.allowed_groups), [])

  cert_ttl     = var.cert_ttl != null ? var.cert_ttl : try(local.cfg.vault.cert_ttl, null)
  cert_ttl_max = var.cert_ttl_max != null ? var.cert_ttl_max : try(local.cfg.vault.cert_ttl_max, null)

  # Convert a Go duration string ("720h", "30m", "45s", "30d") to whole
  # seconds. A bare number is treated as seconds. An absent/unparsable value
  # becomes null so the Vault role default applies. Duplicated for both TTLs
  # because HCL has no reusable local functions.
  cert_ttl_seconds = try(coalesce(
    try(tonumber(regex("^([0-9]+)d$", local.cert_ttl)[0]) * 86400, null),
    try(tonumber(regex("^([0-9]+)h$", local.cert_ttl)[0]) * 3600, null),
    try(tonumber(regex("^([0-9]+)m$", local.cert_ttl)[0]) * 60, null),
    try(tonumber(regex("^([0-9]+)s$", local.cert_ttl)[0]), null),
    try(tonumber(local.cert_ttl), null),
  ), null)

  cert_ttl_max_seconds = try(coalesce(
    try(tonumber(regex("^([0-9]+)d$", local.cert_ttl_max)[0]) * 86400, null),
    try(tonumber(regex("^([0-9]+)h$", local.cert_ttl_max)[0]) * 3600, null),
    try(tonumber(regex("^([0-9]+)m$", local.cert_ttl_max)[0]) * 60, null),
    try(tonumber(regex("^([0-9]+)s$", local.cert_ttl_max)[0]), null),
    try(tonumber(local.cert_ttl_max), null),
  ), null)
}
