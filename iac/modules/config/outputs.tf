output "vault_address" {
  description = "Vault address, or null to fall back to VAULT_ADDR."
  value       = local.vault_address
}

output "pki_mount" {
  description = "PKI secrets engine mount."
  value       = local.pki_mount
}

output "pki_role" {
  description = "PKI role name."
  value       = local.pki_role
}

output "auth_mount" {
  description = "JWT auth backend mount."
  value       = local.auth_mount
}

output "auth_role" {
  description = "JWT auth role name."
  value       = local.auth_role
}

output "approle_mount" {
  description = "AppRole auth backend mount."
  value       = local.approle_mount
}

output "revoke_existing" {
  description = "Whether revocation/AppRole support is enabled."
  value       = local.revoke_existing
}

output "oidc_issuer" {
  description = "OIDC discovery URL."
  value       = local.oidc_issuer
}

output "oidc_client_id" {
  description = "OIDC client id (JWT audience)."
  value       = local.oidc_client_id
}

output "allowed_groups" {
  description = "OIDC groups allowed to request certificates."
  value       = local.allowed_groups
}

output "cert_ttl" {
  description = "Issued certificate TTL as configured (raw string)."
  value       = local.cert_ttl
}

output "cert_ttl_max" {
  description = "Issued certificate maximum TTL as configured (raw string)."
  value       = local.cert_ttl_max
}

output "cert_ttl_seconds" {
  description = "Issued certificate TTL in seconds, or null to inherit the Vault role default."
  value       = local.cert_ttl_seconds
}

output "cert_ttl_max_seconds" {
  description = "Issued certificate maximum TTL in seconds, or null to inherit the Vault role default."
  value       = local.cert_ttl_max_seconds
}
