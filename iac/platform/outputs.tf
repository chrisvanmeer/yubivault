output "jwt_auth_accessor" {
  description = "Accessor of the JWT auth mount; consumed by the pki stack for allowed_domains templating."
  value       = vault_jwt_auth_backend.this.accessor
}

output "jwt_auth_mount" {
  description = "Path of the JWT auth mount."
  value       = vault_jwt_auth_backend.this.path
}

output "jwt_auth_role" {
  description = "Name of the JWT auth role."
  value       = vault_jwt_auth_backend_role.middleware.role_name
}

output "sign_policy_names" {
  description = "Names of the signing policies attached to the JWT role."
  value       = local.sign_policy_names
}

output "backend_policy_name" {
  description = "Name of the backend (inventory/revocation) policy, or null when disabled."
  value       = try(vault_policy.backend[0].name, null)
}

output "approle_mount" {
  description = "Path of the AppRole auth mount, or null when disabled."
  value       = try(vault_auth_backend.approle[0].path, null)
}

output "approle_role_name" {
  description = "Name of the portal AppRole role, or null when disabled."
  value       = try(vault_approle_auth_backend_role.portal[0].role_name, null)
}

output "approle_role_id" {
  description = "Role ID for config.yaml (vault.approle_role_id)."
  value       = try(vault_approle_auth_backend_role.portal[0].role_id, null)
  sensitive   = true
}

output "approle_secret_id" {
  description = "Secret ID for config.yaml (vault.approle_secret_id)."
  value       = try(vault_approle_auth_backend_role_secret_id.portal[0].secret_id, null)
  sensitive   = true
}

output "config_yaml_hint" {
  description = "Values to place under the vault: block of config.yaml."
  value = {
    address       = module.config.vault_address
    pki_mount     = module.config.pki_mount
    pki_role      = module.config.pki_role
    auth_mount    = module.config.auth_mount
    auth_role     = module.config.auth_role
    approle_mount = try(vault_auth_backend.approle[0].path, null)
  }
}
