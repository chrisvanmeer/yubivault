output "pki_mount" {
  description = "Path of the intermediate PKI mount."
  value       = vault_mount.pki_int.path
}

output "pki_role" {
  description = "Name of the signing role."
  value       = module.config.pki_role
}

output "intermediate_csr_path" {
  description = "Where the intermediate CSR is written for offline signing."
  value       = local.csr_abs
}

output "signed_intermediate_path" {
  description = "Where the offline-signed intermediate certificate is expected."
  value       = local.signed_abs
}

output "role_created" {
  description = "Whether the signed intermediate was present and the role was (re)created."
  value       = local.signed_available
}

output "role_ttl_seconds" {
  description = "Configured certificate TTL in seconds (null inherits the role default)."
  value       = module.config.cert_ttl_seconds
}

output "role_max_ttl_seconds" {
  description = "Configured certificate maximum TTL in seconds (null inherits the role default)."
  value       = module.config.cert_ttl_max_seconds
}

output "next_step" {
  description = "Human hint for the offline signing step."
  value       = local.signed_available ? "signed intermediate imported; role ${module.config.pki_role} active on ${vault_mount.pki_int.path}" : "sign ${local.csr_abs} on the airgapped root and save the result as ${local.signed_abs}, then run apply again"
}
