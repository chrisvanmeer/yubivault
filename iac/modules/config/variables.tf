# Inputs for the shared YubiVault configuration reader.
#
# Every value can be supplied explicitly here; when left null the module falls
# back to the matching key in config.yaml and finally to a safe default.

variable "config_file" {
  description = "Absolute path to a YubiVault config.yaml, or null to use overrides/defaults only."
  type        = string
  default     = null
}

variable "vault_address" {
  description = "Vault address (vault.address). Null lets the provider use VAULT_ADDR."
  type        = string
  default     = null
}

variable "pki_mount" {
  description = "PKI secrets engine mount (vault.pki_mount)."
  type        = string
  default     = null
}

variable "pki_role" {
  description = "PKI role name (vault.pki_role)."
  type        = string
  default     = null
}

variable "auth_mount" {
  description = "JWT auth backend mount (vault.auth_mount)."
  type        = string
  default     = null
}

variable "auth_role" {
  description = "JWT auth role name (vault.auth_role)."
  type        = string
  default     = null
}

variable "approle_mount" {
  description = "AppRole auth backend mount (vault.approle_mount)."
  type        = string
  default     = null
}

variable "revoke_existing" {
  description = "Whether revocation/AppRole support is enabled (vault.revoke_existing)."
  type        = bool
  default     = null
}

variable "oidc_issuer" {
  description = "OIDC discovery URL (oidc.issuer)."
  type        = string
  default     = null
}

variable "oidc_client_id" {
  description = "OIDC client id, used as the JWT audience (oidc.client_id)."
  type        = string
  default     = null
}

variable "allowed_groups" {
  description = "OIDC groups allowed to request certificates (oidc.allowed_groups)."
  type        = list(string)
  default     = null
}

variable "cert_ttl" {
  description = "Issued certificate TTL as a Go duration string (vault.cert_ttl)."
  type        = string
  default     = null
}

variable "cert_ttl_max" {
  description = "Issued certificate maximum TTL as a Go duration string (vault.cert_ttl_max)."
  type        = string
  default     = null
}
