# The platform stack sets up the parts that only change when your OIDC/Vault
# layout changes: the JWT auth backend and role, the signing/backend policies
# and (optionally) the portal AppRole. It does not touch the PKI engine.

variable "config_file" {
  description = "Path to config.yaml, relative to this stack directory."
  type        = string
  default     = "../../config.yaml"
}

# --- Optional overrides (win over config.yaml) -------------------------------

variable "vault_address" {
  description = "Override vault.address."
  type        = string
  default     = null
}

variable "pki_mount" {
  description = "Override vault.pki_mount."
  type        = string
  default     = null
}

variable "pki_role" {
  description = "Override vault.pki_role."
  type        = string
  default     = null
}

variable "auth_mount" {
  description = "Override vault.auth_mount."
  type        = string
  default     = null
}

variable "auth_role" {
  description = "Override vault.auth_role."
  type        = string
  default     = null
}

variable "approle_mount" {
  description = "Override vault.approle_mount."
  type        = string
  default     = null
}

variable "revoke_existing" {
  description = "Override vault.revoke_existing."
  type        = bool
  default     = null
}

variable "oidc_issuer" {
  description = "Override oidc.issuer."
  type        = string
  default     = null
}

variable "oidc_client_id" {
  description = "Override oidc.client_id."
  type        = string
  default     = null
}

variable "allowed_groups" {
  description = "Override oidc.allowed_groups."
  type        = list(string)
  default     = null
}

# --- Policy / role tuning ----------------------------------------------------

variable "jwt_user_claim" {
  description = "JWT claim used as the Vault identity alias name."
  type        = string
  default     = "preferred_username"
}

variable "sign_policy_prefix" {
  description = "Prefix for the per-group signing policies (pol-<group>)."
  type        = string
  default     = "pol-"
}

variable "fallback_sign_policy_name" {
  description = "Signing policy name used when no allowed groups are configured."
  type        = string
  default     = "pol-yubivault-user"
}

variable "backend_policy_name" {
  description = "Name of the AppRole/revocation policy."
  type        = string
  default     = "pol-yubivault-backend"
}

variable "approle_role_name" {
  description = "Name of the portal AppRole role."
  type        = string
  default     = "yubivault-portal"
}

variable "approle_token_ttl" {
  description = "AppRole token TTL in seconds (README uses 1h)."
  type        = number
  default     = 3600
}

variable "approle_token_max_ttl" {
  description = "AppRole token maximum TTL in seconds (README uses 4h)."
  type        = number
  default     = 14400
}
