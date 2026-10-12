# The pki stack manages the rotatable PKI material: the intermediate mount, the
# intermediate key/CSR, the signed intermediate and the signing role. Run the
# guided rotation with ./rotate.sh, or drive it manually.

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

variable "cert_ttl" {
  description = "Override vault.cert_ttl (Go duration string, e.g. \"720h\")."
  type        = string
  default     = null
}

variable "cert_ttl_max" {
  description = "Override vault.cert_ttl_max (Go duration string, e.g. \"8760h\")."
  type        = string
  default     = null
}

# --- Rotation wiring ---------------------------------------------------------

variable "jwt_auth_accessor" {
  description = "Accessor of the JWT auth mount (output of the platform stack). Used in the allowed_domains identity template."
  type        = string
}

variable "rotation_token" {
  description = "Opaque value; change it (e.g. to a timestamp) to trigger a rotation on the next apply."
  type        = string
  default     = "initial"
}

variable "csr_output_file" {
  description = "Where the generated intermediate CSR is written, relative to this stack."
  type        = string
  default     = "generated/intermediate.csr"
}

variable "signed_intermediate_file" {
  description = "Path to the offline-signed intermediate certificate (PEM), relative to this stack."
  type        = string
  default     = "generated/intermediate-signed.pem"
}

# --- Intermediate / mount tuning ---------------------------------------------

variable "intermediate_common_name" {
  description = "Common Name of the intermediate CA."
  type        = string
  default     = "YubiVault Intermediate CA"
}

variable "intermediate_key_type" {
  description = "Intermediate key type."
  type        = string
  default     = "rsa"
}

variable "intermediate_key_bits" {
  description = "Intermediate key size in bits (rsa)."
  type        = number
  default     = 4096
}

variable "mount_default_lease_ttl_seconds" {
  description = "Default lease TTL of the PKI mount, in seconds."
  type        = number
  default     = 31536000
}

variable "mount_max_lease_ttl_seconds" {
  description = "Maximum lease TTL of the PKI mount, in seconds. Must be >= the role max_ttl."
  type        = number
  default     = 315360000
}

variable "allow_bare_domains" {
  description = "Allow certificates whose CN exactly matches an allowed domain."
  type        = bool
  default     = true
}
