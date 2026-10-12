# Vault provider configuration. The address comes from config.yaml when
# present, otherwise VAULT_ADDR is used. Authentication uses VAULT_TOKEN (or
# ~/.vault-token); no token is stored in this repository.

provider "vault" {
  address = module.config.vault_address
}

provider "local" {}
