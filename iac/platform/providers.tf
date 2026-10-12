# Vault provider configuration.
#
# The address is taken from config.yaml when present, otherwise VAULT_ADDR is
# used. The token is never stored here: export VAULT_TOKEN (or let the client
# read ~/.vault-token) before running plan/apply.

provider "vault" {
  address = module.config.vault_address
}
