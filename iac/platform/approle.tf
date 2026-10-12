# AppRole used by the portal for certificate inventory and revocation.
#
# Maps the README's:
#   vault auth enable approle
#   vault write auth/approle/role/yubivault-portal secret_id_ttl=0 \
#       token_num_uses=0 token_ttl=1h token_max_ttl=4h secret_id_num_uses=0 \
#       policies=pol-yubivault-backend
#
# Created only when vault.revoke_existing is enabled.

resource "vault_auth_backend" "approle" {
  count = module.config.revoke_existing ? 1 : 0

  type = "approle"
  path = module.config.approle_mount
}

resource "vault_approle_auth_backend_role" "portal" {
  count = module.config.revoke_existing ? 1 : 0

  backend   = vault_auth_backend.approle[0].path
  role_name = var.approle_role_name

  token_policies = [vault_policy.backend[0].name]

  token_ttl          = var.approle_token_ttl
  token_max_ttl      = var.approle_token_max_ttl
  token_num_uses     = 0
  secret_id_ttl      = 0
  secret_id_num_uses = 0
}

# Generates a fresh SecretID. The role_id and secret_id are exposed as
# sensitive outputs so they can be dropped into config.yaml.
resource "vault_approle_auth_backend_role_secret_id" "portal" {
  count = module.config.revoke_existing ? 1 : 0

  backend   = vault_auth_backend.approle[0].path
  role_name = vault_approle_auth_backend_role.portal[0].role_name
}
