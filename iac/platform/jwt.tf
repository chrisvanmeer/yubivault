# JWT/OIDC auth backend and the middleware role.
#
# Maps the README's:
#   vault auth enable -path=jwt-yubivault jwt
#   vault write auth/jwt-yubivault/config oidc_discovery_url=... default_role=...
#   vault write auth/jwt-yubivault/role/yubivault-middleware role_type=jwt \
#       user_claim=preferred_username bound_audiences=yubivault policies=...

resource "vault_jwt_auth_backend" "this" {
  path               = module.config.auth_mount
  type               = "jwt"
  description        = "YubiVault delegated signing (managed by IaC)"
  oidc_discovery_url = module.config.oidc_issuer
  default_role       = module.config.auth_role
}

resource "vault_jwt_auth_backend_role" "middleware" {
  backend         = vault_jwt_auth_backend.this.path
  role_name       = module.config.auth_role
  role_type       = "jwt"
  user_claim      = var.jwt_user_claim
  bound_audiences = [module.config.oidc_client_id]
  token_policies  = local.sign_policy_names
}
