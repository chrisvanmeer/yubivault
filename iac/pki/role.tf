# The signing role.
#
# This is the piece that must be recreated after every CA rotation. The allowed
# domain is an identity template that resolves to the OIDC user name, so the
# certificate is issued for the authenticated user's CN. Only the CN is allowed
# (no subdomains, no hostname enforcement, client use only).

resource "vault_pki_secret_backend_role" "this" {
  count = local.signed_available ? 1 : 0

  backend = vault_mount.pki_int.path
  name    = module.config.pki_role

  allowed_domains          = ["{{identity.entity.aliases.${var.jwt_auth_accessor}.name}}"]
  allowed_domains_template = true
  allow_bare_domains       = var.allow_bare_domains
  enforce_hostnames        = false
  allow_any_name           = false
  client_flag              = true
  server_flag              = false

  ttl     = module.config.cert_ttl_seconds
  max_ttl = module.config.cert_ttl_max_seconds

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.signed]
}
