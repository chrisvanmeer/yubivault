# Policies.
#
# The signing policy is attached to the JWT role above (one per allowed group).
# The backend policy is attached to the portal AppRole and only grants the
# inventory/revocation endpoints, never signing.

resource "vault_policy" "signer" {
  for_each = toset(local.sign_policy_names)

  name = each.value

  policy = <<-EOT
    # YubiVault: delegate signing to the authenticated OIDC user.
    path "${module.config.pki_mount}/sign/${module.config.pki_role}" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_policy" "backend" {
  count = module.config.revoke_existing ? 1 : 0

  name = var.backend_policy_name

  policy = <<-EOT
    # YubiVault: certificate inventory and revocation via the portal AppRole.
    path "${module.config.pki_mount}/certs" {
      capabilities = ["list"]
    }

    path "${module.config.pki_mount}/cert/*" {
      capabilities = ["read"]
    }

    path "${module.config.pki_mount}/revoke" {
      capabilities = ["create", "update"]
    }
  EOT
}
