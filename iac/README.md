# YubiVault Infrastructure as Code

This directory codifies the HashiCorp Vault / OpenBao setup that the
[README](../README.md) describes in its *HashiCorp Vault Prerequisites* section,
using plain HCL that runs with both **OpenTofu** (`tofu`) and **Terraform**
(`terraform`).

It is split into two stacks:

- `platform/` — the parts that only change when your OIDC/Vault layout changes:
  the JWT auth backend and role, the signing and backend policies, and the
  optional portal AppRole.
- `pki/` — the rotatable PKI material: the intermediate mount, the intermediate
  key/CSR, the offline-signed intermediate, and the signing role. This is the
  stack an engineer re-runs every *N* days.

All values are read from the repository's `config.yaml` (overridable per stack
via variables), so the role keeps the exact `allowed_domains` and validity
settings the portal expects after every rotation.

## Directory layout

```text
iac/
├── README.md
├── Makefile
├── modules/config/           # shared config.yaml reader (no providers)
├── platform/                 # one-time auth/policy setup
│   ├── versions.tf
│   ├── providers.tf
│   ├── variables.tf
│   ├── locals.tf
│   ├── jwt.tf
│   ├── policies.tf
│   ├── approle.tf
│   ├── outputs.tf
│   └── terraform.tfvars.example
└── pki/                      # rotatable PKI material
    ├── versions.tf
    ├── providers.tf
    ├── variables.tf
    ├── locals.tf
    ├── mount.tf
    ├── intermediate.tf
    ├── role.tf
    ├── outputs.tf
    ├── rotate.sh
    ├── generated/            # CSR + signed intermediate (git-ignored)
    └── terraform.tfvars.example
```

## Prerequisites

- **OpenTofu** or **Terraform** >= 1.3.
- Network access to the Vault/OpenBao server during `init`/`apply`.
- A Vault token with permission to manage auth backends, policies and the PKI
  mount. Export it before running, for example:

  ```bash
  export VAULT_ADDR="https://vault.example.com"
  export VAULT_TOKEN="hvs...."
  ```

  The address is taken from `config.yaml` (`vault.address`); `VAULT_ADDR` is
  used only when that key is absent. Tokens are never written to any file in
  this repository.

- The root CA that signs the intermediate lives **offline / airgapped**. IaC
  generates the intermediate CSR; you sign it offline and import the result.

## How config.yaml is used

The shared `modules/config` module reads `../../config.yaml` (relative to each
stack) and applies this precedence:

```text
explicit variable  >  config.yaml  >  built-in default
```

| config.yaml key          | used for                                              |
| ------------------------ | ----------------------------------------------------- |
| `vault.address`          | Vault provider address                                |
| `vault.pki_mount`        | PKI mount path                                        |
| `vault.pki_role`         | PKI role name                                         |
| `vault.auth_mount`       | JWT auth backend path                                 |
| `vault.auth_role`        | JWT auth role name and `default_role`                 |
| `vault.approle_mount`    | AppRole auth backend path                             |
| `vault.revoke_existing`  | whether the AppRole and backend policy are created    |
| `vault.cert_ttl`         | PKI role `ttl` (Go duration, converted to seconds)    |
| `vault.cert_ttl_max`     | PKI role `max_ttl` (Go duration, converted to seconds)|
| `oidc.issuer`            | JWT `oidc_discovery_url`                              |
| `oidc.client_id`         | JWT `bound_audiences`                                 |
| `oidc.allowed_groups`    | one signing policy per group, named `pol-<group>`     |

`vault.cert_ttl` and `vault.cert_ttl_max` accept a single-unit Go duration
(`s`, `m`, `h`, `d`) or a bare number of seconds. Compound durations such as
`1h30m` are not converted; use the equivalent seconds (for example `5400`)
instead, since Vault's role takes whole seconds.

Secrets in `config.yaml` (`server.session_secret`, `vault.approle_secret_id`,
`oidc.client_secret`) are intentionally **never** read. The committed
`terraform.tfvars.example` files use `example.com` placeholders only.

## Platform stack

One-time setup; re-run it only when the OIDC or Vault layout changes.

```bash
cd platform
tofu init
tofu plan
tofu apply
```

This creates the JWT auth backend and role, one signing policy per allowed
group (`pol-<group>`, or `pol-yubivault-user` when no groups are configured),
and — when `revoke_existing` is enabled — the backend policy, the AppRole
backend, its role and a fresh SecretID.

Useful outputs:

```bash
tofu output -raw jwt_auth_accessor          # needed by the pki stack
tofu output -json sign_policy_names
tofu output -raw approle_role_id            # sensitive
tofu output -raw approle_secret_id          # sensitive
```

## PKI stack and the N-day rotation

The `pki/` stack owns the intermediate mount, the intermediate key/CSR, the
signed intermediate and the signing role. Rotation is manual and driven by
`rotate.sh`; nothing rotates on a timer.

### How a rotation works

1. Rotate the intermediate key material by running the guided script.
2. The script generates a fresh CSR and writes it to `pki/generated/intermediate.csr`.
3. You sign that CSR on the airgapped root.
4. You save the signed certificate as `pki/generated/intermediate-signed.pem`.
5. The script imports it and (re)creates the signing role with the
   `allowed_domains` template and validity from `config.yaml`.

Vault refuses a signed certificate that does not match the mount's private key,
so a stale or mismatched file fails loudly instead of producing a broken CA.

### Guided rotation

```bash
cd pki
tofu init                 # once

# rekey (default): rotate the intermediate in place, keep the mount and role
./rotate.sh rekey

# recreate: replace the whole pki_int mount (wipes cert records; role recreated)
./rotate.sh recreate
```

Both modes ask you to press ENTER after you have placed the signed intermediate.

### Rekey versus recreate

- `rekey` rotates the intermediate key on the existing mount by changing
  `rotation_token`; the mount and its certificate records are kept. Best on
  Vault 1.11+ (multi-issuer).
- `recreate` replaces the entire mount explicitly with
  `-replace=vault_mount.pki_int`. All issued certificate records and the CRL are
  wiped, and the role is recreated from scratch. Use this when you want a clean
  mount every cycle.

### Manual rotation

If you prefer to drive it yourself, change `rotation_token` and apply twice. For
a rekey (mount kept):

```bash
ACCESSOR="$(tofu -chdir=../platform output -raw jwt_auth_accessor)"

tofu apply \
  -var "rotation_token=$(date -u +%Y%m%dT%H%M%SZ)" \
  -var "jwt_auth_accessor=$ACCESSOR"

# ... sign pki/generated/intermediate.csr offline ...

tofu apply -var "jwt_auth_accessor=$ACCESSOR"
```

For a full recreate, add `-replace=vault_mount.pki_int` to the first apply and
remove `pki/generated/intermediate-signed.pem` beforehand:

```bash
rm -f pki/generated/intermediate-signed.pem

tofu apply -replace=vault_mount.pki_int \
  -var "rotation_token=$(date -u +%Y%m%dT%H%M%SZ)" \
  -var "jwt_auth_accessor=$ACCESSOR"

# ... sign pki/generated/intermediate.csr offline ...

tofu apply -var "jwt_auth_accessor=$ACCESSOR"
```

The first apply creates the mount and the CSR and skips the role (no signed
intermediate yet). The second apply imports the signed certificate and creates
the role.

## Importing an existing Vault

If Vault already has these objects (for example a running installation), import
them once before the first `apply` so Terraform adopts instead of recreates
them. Replace the example names with your own values.

```bash
# platform
tofu -chdir=platform import 'vault_jwt_auth_backend.this'                 'jwt-yubivault'
tofu -chdir=platform import 'vault_jwt_auth_backend_role.middleware'      'auth/jwt-yubivault/role/yubivault-middleware'
tofu -chdir=platform import 'vault_policy.signer["pol-yubivault-users"]'  'pol-yubivault-users'
tofu -chdir=platform import 'vault_policy.backend[0]'                     'pol-yubivault-backend'
tofu -chdir=platform import 'vault_auth_backend.approle[0]'               'approle'
tofu -chdir=platform import 'vault_approle_auth_backend_role.portal[0]'   'auth/approle/role/yubivault-portal'

# pki
tofu -chdir=pki import 'vault_mount.pki_int'                  'pki_int'
tofu -chdir=pki import 'vault_pki_secret_backend_role.this[0]' 'pki_int/roles/yubivault'
```

The AppRole SecretID cannot be imported meaningfully; let Vault issue a new one
by keeping the `vault_approle_auth_backend_role_secret_id` resource.

## Make targets

A small `Makefile` wraps the common commands. It uses `tofu` by default; pass
`TF=terraform` to switch.

```bash
make platform-apply
make pki-plan
make rotate-rekey
make rotate-recreate
```

## OpenTofu and Terraform

- The same files work with both tools; run `tofu` or `terraform` interchangeably.
- The provider source (`hashicorp/vault`, `hashicorp/local`) resolves through
  the OpenTofu registry mirror too.
- `.terraform.lock.hcl` and all state files are git-ignored because the
  provider hashes can differ between the two registries.
- State may contain the AppRole credentials, so store it securely and do not
  commit it.

## Notes and caveats

- Rotating with `recreate` briefly removes the `pki_int` mount (Vault cannot
  host two mounts at the same path), so issuance is unavailable for a moment.
- After a rotation, relying parties must trust the root, not a fixed
  intermediate. Distribute the new intermediate chain to the VPN/verification
  endpoint if it pins the intermediate.
- Certificates issued under a previous intermediate remain valid until they
  expire, but can no longer be revoked through the mount if it was recreated.
