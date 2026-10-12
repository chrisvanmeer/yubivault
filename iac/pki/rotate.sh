#!/usr/bin/env bash
#
# Guided PKI rotation for YubiVault.
#
# Two-phase flow for an offline / airgapped root:
#   phase 1: (re)create the mount and generate a fresh intermediate CSR
#   phase 2: import the offline-signed intermediate and (re)create the role
#
# Usage:
#   ./rotate.sh [rekey|recreate]
#
#   rekey    (default) rotate the intermediate in place; the mount is kept
#   recreate replace the whole PKI mount (all cert records are wiped)
#
# Run `tofu init` / `terraform init` once before using this script.

set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-rekey}"
case "$MODE" in
  rekey)    ;;
  recreate) ;;
  *)
    echo "usage: $0 [rekey|recreate]" >&2
    exit 2
    ;;
esac

if command -v tofu >/dev/null 2>&1; then
  TF="tofu"
elif command -v terraform >/dev/null 2>&1; then
  TF="terraform"
else
  echo "error: neither 'tofu' nor 'terraform' was found in PATH" >&2
  exit 1
fi

if [[ ! -f .terraform.lock.hcl ]]; then
  echo ">> No provider lock file yet; running '$TF init' first..."
  "$TF" init
fi

ACCESSOR="$("$TF" -chdir=../platform output -raw jwt_auth_accessor)"
TOKEN="$(date -u +%Y%m%dT%H%M%SZ)"

# In recreate mode the whole mount is replaced explicitly; in rekey mode the
# token change alone rotates the intermediate key on the existing mount.
REPLACE=()
if [[ "$MODE" == "recreate" ]]; then
  REPLACE=(-replace="vault_mount.pki_int")
fi

echo ">> Rotating PKI (mode=$MODE, token=$TOKEN)"
echo ">> Removing any previous signed intermediate so it cannot be reused."
rm -f generated/intermediate-signed.pem

echo ">> Phase 1: (re)creating the mount and generating a new intermediate CSR..."
"$TF" apply "${REPLACE[@]+"${REPLACE[@]}"}" \
  -var "rotation_token=$TOKEN" \
  -var "jwt_auth_accessor=$ACCESSOR"

echo
echo ">> A new CSR is at:"
echo "     ${PWD}/generated/intermediate.csr"
echo
echo ">> Sign it on the airgapped root (for example, on the root Vault):"
echo "     vault write -format=json <root-pki>/root/sign-intermediate \\"
echo "       csr=@generated/intermediate.csr common_name=\"YubiVault Intermediate CA\" \\"
echo "       ttl=<intermediate-ttl> | jq -r .data.certificate > generated/intermediate-signed.pem"
echo
echo ">> Save the signed certificate as:"
echo "     ${PWD}/generated/intermediate-signed.pem"
echo
read -r -p ">> Press ENTER once the signed intermediate is in place (Ctrl-C to abort)... "

if [[ ! -s generated/intermediate-signed.pem ]]; then
  echo "error: generated/intermediate-signed.pem is missing or empty; aborting" >&2
  exit 1
fi

echo ">> Phase 2: importing the signed intermediate and (re)creating the role..."
"$TF" apply \
  -var "rotation_token=$TOKEN" \
  -var "jwt_auth_accessor=$ACCESSOR"

echo ">> Rotation complete."
