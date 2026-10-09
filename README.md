# YubiVault

YubiVault is an airgapped **Validation Middleware & Vault Delegation Proxy** for issuing OpenVPN client certificates. It enforces hardware-backed cryptographic origin by verifying that a Certificate Signing Request (CSR) was generated directly inside a physical YubiKey (Slot `9a` or `9c`) using YubiKey PIV Attestation before delegating the signing request to HashiCorp Vault / OpenBao.

---

## Features

- **Hardware Attestation Verification**: Parses Yubico ASN.1 Key Origin OIDs (`1.3.6.1.4.1.41482.3.3...`) to prove keys were generated on-device and never exported or created in software.
- **Flexible PIV Slot Selection**: Supports both Slot `9a` (Authentication) and Slot `9c` (Digital Signature) with dynamically updated client terminal commands.
- **Automatic Cert Revocation**: Optional `revoke_existing` mode that safely identifies and revokes prior active, unexpired certificates matching the user's Common Name before issuing a new certificate.
- **Yubico Root CA Chain Validation**: Validates the YubiKey attestation certificate chain against official Yubico Root CAs.
- **OIDC Authentication & Delegation**: Authenticates users via OIDC (Keycloak, Entra ID, Authelia, Okta) and exchanges the user's raw ID token with Vault JWT auth, maintaining strict Vault entity alias mapping.
- **Customizable Branding**: Configurable application title and short title via `config.yaml`.
- **Systemd Management**: Built-in `--install` and `--uninstall` flags for automated systemd service management and production deployment to `/etc/yubivault` and `/usr/local/bin/yubivault`.
- **Airgapped Design**: Dependencies (HTMX, Tailwind CSS, Favicon, Yubico Root CAs) are served entirely locally without third-party CDNs or runtime internet access.
- **Dark Mode Support**: Automatic OS theme detection with manual light/dark toggle and `localStorage` persistence.

---

## Directory Structure

### Development Layout

Ensure your project tree matches the following layout before compiling:

```text
.
├── config.yaml               # Operational configuration
├── go.mod                    # Go module definition
├── go.sum                    # Go module checksums
├── server.go                 # Main application logic
├── input.css                 # Tailwind CSS v4 entrypoint
├── yubico-roots.pem          # Combined official Yubico Root CAs
├── templates/
│   └── index.html            # HTMX + Tailwind UI template
└── static/
    ├── favicon.svg           # Portal favicon
    ├── htmx.min.js           # Airgapped HTMX library
    └── tailwind.css          # Compiled Tailwind CSS output
```

### Production Service Layout (`/etc/yubivault/`)

When installed via `sudo ./yubivault --install`, the binary is copied to `/usr/local/bin/yubivault` and runtime files are staged at `/etc/yubivault/`:

```text
/etc/yubivault/
├── config.yaml
├── yubico-roots.pem
├── templates/
│   └── index.html
└── static/
    ├── favicon.svg
    ├── htmx.min.js
    └── tailwind.css
```

---

## Prerequisites

- **Go**: Version 1.22 or higher
- **YubiKey Manager CLI (`ykman`)**: Installed on client machines
- **HashiCorp Vault / OpenBao**: Configured with PKI secrets engine & JWT/OIDC auth engine
- **OIDC Provider**: Keycloak, Entra ID, Authelia, or Okta

---

## Setup & Installation

### 1. Initialize Go Module & Dependencies

```bash
go mod init yubivault
go mod tidy
```

### 2. Download Airgapped Assets

#### A. HTMX Library & Favicon

```bash
mkdir -p static
curl -L -o static/htmx.min.js https://unpkg.com/htmx.org@4/dist/htmx.min.js
```

Create `static/favicon.svg`:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" fill="#2563eb" fill-opacity="0.15"/>
  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  <circle cx="12" cy="16" r="1.5" fill="#2563eb"/>
</svg>
```

#### B. Yubico Root & Intermediate CAs

```bash
curl -sL \
  https://developers.yubico.com/PKI/yubico-piv-ca-1.pem \
  https://developers.yubico.com/PKI/yubico-ca-1.pem \
  https://developers.yubico.com/PKI/yubico-intermediate.pem \
  > yubico-roots.pem
```

---

### 3. Build Airgapped Tailwind CSS (v4)

#### A. Create `input.css`

```bash
cat <<EOF> input.css
@import "tailwindcss";

@custom-variant dark (&:where(.dark, .dark *));
EOF
```

#### B. Download Tailwind CLI & Compile

- **macOS ARM64 (Apple Silicon):**

  ```bash
  curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-macos-arm64
  chmod +x tailwindcss-macos-arm64
  ./tailwindcss-macos-arm64 -i input.css -o ./static/tailwind.css --content="./templates/*.html" --content="./server.go" --minify
  ```

- **Linux x86_64:**

  ```bash
  curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
  chmod +x tailwindcss-linux-x64
  ./tailwindcss-linux-x64 -i input.css -o ./static/tailwind.css --content="./templates/*.html" --content="./server.go" --minify
  ```

---

## Configuration (`config.yaml`)

Create `config.yaml` in the project root or `/etc/yubivault/config.yaml`:

```yaml
server:
  listen_addr: "127.0.0.1:8080"
  session_secret: "super-secret-32-byte-key-here!!"
  # debug: true -> defaults to false

ui:
  title: "YubiVault Portal"
  short_title: "YBV"

vault:
  address: "https://vault.example.com"
  pki_mount: "pki_int"
  pki_role: "yubivault"
  auth_mount: "jwt-yubivault"
  auth_role: "yubivault-middleware"
  # revoke_existing: true -> defaults to false

oidc:
  issuer: "https://idp.example.com/realms/master"
  client_id: "yubivault"
  client_secret: "your-oidc-client-secret"
  redirect_url: "http://127.0.0.1:18080/callback"

yubico:
  root_ca_file: "yubico-roots.pem"
  # rsa_bits: 2048 -> defaults to 3072
```

---

## HashiCorp Vault Prerequisites

Ensure Vault has the JWT auth backend enabled and configured to accept OIDC tokens from your provider, along with proper PKI permissions.

### 1. Configure JWT Auth Engine

```bash
# Enable JWT auth engine
vault auth enable -path=jwt-yubivault jwt

# Configure JWT endpoint
vault write auth/jwt-yubivault/config \
    oidc_discovery_url="https://idp.example.com/realms/master" \
    default_role="yubivault-middleware"

# Define JWT role mapping
vault write auth/jwt-yubivault/role/yubivault-middleware \
    role_type="jwt" \
    user_claim="preferred_username" \
    bound_audiences="yubivault" \
    policies="pol-testers"
```

### 2. Configure PKI Engine & Role

```bash
# Define PKI role with Identity Templating
vault write pki_int/roles/yubivault \
    allowed_domains="{{identity.entity.aliases.auth_jwt_0429de2e.name}}" \
    allowed_domains_template=true \
    allow_bare_domains=true \
    enforce_hostnames=false \
    allow_any_name=false \
    client_flag=true \
    server_flag=false
```

*(Note: Replace `auth_jwt_0429de2e` with your Vault JWT auth mount accessor ID obtained via `vault auth list`).*

### 3. Vault Policy (`pol-testers`)

Ensure the Vault policy allows signing, listing, reading, and revoking certificates:

```hcl
path "pki_int/sign/yubivault" {
  capabilities = ["create", "update"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}
```

---

## Running & Managing the Application

### Local Development

```bash
go run server.go
```

Access the portal in your browser at `http://127.0.0.1:8080/`.

### Systemd Service Installation (Production)

To install YubiVault as a managed systemd service:

```bash
# Compile binary
go build -o yubivault server.go

# Install systemd service and stage configuration/assets in /etc/yubivault/
sudo ./yubivault --install
```

To remove the service:

```bash
sudo ./yubivault --uninstall
```

---

## Client Usage Instructions

End users perform the following steps to request an attested certificate:

1. **Insert YubiKey** into the workstation.
2. **Select PIV Slot** in the portal UI (`Slot 9a` for Authentication or `Slot 9c` for Digital Signature).
3. **Execute Terminal Commands** shown in Step 2 of the portal:

   ```bash
   # 1. Generate RSA key pair in chosen slot (e.g. 9a)
   ykman piv keys generate 9a public.pem -a RS3072

   # 2. Generate Certificate Signing Request
   ykman piv certificates request 9a public.pem user.csr -s "CN=username"

   # 3. Generate Hardware Attestation Certificate
   ykman piv keys attest 9a attest.crt

   # 4. Export YubiKey Attestation Intermediate Certificate
   ykman piv certificates export f9 intermediate.crt
   ```

4. **Upload Files & Submit**: Drag & drop `user.csr`, `attest.crt`, and `intermediate.crt` into Step 3 upload zones, then click **Verify & Issue Certificate**.
5. **Confirm Revocation Warning** (if prompted by modal when `revoke_existing` is enabled).
6. **Download Certificate & Import**:
   - Download the issued `user.crt` into the **same working directory** where terminal commands were run.
   - Run the import command provided in the success modal:

     ```bash
     ykman piv certificates import 9a user.crt -v -m <mgmt key> -P <pin>
     ```
