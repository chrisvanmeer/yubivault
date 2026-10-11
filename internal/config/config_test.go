package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes a YAML file into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

// validConfig returns a minimal, valid configuration pointing at a real root
// file so Validate can stat it.
func validConfig(t *testing.T) *Config {
	t.Helper()
	root := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(root, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write roots: %v", err)
	}
	var c Config
	c.Server.SessionSecret = strings.Repeat("x", MinSessionSecretLen)
	c.Vault.Address = "https://vault.example.com"
	c.OIDC.Issuer = "https://idp.example.com"
	c.OIDC.ClientID = "client"
	c.OIDC.RedirectURL = "https://portal.example.com/callback"
	c.Yubico.RootCAFile = root
	c.applyDefaults()
	return &c
}

func TestLoadAppliesDefaults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(root, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write roots: %v", err)
	}
	path := writeConfig(t, `
server:
  listen_addr: "127.0.0.1:9000"
  session_secret: "`+strings.Repeat("y", 32)+`"
vault:
  address: "https://vault.example.com"
oidc:
  issuer: "https://idp.example.com"
  client_id: "client"
  redirect_url: "https://portal.example.com/callback"
yubico:
  root_ca_file: "`+root+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.UI.Title != "YubiVault Portal" {
		t.Errorf("default UI title not applied: %q", cfg.UI.Title)
	}
	if cfg.Vault.RevokeMode != RevokeModeStrict {
		t.Errorf("default revoke mode = %q, want %q", cfg.Vault.RevokeMode, RevokeModeStrict)
	}
	if cfg.Server.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("explicit listen address lost: %q", cfg.Server.ListenAddr)
	}
}

func TestValidateRejectsExampleSecret(t *testing.T) {
	c := validConfig(t)
	c.Server.SessionSecret = exampleSessionSecret
	if err := c.Validate(); err == nil {
		t.Fatal("expected the placeholder example secret to be rejected")
	}
}

func TestValidateRequiresCoreFields(t *testing.T) {
	c := validConfig(t)
	c.Vault.Address = ""
	c.OIDC.Issuer = ""
	c.OIDC.ClientID = ""
	c.OIDC.RedirectURL = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"vault.address", "oidc.issuer", "oidc.client_id", "oidc.redirect_url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestValidateRevokeMode(t *testing.T) {
	c := validConfig(t)
	c.Vault.RevokeMode = "yolo"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "revoke_mode") {
		t.Errorf("expected revoke_mode error, got %v", err)
	}

	c.Vault.RevokeMode = RevokeModeBestEffort
	if err := c.Validate(); err != nil {
		t.Errorf("best_effort should be valid: %v", err)
	}
}

func TestValidateTTL(t *testing.T) {
	c := validConfig(t)
	c.Vault.CertTTL = "not-a-duration"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cert_ttl") {
		t.Errorf("expected cert_ttl error, got %v", err)
	}

	c.Vault.CertTTL = "720h"
	c.Vault.CertTTLMax = "8760h"
	if err := c.Validate(); err != nil {
		t.Errorf("valid TTLs rejected: %v", err)
	}
}

func TestAllowedKeyTypes(t *testing.T) {
	var c Config
	if got := c.AllowedKeyTypes(); len(got) != 1 || got[0] != "rsa3072" {
		t.Errorf("default allowed key types = %v, want [rsa3072]", got)
	}

	c.Yubico.RSABits = 4096
	if got := c.AllowedKeyTypes(); len(got) != 1 || got[0] != "rsa4096" {
		t.Errorf("legacy rsa_bits mapping = %v, want [rsa4096]", got)
	}

	c.Yubico.KeyTypes = []string{"eccp256", "rsa3072"}
	if got := c.AllowedKeyTypes(); len(got) != 2 || got[0] != "eccp256" {
		t.Errorf("key_types override = %v, want [eccp256 rsa3072]", got)
	}
}

func TestValidateUnknownKeyType(t *testing.T) {
	c := validConfig(t)
	c.Yubico.KeyTypes = []string{"dsa1024"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dsa1024") {
		t.Errorf("expected unknown key type error, got %v", err)
	}
}

func TestYkmanAlgorithm(t *testing.T) {
	if algo, ok := YkmanAlgorithm("eccp384"); !ok || algo != "ECCP384" {
		t.Errorf("YkmanAlgorithm(eccp384) = %q, %v", algo, ok)
	}
	if _, ok := YkmanAlgorithm("nope"); ok {
		t.Error("unknown key type reported as supported")
	}
}

func TestRevokeExistingRequiresAppRole(t *testing.T) {
	c := validConfig(t)
	c.Vault.RevokeExisting = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "approle") {
		t.Errorf("expected approle requirement error, got %v", err)
	}
}

func TestLoggingDefaults(t *testing.T) {
	c := validConfig(t)
	if got := c.LogDir(); got != defaultLogDir {
		t.Errorf("default LogDir() = %q, want %q", got, defaultLogDir)
	}
	if got, want := c.LogFilePath(), filepath.Join(defaultLogDir, defaultLogFile); got != want {
		t.Errorf("default LogFilePath() = %q, want %q", got, want)
	}
	if c.Logging.Owner != defaultLogOwner || c.Logging.Group != defaultLogGroup {
		t.Errorf("default owner/group = %s:%s, want %s:%s",
			c.Logging.Owner, c.Logging.Group, defaultLogOwner, defaultLogGroup)
	}
	if c.LogDirExplicit() {
		t.Error("defaulted log dir should not be reported as explicit")
	}
}

func TestLoggingDisabledWithEmptyDir(t *testing.T) {
	c := validConfig(t)
	empty := ""
	c.Logging.Dir = &empty
	if got := c.LogDir(); got != "" {
		t.Errorf("LogDir() = %q, want empty (file logging disabled)", got)
	}
	if got := c.LogFilePath(); got != "" {
		t.Errorf("LogFilePath() = %q, want empty (file logging disabled)", got)
	}
}

func TestLoadLogDirExplicit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(root, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write roots: %v", err)
	}
	path := writeConfig(t, `
server:
  session_secret: "`+strings.Repeat("y", 32)+`"
vault:
  address: "https://vault.example.com"
oidc:
  issuer: "https://idp.example.com"
  client_id: "client"
  redirect_url: "https://portal.example.com/callback"
yubico:
  root_ca_file: "`+root+`"
logging:
  dir: "/var/log/custom"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.LogDirExplicit() {
		t.Error("explicit logging.dir should be reported as explicit")
	}
	if got := cfg.LogFilePath(); got != filepath.Join("/var/log/custom", defaultLogFile) {
		t.Errorf("LogFilePath() = %q", got)
	}
}

func TestValidateLoggingFileRejectsSeparators(t *testing.T) {
	c := validConfig(t)
	c.Logging.File = "logs/yubivault.log"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "logging.file") {
		t.Errorf("expected logging.file separator error, got %v", err)
	}
}

func TestCertificatesEnabledDefault(t *testing.T) {
	c := validConfig(t)
	if !c.CertificatesEnabled() {
		t.Error("certificate inventory page should be enabled by default")
	}
	disabled := false
	c.UI.CertificatesEnabled = &disabled
	if c.CertificatesEnabled() {
		t.Error("certificate inventory page should be disabled when configured")
	}
}

func TestValidateManualFile(t *testing.T) {
	c := validConfig(t)
	dir := t.TempDir()
	c.UI.ManualDir = dir
	if err := os.WriteFile(filepath.Join(dir, "manual.md"), []byte("# Manual"), 0o600); err != nil {
		t.Fatalf("failed to write manual: %v", err)
	}

	c.UI.ManualFile = "manual.txt"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "manual_file") {
		t.Errorf("expected manual_file extension error, got %v", err)
	}

	c.UI.ManualFile = "manual.md"
	if err := c.Validate(); err != nil {
		t.Errorf("valid markdown manual rejected: %v", err)
	}

	c.UI.ManualFile = "missing.pdf"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "manual_file") {
		t.Errorf("expected missing manual error, got %v", err)
	}
}

func TestValidateManuals(t *testing.T) {
	c := validConfig(t)
	dir := t.TempDir()
	c.UI.ManualDir = dir
	if err := os.WriteFile(filepath.Join(dir, "manual-windows.md"), []byte("# Windows"), 0o600); err != nil {
		t.Fatalf("failed to write manual: %v", err)
	}

	c.UI.Manuals = map[string]string{"windows": "manual-windows.md"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid per-OS manual rejected: %v", err)
	}

	c.UI.Manuals = map[string]string{"windows": "nope.PDF"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ui.manuals.windows") {
		t.Errorf("expected ui.manuals.windows error, got %v", err)
	}
}

func TestValidateManualDirRequired(t *testing.T) {
	c := validConfig(t)
	c.UI.ManualFile = "manual.md"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "manual_dir") {
		t.Errorf("expected manual_dir requirement error, got %v", err)
	}
}

func TestManualPath(t *testing.T) {
	c := validConfig(t)
	c.UI.ManualDir = "/srv/manuals"
	c.UI.ManualFile = "manual.md"
	c.UI.Manuals = map[string]string{"macos": "manual-macos.md", "abs": "/abs/manual.pdf"}

	if got, want := c.ManualPath("macos"), "/srv/manuals/manual-macos.md"; got != want {
		t.Errorf("ManualPath(macos) = %q, want %q", got, want)
	}
	if got, want := c.ManualPath("abs"), "/abs/manual.pdf"; got != want {
		t.Errorf("ManualPath(abs) = %q, want %q", got, want)
	}
	if got, want := c.ManualPath("windows"), "/srv/manuals/manual.md"; got != want {
		t.Errorf("ManualPath(fallback) = %q, want %q", got, want)
	}
	if got, want := c.ManualPath(""), "/srv/manuals/manual.md"; got != want {
		t.Errorf("ManualPath(empty) = %q, want %q", got, want)
	}

	files := c.ManualFiles()
	if got, want := files["macos"], "/srv/manuals/manual-macos.md"; got != want {
		t.Errorf("ManualFiles[macos] = %q, want %q", got, want)
	}
	if got, want := files["default"], "/srv/manuals/manual.md"; got != want {
		t.Errorf("ManualFiles[default] = %q, want %q", got, want)
	}
}
