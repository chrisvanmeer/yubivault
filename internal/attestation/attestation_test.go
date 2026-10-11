package attestation

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
)

func newPool() *x509.CertPool { return x509.NewCertPool() }

func TestNormalizeCN(t *testing.T) {
	cases := map[string]string{
		"Chris":               "chris",
		"Chris@Example.com":   "chris",
		"alice.smith@corp.io": "alice.smith",
		"UPPER@lower":         "upper",
		"A+B@c":               "a+b",
		"":                    "",
	}
	for in, want := range cases {
		if got := NormalizeCN(in); got != want {
			t.Errorf("NormalizeCN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateCN(t *testing.T) {
	valid := []string{"chris", "alice.smith", "a+b", "a_b", "a-b", "a@b", "chris@example.com", strings.Repeat("a", 64)}
	for _, cn := range valid {
		if err := ValidateCN(cn); err != nil {
			t.Errorf("ValidateCN(%q) unexpected error: %v", cn, err)
		}
	}
	invalid := []string{"", "UPPER", "with space", "semi;colon", "a/b", "a\\b", `quote"x`, strings.Repeat("a", 65)}
	for _, cn := range invalid {
		if err := ValidateCN(cn); err == nil {
			t.Errorf("ValidateCN(%q) expected error, got nil", cn)
		}
	}
}

func TestRenderCN(t *testing.T) {
	cases := []struct {
		identity string
		email    string
		template string
		domain   string
		want     string
	}{
		{"chris", "chris@example.com", "{user}", "", "chris"},
		{"Chris", "Chris@Example.com", "{user}@{domain}", "example.com", "chris@example.com"},
		{"chris", "chris@example.com", "{user}.{domain}", "example.com", "chris.example.com"},
		{"chris", "Chris@Example.com", "{email}", "", "chris@example.com"},
		{"chris", "", "{email}", "", "chris"},
		{"chris", "chris@example.com", "vpn-{user}", "example.com", "vpn-chris"},
	}
	for _, c := range cases {
		got, err := RenderCN(c.identity, c.email, c.template, c.domain)
		if err != nil {
			t.Errorf("RenderCN(%q, %q, %q, %q) unexpected error: %v",
				c.identity, c.email, c.template, c.domain, err)
			continue
		}
		if got != c.want {
			t.Errorf("RenderCN(%q, %q, %q, %q) = %q, want %q",
				c.identity, c.email, c.template, c.domain, got, c.want)
		}
	}
}

func TestRenderCNRejectsBadTemplates(t *testing.T) {
	for _, tmpl := range []string{"", "{user}-{unknown}", "has space", "bad/slash"} {
		if _, err := RenderCN("chris", "chris@example.com", tmpl, "example.com"); err == nil {
			t.Errorf("RenderCN with template %q expected error, got nil", tmpl)
		}
	}
}

func TestValidateIdentity(t *testing.T) {
	if err := ValidateIdentity("Chris@Example.com"); err != nil {
		t.Errorf("Valid identity rejected: %v", err)
	}
	if err := ValidateIdentity("bad identity!"); err == nil {
		t.Error("identity with spaces should be rejected")
	}
}

func TestNewRequiresRootsAndKeyTypes(t *testing.T) {
	if _, err := New(Options{AllowedKeyTypes: []string{"rsa3072"}}); err == nil {
		t.Error("expected error when roots are missing")
	}
	if _, err := New(Options{Roots: newPool(), AllowedKeyTypes: nil}); err == nil {
		t.Error("expected error when no key types are allowed")
	}
	if _, err := New(Options{Roots: newPool(), AllowedKeyTypes: []string{"rsa3072"}}); err != nil {
		t.Errorf("unexpected error for valid options: %v", err)
	}
}

func TestLoadRoots(t *testing.T) {
	if _, err := LoadRoots(""); err == nil {
		t.Error("expected error for empty path")
	}
	if _, err := LoadRoots("/does/not/exist.pem"); err == nil {
		t.Error("expected error for missing file")
	}

	pool, err := LoadRoots(filepath.Join("..", "..", "yubico-roots.pem"))
	if err != nil {
		t.Fatalf("failed to load shipped Yubico roots: %v", err)
	}
	if pool == nil {
		t.Fatal("expected a non-nil pool")
	}
}
