package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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

func TestDeviceInfo(t *testing.T) {
	serialDER, err := asn1.Marshal(big.NewInt(12345678))
	if err != nil {
		t.Fatalf("marshal serial: %v", err)
	}
	fwDER, err := asn1.Marshal([]byte{5, 4, 3})
	if err != nil {
		t.Fatalf("marshal firmware: %v", err)
	}

	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{Id: yubicoSerialOID, Value: serialDER},
			{Id: yubicoFirmwareOID, Value: fwDER},
		},
	}
	serial, firmware := DeviceInfo(cert)
	if serial != "12345678" {
		t.Errorf("serial = %q, want 12345678", serial)
	}
	if firmware != "5.4.3" {
		t.Errorf("firmware = %q, want 5.4.3", firmware)
	}
}

func TestDeviceInfoRawFirmware(t *testing.T) {
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{Id: yubicoFirmwareOID, Value: []byte{5, 4, 3}},
		},
	}
	if _, fw := DeviceInfo(cert); fw != "5.4.3" {
		t.Errorf("raw firmware = %q, want 5.4.3", fw)
	}
}

func TestDeviceInfoMissingExtensions(t *testing.T) {
	cert := &x509.Certificate{}
	serial, firmware := DeviceInfo(cert)
	if serial != "" || firmware != "" {
		t.Errorf("expected empty device info, got %q / %q", serial, firmware)
	}
}

func TestParseVersion(t *testing.T) {
	valid := []struct {
		in   string
		want version
	}{
		{"5.4.3", version{5, 4, 3}},
		{"2.4.4", version{2, 4, 4}},
		{"0.0.0", version{0, 0, 0}},
		{"255.255.255", version{255, 255, 255}},
	}
	for _, tc := range valid {
		got, ok := parseVersion(tc.in)
		if !ok || got != tc.want {
			t.Errorf("parseVersion(%q) = (%v, %v), want (%v, true)", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []string{"", "5.4", "5.4.3.1", "a.b.c", "256.0.0", "-1.0.0", "5.4.x"} {
		if got, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) = (%v, true), want failure", in, got)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b version
		want bool
	}{
		{version{5, 4, 3}, version{5, 4, 4}, true},
		{version{5, 4, 3}, version{5, 5, 0}, true},
		{version{5, 4, 3}, version{6, 0, 0}, true},
		{version{5, 4, 3}, version{5, 4, 3}, false},
		{version{6, 0, 0}, version{5, 9, 9}, false},
	}
	for _, c := range cases {
		if got := c.a.less(c.b); got != c.want {
			t.Errorf("%v.less(%v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestEnforceDevicePolicy(t *testing.T) {
	minFW := version{5, 4, 3}

	withFW := &Verifier{minVersion: &minFW}
	if err := withFW.enforceDevicePolicy("", "5.4.2"); err == nil {
		t.Error("firmware below the minimum must be rejected")
	}
	if err := withFW.enforceDevicePolicy("", "5.4.3"); err != nil {
		t.Errorf("firmware at the minimum should pass: %v", err)
	}
	if err := withFW.enforceDevicePolicy("", "5.5.0"); err != nil {
		t.Errorf("firmware above the minimum should pass: %v", err)
	}
	if err := withFW.enforceDevicePolicy("", ""); err == nil {
		t.Error("missing firmware must fail closed when a minimum is set")
	}

	withSerial := &Verifier{minSerial: big.NewInt(10000000)}
	if err := withSerial.enforceDevicePolicy("9999999", ""); err == nil {
		t.Error("serial below the minimum must be rejected")
	}
	if err := withSerial.enforceDevicePolicy("10000000", ""); err != nil {
		t.Errorf("serial at the minimum should pass: %v", err)
	}
	if err := withSerial.enforceDevicePolicy("", ""); err == nil {
		t.Error("missing serial must fail closed when a minimum is set")
	}

	noPolicy := &Verifier{}
	if err := noPolicy.enforceDevicePolicy("", ""); err != nil {
		t.Errorf("with no minimums any device should pass: %v", err)
	}
}

func TestFingerprintOf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fp := FingerprintOf(&key.PublicKey)
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint %q must start with sha256:", fp)
	}
	if len(fp) != len("sha256:")+64 {
		t.Errorf("fingerprint %q has unexpected length %d", fp, len(fp))
	}
	if FingerprintOf(&key.PublicKey) != fp {
		t.Error("fingerprint must be stable for the same key")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	if FingerprintOf(&other.PublicKey) == fp {
		t.Error("different keys must produce different fingerprints")
	}
	if got := FingerprintOf("not a key"); got != "" {
		t.Errorf("unencodable key should yield an empty fingerprint, got %q", got)
	}
}
