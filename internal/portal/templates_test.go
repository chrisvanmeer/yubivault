package portal

import (
	"bytes"
	"html/template"
	"os"
	"testing"
	"time"

	"yubivault/internal/pki"
)

func parseTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.ParseFS(os.DirFS("../.."), "templates/*.html")
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}
	return tmpl
}

func render(t *testing.T, tmpl *template.Template, name string, data any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("template %s failed to execute: %v", name, err)
	}
	return buf.String()
}

func indexData(loggedIn bool) map[string]any {
	return map[string]any{
		"IsLoggedIn":          loggedIn,
		"UserIdentity":        "Chris@Example.com",
		"CertCN":              "chris",
		"KeyTypes":            []keyTypeChoice{{Name: "eccp256", Ykman: "ECCP256", Label: "ECC P-256", Detail: "Fast"}, {Name: "rsa3072", Ykman: "RSA3072", Label: "RSA 3072", Detail: "Compatible"}},
		"UITitle":             "YubiVault Portal",
		"UIShortTitle":        "YBV",
		"RevokeExisting":      true,
		"SingleKeyType":       false,
		"HasAppRole":          true,
		"CertificatesEnabled": true,
	}
}

func TestTemplatesParse(t *testing.T) {
	tmpl := parseTemplates(t)
	for _, name := range []string{"index.html", "cert_modal.html", "confirm_revoke.html", "inventory.html", "manual_modal"} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("template %s is not registered", name)
		}
	}
}

func TestRenderManualModal(t *testing.T) {
	tmpl := parseTemplates(t)

	md := render(t, tmpl, "manual_modal", map[string]any{
		"ManualAvailable": true,
		"ManualSelected":  "macos",
		"ManualDocs": []manualDoc{
			{Key: "macos", Label: "macOS", HTML: template.HTML("<h1>Hello</h1>"), URL: "/manual/raw?os=macos"},
			{Key: "windows", Label: "Windows", IsPDF: true, URL: "/manual/raw?os=windows"},
		},
	})
	for _, want := range []string{"manual-modal", "Hello", "markdown-body", ">macOS<", ">Windows<", "/manual/raw?os=macos", "download=1"} {
		if !bytes.Contains([]byte(md), []byte(want)) {
			t.Errorf("manual modal missing %q", want)
		}
	}

	pdf := render(t, tmpl, "manual_modal", map[string]any{
		"ManualAvailable": true,
		"ManualSelected":  "default",
		"ManualDocs": []manualDoc{
			{Key: "default", Label: "Manual", IsPDF: true, URL: "/manual/raw?os=default"},
		},
	})
	if !bytes.Contains([]byte(pdf), []byte("<iframe")) {
		t.Error("pdf manual modal should embed the document in an iframe")
	}

	none := render(t, tmpl, "manual_modal", map[string]any{"ManualAvailable": false})
	if bytes.Contains([]byte(none), []byte("manual-modal")) {
		t.Error("manual modal should not render when unavailable")
	}
}

func TestRenderIndex(t *testing.T) {
	tmpl := parseTemplates(t)

	loggedOut := render(t, tmpl, "index.html", indexData(false))
	if !bytes.Contains([]byte(loggedOut), []byte("/login")) {
		t.Error("logged-out index should offer the login link")
	}

	loggedIn := render(t, tmpl, "index.html", indexData(true))
	for _, want := range []string{"CN=chris", "ECCP256", "RSA3072", "selected-keytype-input", "/certs", `const CERT_CN = "chris";`} {
		if !bytes.Contains([]byte(loggedIn), []byte(want)) {
			t.Errorf("logged-in index missing %q", want)
		}
	}
	if bytes.Contains([]byte(loggedIn), []byte(`\"chris\"`)) {
		t.Error("certificate CN is double-quoted in the generated ykman command")
	}
	if bytes.Contains([]byte(loggedIn), []byte("{{")) {
		t.Error("unrendered template action leaked into index.html output")
	}
	for _, unwanted := range []string{"Certificate subject", "<footer"} {
		if bytes.Contains([]byte(loggedIn), []byte(unwanted)) {
			t.Errorf("logged-in index should not contain %q", unwanted)
		}
	}

	noCerts := indexData(true)
	noCerts["CertificatesEnabled"] = false
	if out := render(t, tmpl, "index.html", noCerts); bytes.Contains([]byte(out), []byte(`href="/certs"`)) {
		t.Error("disabled certificate page link leaked into index.html output")
	}
}

func TestRenderCertModal(t *testing.T) {
	tmpl := parseTemplates(t)
	out := render(t, tmpl, "cert_modal.html", issuedCert{
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		Serial:   "12:34:56",
		CN:       "chris",
		Slot:     "9a",
		KeyType:  "eccp256",
		NotAfter: "2027-01-01 00:00 UTC",
		Issued:   1,
		Warnings: []string{"heads up"},
	})
	for _, want := range []string{"CN=chris", "12:34:56", "ykman piv certificates import 9a user.crt", "Warnings", "heads up"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("cert modal missing %q", want)
		}
	}
}

func TestRenderConfirmRevoke(t *testing.T) {
	tmpl := parseTemplates(t)
	out := render(t, tmpl, "confirm_revoke.html", map[string]any{
		"UserIdentity": "Chris@Example.com",
		"CertCN":       "chris",
		"ActiveCerts": []pki.ActiveCert{
			{Serial: "aa:bb", CN: "chris", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
	})
	for _, want := range []string{"CN=chris", "immediately revoke", "confirmRevocationAndSubmit", "cancelRevocation"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("confirm_revoke missing %q", want)
		}
	}
	if bytes.Contains([]byte(out), []byte("aa:bb")) {
		t.Error("confirm_revoke should not list individual certificate serials")
	}
}

func TestRenderInventory(t *testing.T) {
	tmpl := parseTemplates(t)
	base := map[string]any{
		"IsLoggedIn":   true,
		"UserIdentity": "Chris@Example.com",
		"CertCN":       "chris",
		"UITitle":      "YubiVault Portal",
		"UIShortTitle": "YBV",
	}

	noRole := render(t, tmpl, "inventory.html", base)
	if !bytes.Contains([]byte(noRole), []byte("Inventory unavailable")) {
		t.Error("inventory without AppRole should explain it is unavailable")
	}

	base["HasAppRole"] = true
	base["Certs"] = []pki.ActiveCert{
		{Serial: "aa", CN: "chris", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Serial: "bb", CN: "chris", Revoked: true},
	}
	base["ActiveCount"] = 1
	withCerts := render(t, tmpl, "inventory.html", base)
	for _, want := range []string{"aa", "bb", "Active", "Revoked"} {
		if !bytes.Contains([]byte(withCerts), []byte(want)) {
			t.Errorf("inventory missing %q", want)
		}
	}
}
