package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"

	"yubivault/internal/config"
)

func testPortal() *Portal {
	return &Portal{logger: slog.Default()}
}

// testPortalWithConfig builds a Portal with a runtime snapshot for tests that
// need configuration and session handling but not the attestation or Vault
// wiring.
func testPortalWithConfig(cfg *config.Config) *Portal {
	if cfg == nil {
		cfg = &config.Config{}
	}
	p := &Portal{logger: slog.Default()}
	p.rt.Store(&portalRuntime{
		config:      cfg,
		cookieStore: sessions.NewCookieStore([]byte(strings.Repeat("h", 64)), []byte(strings.Repeat("b", 32))),
	})
	return p
}

func TestCertCN(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	p.config().CN.Template = "{user}"
	p.config().CN.Pattern = config.DefaultCNPattern

	got, err := p.certCN("Chris@Example.com", "Chris@Example.com")
	if err != nil {
		t.Fatalf("certCN returned error: %v", err)
	}
	if got != "chris" {
		t.Errorf("certCN default = %q, want %q", got, "chris")
	}

	p.config().CN.Template = "{user}@{domain}"
	p.config().CN.Domain = "example.com"
	got, err = p.certCN("Chris", "Chris@Example.com")
	if err != nil {
		t.Fatalf("certCN dotted template returned error: %v", err)
	}
	if got != "chris@example.com" {
		t.Errorf("certCN dotted = %q, want %q", got, "chris@example.com")
	}

	p.config().CN.Pattern = `[a-z.]+`
	if _, err := p.certCN("Chris", "Chris@Example.com"); err == nil {
		t.Error("certCN should reject a CN that does not match the pattern")
	}
}

func TestSameOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://portal.example.com/login", nil)
	cases := map[string]bool{
		"https://portal.example.com":     true,
		"https://portal.example.com/x/y": true,
		"https://evil.example.com":       false,
		"portal.example.com":             false,
		"":                               false,
	}
	for origin, want := range cases {
		if got := sameOrigin(origin, req); got != want {
			t.Errorf("sameOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := clientIP(req); got != "203.0.113.7" {
		t.Errorf("clientIP with XFF = %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req2.RemoteAddr = "198.51.100.4:5555"
	if got := clientIP(req2); got != "198.51.100.4" {
		t.Errorf("clientIP = %q", got)
	}
}

func TestOriginCheck(t *testing.T) {
	p := testPortal()
	handler := p.originCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	post := func(origin, referer string) int {
		req := httptest.NewRequest(http.MethodPost, "https://portal.example.com/api/sign-csr", nil)
		req.Host = "portal.example.com"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post("https://portal.example.com", ""); code != http.StatusOK {
		t.Errorf("same-origin POST rejected with %d", code)
	}
	if code := post("", "https://portal.example.com/"); code != http.StatusOK {
		t.Errorf("same-origin referer POST rejected with %d", code)
	}
	if code := post("https://evil.example.com", ""); code != http.StatusForbidden {
		t.Errorf("cross-origin POST accepted with %d", code)
	}
	if code := post("", "https://evil.example.com/"); code != http.StatusForbidden {
		t.Errorf("cross-origin referer POST accepted with %d", code)
	}

	get := httptest.NewRequest(http.MethodGet, "https://portal.example.com/", nil)
	get.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Errorf("GET should bypass origin check, got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	p := testPortal()
	handler := p.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://portal.example.com/", nil))

	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set on plain HTTP")
	}
}

func TestSecurityHeadersHSTS(t *testing.T) {
	p := testPortal()
	handler := p.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "https://portal.example.com/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Error("HSTS header missing for HTTPS request")
	}
}

func TestLoadManuals(t *testing.T) {
	dir := t.TempDir()
	macPath := filepath.Join(dir, "manual-macos.md")
	winPath := filepath.Join(dir, "manual-windows.pdf")
	if err := os.WriteFile(macPath, []byte("# macOS\n\nbody text"), 0o600); err != nil {
		t.Fatalf("failed to write markdown manual: %v", err)
	}
	if err := os.WriteFile(winPath, []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatalf("failed to write pdf manual: %v", err)
	}

	p := testPortalWithConfig(&config.Config{})
	p.config().UI.Manuals = map[string]string{"macos": macPath, "windows": winPath}

	reqFor := func(ua string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", ua)
		return req
	}

	m := p.loadManuals(reqFor("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"))
	if !m.Available || len(m.Docs) != 2 {
		t.Fatalf("manuals = %+v; want 2 available docs", m)
	}
	if m.Selected != "macos" {
		t.Errorf("selected = %q; want macos", m.Selected)
	}
	if m.Docs[0].Key != "macos" || m.Docs[0].IsPDF {
		t.Errorf("first doc = %+v; want macos markdown first", m.Docs[0])
	}
	if !strings.Contains(string(m.Docs[0].HTML), "body text") {
		t.Error("markdown manual was not rendered")
	}
	if !m.Docs[1].IsPDF || m.Docs[1].URL != "/manual/raw?os=windows" {
		t.Errorf("second doc = %+v; want windows PDF", m.Docs[1])
	}

	if m := p.loadManuals(reqFor("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")); m.Selected != "windows" {
		t.Errorf("selected = %q; want windows", m.Selected)
	}
	if m := p.loadManuals(reqFor("curl/8.0")); m.Selected != "macos" {
		t.Errorf("selected = %q; want macos fallback for unknown OS", m.Selected)
	}

	p.config().UI.Manuals = nil
	p.config().UI.ManualFile = macPath
	if m := p.loadManuals(reqFor("curl/8.0")); !m.Available || m.Selected != "default" {
		t.Errorf("fallback manual = %+v; want selected default", m)
	}

	p.config().UI.ManualFile = ""
	if m := p.loadManuals(reqFor("curl/8.0")); m.Available {
		t.Error("manual should be unavailable when nothing is configured")
	}
}

func TestLoadManualRewritesImages(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	dir := t.TempDir()
	file := filepath.Join(dir, "manual.md")
	body := "![step](images/step1.png)\n\n![remote](https://example.com/x.png)\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("failed to write manual: %v", err)
	}

	doc, ok := p.loadManualDoc("macos", file)
	if !ok {
		t.Fatal("manual should load")
	}
	html := string(doc.HTML)
	if !strings.Contains(html, `src="/manual/asset/images/step1.png"`) {
		t.Errorf("relative image not rewritten: %s", html)
	}
	if !strings.Contains(html, `src="https://example.com/x.png"`) {
		t.Errorf("absolute image should be untouched: %s", html)
	}
}

func TestHandleManualAsset(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "manuals")
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatalf("failed to create asset dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images", "step1.png"), []byte("PNG"), 0o600); err != nil {
		t.Fatalf("failed to write asset: %v", err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}

	p := testPortalWithConfig(&config.Config{})
	p.config().UI.ManualDir = dir

	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		p.handleManualAsset(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}

	if rec := get("/manual/asset/images/step1.png"); rec.Code != http.StatusOK || rec.Body.String() != "PNG" {
		t.Errorf("asset = %d %q; want 200 PNG", rec.Code, rec.Body.String())
	}
	if ct := get("/manual/asset/images/step1.png").Header().Get("Content-Type"); !strings.Contains(ct, "image/png") {
		t.Errorf("asset content type = %q; want image/png", ct)
	}
	if rec := get("/manual/asset/../secret.txt"); rec.Code != http.StatusNotFound {
		t.Errorf("path traversal escaped the manual dir: %d", rec.Code)
	}
	if rec := get("/manual/asset/missing.png"); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset = %d; want 404", rec.Code)
	}
}

func TestIPLimiter(t *testing.T) {
	lim := newIPLimiter(1, 2)
	first := lim.allow("1.1.1.1")
	second := lim.allow("1.1.1.1")
	if !first || !second {
		t.Fatal("burst should allow two requests")
	}
	if lim.allow("1.1.1.1") {
		t.Fatal("third request should be limited")
	}
	if !lim.allow("2.2.2.2") {
		t.Fatal("different IP should have its own bucket")
	}
}

func TestParseGroups(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want []string
	}{
		{"array", []any{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"string slice", []string{"x", "y"}, []string{"x", "y"}},
		{"delimited string", "g1, g2 g3", []string{"g1", "g2", "g3"}},
		{"empty array", []any{}, nil},
		{"nil", nil, nil},
		{"non string", 42, nil},
	}
	for _, tc := range cases {
		if got := parseGroups(tc.in); !equalStrings(got, tc.want) {
			t.Errorf("%s: parseGroups(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestClaimPath(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"devs"},
		"resource_access": map[string]any{
			"Vault": map[string]any{
				"roles": []any{"testers"},
			},
		},
		"email": "chris@example.com",
	}
	if got, ok := claimPath(claims, "groups").([]any); !ok || len(got) != 1 {
		t.Errorf("top-level claim = %v", got)
	}
	if got, ok := claimPath(claims, "resource_access.Vault.roles").([]any); !ok || len(got) != 1 {
		t.Errorf("nested claim = %v", got)
	}
	if got := claimPath(claims, "resource_access.Other.roles"); got != nil {
		t.Errorf("missing nested claim = %v, want nil", got)
	}
	if got := claimPath(claims, "groups.roles"); got != nil {
		t.Errorf("intermediate non-map = %v, want nil", got)
	}
	if got := stringClaim(claims, "email"); got != "chris@example.com" {
		t.Errorf("stringClaim = %q", got)
	}
	if got := stringClaim(claims, "preferred_username"); got != "" {
		t.Errorf("stringClaim missing = %q, want empty", got)
	}
}

func TestMemberOfAny(t *testing.T) {
	if !memberOfAny([]string{"Testers"}, []string{"testers"}) {
		t.Error("case-insensitive match should succeed")
	}
	if memberOfAny([]string{"testers"}, nil) {
		t.Error("empty allowlist should not match; the caller short-circuits it")
	}
	if memberOfAny(nil, []string{"testers"}) {
		t.Error("no groups should not match a non-empty allowlist")
	}
	if memberOfAny([]string{"devs"}, []string{"testers"}) {
		t.Error("non-matching groups should be rejected")
	}
}

func TestLoginErrorMessage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	if got := loginErrorMessage(req); got != "" {
		t.Errorf("no error param = %q, want empty", got)
	}

	denied := httptest.NewRequest(http.MethodGet, "http://portal/?error=access_denied", nil)
	if got := loginErrorMessage(denied); !strings.Contains(got, "not a member") {
		t.Errorf("access_denied message = %q", got)
	}

	unknown := httptest.NewRequest(http.MethodGet, "http://portal/?error=whatever", nil)
	if got := loginErrorMessage(unknown); got == "" {
		t.Error("unknown error should get a generic message")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		if (len(a) == 0 && b == nil) || (a == nil && len(b) == 0) {
			return true
		}
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newSessionPortal() *Portal {
	return testPortalWithConfig(&config.Config{})
}

// seedSession writes session values into req and attaches the resulting cookie
// so a subsequent session lookup in the same request sees them.
func seedSession(t *testing.T, p *Portal, req *http.Request, values map[string]any) {
	t.Helper()
	sess, err := p.cookieStore().Get(req, sessionName)
	if err != nil {
		t.Fatalf("session lookup failed: %v", err)
	}
	for k, v := range values {
		sess.Values[k] = v
	}
	rec := httptest.NewRecorder()
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("session save failed: %v", err)
	}
	cookie := rec.Header().Get("Set-Cookie")
	req.Header.Set("Cookie", strings.SplitN(cookie, ";", 2)[0])
}

func TestIsMember(t *testing.T) {
	p := newSessionPortal()
	req := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	if !p.isMember(req) {
		t.Error("empty allowlist should make everyone a member")
	}

	p.config().OIDC.AllowedGroups = []string{"yubivault-users"}

	memberReq := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	seedSession(t, p, memberReq, map[string]any{"user_groups": []string{"Yubivault-Users"}})
	if !p.isMember(memberReq) {
		t.Error("group match should be case-insensitive")
	}

	nonMember := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	if p.isMember(nonMember) {
		t.Error("user without groups should not be a member when an allowlist is set")
	}

	other := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	seedSession(t, p, other, map[string]any{"user_groups": []string{"devs"}})
	if p.isMember(other) {
		t.Error("non-matching group should be rejected")
	}
}

func TestRequireMember(t *testing.T) {
	p := newSessionPortal()
	p.config().OIDC.AllowedGroups = []string{"yubivault-users"}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := p.requireMember(ok)

	nonMember := httptest.NewRequest(http.MethodGet, "http://portal/api/sign-csr", nil)
	seedSession(t, p, nonMember, map[string]any{"user_groups": []string{"devs"}})
	rec := httptest.NewRecorder()
	handler(rec, nonMember)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-member should get 403, got %d", rec.Code)
	}

	member := httptest.NewRequest(http.MethodGet, "http://portal/api/sign-csr", nil)
	seedSession(t, p, member, map[string]any{"user_groups": []string{"yubivault-users"}})
	rec = httptest.NewRecorder()
	handler(rec, member)
	if rec.Code != http.StatusOK {
		t.Errorf("member should pass, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Session lifecycle and device pinning
// ---------------------------------------------------------------------------

func TestSessionFresh(t *testing.T) {
	now := time.Now()
	const maxAge = time.Hour
	const idle = 30 * time.Minute

	cases := []struct {
		name     string
		loginAt  time.Time
		activeAt time.Time
		want     bool
	}{
		{"recent", now.Add(-5 * time.Minute), now.Add(-time.Minute), true},
		{"legacy zero timestamps", time.Time{}, time.Time{}, true},
		{"beyond max age", now.Add(-2 * time.Hour), now.Add(-time.Minute), false},
		{"idle timeout", now.Add(-10 * time.Minute), now.Add(-40 * time.Minute), false},
	}
	for _, tc := range cases {
		if got := sessionFresh(tc.loginAt, tc.activeAt, now, maxAge, idle); got != tc.want {
			t.Errorf("%s: sessionFresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSessionStateExpired(t *testing.T) {
	p := newSessionPortal()

	expired := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	seedSession(t, p, expired, map[string]any{
		sessionIdentityK: "chris",
		sessionTokenKey:  "token",
		sessionLoginKey:  old,
		sessionActiveKey: old,
	})
	auth, fresh := p.sessionState(expired)
	if !auth {
		t.Fatal("session with identity and token should be authenticated")
	}
	if fresh {
		t.Error("session older than the max age must not be fresh")
	}

	active := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	now := time.Now().UTC().Format(time.RFC3339)
	seedSession(t, p, active, map[string]any{
		sessionIdentityK: "chris",
		sessionTokenKey:  "token",
		sessionLoginKey:  now,
		sessionActiveKey: now,
	})
	if auth, fresh := p.sessionState(active); !auth || !fresh {
		t.Errorf("fresh session = (auth=%v, fresh=%v), want (true, true)", auth, fresh)
	}
}

func TestPinnedDeviceErr(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	p.config().Yubico.DeviceFingerprints = map[string][]string{
		"chris": {"sha256:aaaa"},
	}
	if err := p.pinnedDeviceErr("chris", "sha256:aaaa"); err != nil {
		t.Errorf("pinned match should pass: %v", err)
	}
	if err := p.pinnedDeviceErr("chris", "sha256:bbbb"); err == nil {
		t.Error("pinned mismatch must be rejected")
	}
	if err := p.pinnedDeviceErr("chris", "SHA256:AAAA"); err != nil {
		t.Errorf("fingerprint comparison should ignore case: %v", err)
	}
	if err := p.pinnedDeviceErr("dave", "sha256:bbbb"); err != nil {
		t.Errorf("a CN without an entry is not pinned: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Hot reload
// ---------------------------------------------------------------------------

// writeRoots creates a temporary PEM file with a self-signed CA certificate.
func writeRoots(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Yubico Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write roots: %v", err)
	}
	return path
}

// baseTestConfig returns a configuration that buildRuntime accepts.
func baseTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.SessionSecret = strings.Repeat("x", 40)
	cfg.Vault.Address = "https://vault.example.com"
	cfg.Vault.PKIMount = "pki"
	cfg.Vault.PKIRole = "user"
	cfg.OIDC.Issuer = "https://idp.example.com"
	cfg.OIDC.ClientID = "client"
	cfg.OIDC.RedirectURL = "https://portal.example.com/callback"
	cfg.Yubico.RootCAFile = writeRoots(t)
	return cfg
}

func TestOIDCConfigChanged(t *testing.T) {
	a := baseTestConfig(t)
	b := *a
	if oidcConfigChanged(a, &b) {
		t.Error("identical OIDC settings should not report a change")
	}
	b = *a
	b.OIDC.Issuer = "https://other.example.com"
	if !oidcConfigChanged(a, &b) {
		t.Error("issuer change must be detected")
	}
	b = *a
	b.OIDC.ClientID = "other"
	if !oidcConfigChanged(a, &b) {
		t.Error("client id change must be detected")
	}
	if !oidcConfigChanged(nil, a) {
		t.Error("a nil previous config must report a change")
	}
}

func TestReloadAppliesConfig(t *testing.T) {
	cfg1 := baseTestConfig(t)
	rt, err := buildRuntime(cfg1)
	if err != nil {
		t.Fatalf("buildRuntime: %v", err)
	}
	p := &Portal{logger: slog.Default()}
	p.rt.Store(rt)

	cfg2 := *cfg1
	cfg2.UI.Title = "Reloaded Portal"
	if err := p.Reload(&cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if p.config() != &cfg2 {
		t.Errorf("config not swapped: got %p want %p", p.config(), &cfg2)
	}
	if got := p.config().UI.Title; got != "Reloaded Portal" {
		t.Errorf("UI.Title = %q, want %q", got, "Reloaded Portal")
	}
	if p.attest() == rt.attest {
		t.Error("derived attestation verifier should be rebuilt on reload")
	}
	if p.cookieStore() == rt.cookieStore {
		t.Error("derived session store should be rebuilt on reload")
	}
}

func TestReloadFailureKeepsConfig(t *testing.T) {
	cfg1 := baseTestConfig(t)
	rt, err := buildRuntime(cfg1)
	if err != nil {
		t.Fatalf("buildRuntime: %v", err)
	}
	p := &Portal{logger: slog.Default()}
	p.rt.Store(rt)

	bad := *cfg1
	bad.Yubico.RootCAFile = filepath.Join(t.TempDir(), "missing.pem")
	if err := p.Reload(&bad); err == nil {
		t.Fatal("Reload must fail when the roots file is unreadable")
	}
	if p.config() != cfg1 {
		t.Error("a failed reload must keep the previous configuration active")
	}
}

// ---------------------------------------------------------------------------
// Resource usage: session reuse, manual caching and streaming
// ---------------------------------------------------------------------------

func TestSessionRefreshThrottled(t *testing.T) {
	p := newSessionPortal()

	recent := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	now := time.Now().UTC().Format(time.RFC3339)
	seedSession(t, p, recent, map[string]any{
		sessionIdentityK: "chris",
		sessionTokenKey:  "token",
		sessionLoginKey:  now,
		sessionActiveKey: now,
	})
	rec := httptest.NewRecorder()
	p.touchActivity(rec, recent)
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("a recently active session must not be re-saved on every request")
	}

	stale := httptest.NewRequest(http.MethodGet, "http://portal/", nil)
	old := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	seedSession(t, p, stale, map[string]any{
		sessionIdentityK: "chris",
		sessionTokenKey:  "token",
		sessionLoginKey:  old,
		sessionActiveKey: old,
	})
	rec = httptest.NewRecorder()
	p.touchActivity(rec, stale)
	if rec.Header().Get("Set-Cookie") == "" {
		t.Error("an idle session past the throttle interval should be refreshed")
	}
}

func TestManualRenderCache(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	file := filepath.Join(t.TempDir(), "manual.md")
	if err := os.WriteFile(file, []byte("# One\n\nfirst content"), 0o600); err != nil {
		t.Fatal(err)
	}

	doc1, ok := p.loadManualDoc("macos", file)
	if !ok || !strings.Contains(string(doc1.HTML), "first content") {
		t.Fatalf("first render = %+v; want the markdown body", doc1)
	}
	if doc2, ok := p.loadManualDoc("macos", file); !ok || doc2.HTML != doc1.HTML {
		t.Error("an unchanged manual should render identically")
	}

	// A cache hit must not touch the file again: capture the stat signature,
	// remove the file, and render with the stale info.
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	r1, ok := p.renderManual(file, info)
	if !ok {
		t.Fatal("render failed")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if r2, ok := p.renderManual(file, info); !ok || r2.html != r1.html {
		t.Error("an unchanged file should be served from the render cache")
	}

	// When the file changes the cache invalidates and the new body appears.
	if err := os.WriteFile(file, []byte("# Two\n\nsecond content"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(file, future, future); err != nil {
		t.Fatal(err)
	}
	doc3, ok := p.loadManualDoc("macos", file)
	if !ok || !strings.Contains(string(doc3.HTML), "second content") {
		t.Errorf("a changed manual should re-render, got %q", doc3.HTML)
	}
}

func TestManualRenderCacheConcurrent(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	file := filepath.Join(t.TempDir(), "manual.md")
	if err := os.WriteFile(file, []byte("# Hi\n\nbody"), 0o600); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := p.loadManualDoc("macos", file); !ok {
				t.Error("concurrent manual render failed")
			}
		}()
	}
	wg.Wait()
}

func TestHandleManualRawStreams(t *testing.T) {
	p := testPortalWithConfig(&config.Config{})
	dir := t.TempDir()
	file := filepath.Join(dir, "manual.md")
	body := "# Hello\n\nstreaming body"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p.config().UI.ManualFile = file

	rec := httptest.NewRecorder()
	p.handleManualRaw(rec, httptest.NewRequest(http.MethodGet, "/manual/raw?os=default", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Errorf("content type = %q, want text/markdown", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "inline") {
		t.Errorf("disposition = %q, want inline", cd)
	}
	if rec.Body.String() != body {
		t.Errorf("body = %q, want %q", rec.Body.String(), body)
	}

	// ServeContent adds Range support for free.
	rangeReq := httptest.NewRequest(http.MethodGet, "/manual/raw?os=default", nil)
	rangeReq.Header.Set("Range", "bytes=0-4")
	rec = httptest.NewRecorder()
	p.handleManualRaw(rec, rangeReq)
	if rec.Code != http.StatusPartialContent {
		t.Errorf("range status = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "# Hel" {
		t.Errorf("range body = %q, want %q", rec.Body.String(), "# Hel")
	}
}
