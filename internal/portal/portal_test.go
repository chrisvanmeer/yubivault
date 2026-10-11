package portal

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/sessions"

	"yubivault/internal/config"
)

func testPortal() *Portal {
	return &Portal{logger: slog.Default()}
}

func TestCertCN(t *testing.T) {
	p := &Portal{
		logger: slog.Default(),
		config: &config.Config{},
	}
	p.config.CN.Template = "{user}"
	p.config.CN.Pattern = config.DefaultCNPattern

	got, err := p.certCN("Chris@Example.com", "Chris@Example.com")
	if err != nil {
		t.Fatalf("certCN returned error: %v", err)
	}
	if got != "chris" {
		t.Errorf("certCN default = %q, want %q", got, "chris")
	}

	p.config.CN.Template = "{user}@{domain}"
	p.config.CN.Domain = "example.com"
	got, err = p.certCN("Chris", "Chris@Example.com")
	if err != nil {
		t.Fatalf("certCN dotted template returned error: %v", err)
	}
	if got != "chris@example.com" {
		t.Errorf("certCN dotted = %q, want %q", got, "chris@example.com")
	}

	p.config.CN.Pattern = `[a-z.]+`
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

	p := &Portal{config: &config.Config{}, logger: slog.Default()}
	p.config.UI.Manuals = map[string]string{"macos": macPath, "windows": winPath}

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

	p.config.UI.Manuals = nil
	p.config.UI.ManualFile = macPath
	if m := p.loadManuals(reqFor("curl/8.0")); !m.Available || m.Selected != "default" {
		t.Errorf("fallback manual = %+v; want selected default", m)
	}

	p.config.UI.ManualFile = ""
	if m := p.loadManuals(reqFor("curl/8.0")); m.Available {
		t.Error("manual should be unavailable when nothing is configured")
	}
}

func TestLoadManualRewritesImages(t *testing.T) {
	p := &Portal{config: &config.Config{}, logger: slog.Default()}
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

	p := &Portal{config: &config.Config{}, logger: slog.Default()}
	p.config.UI.ManualDir = dir

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
	return &Portal{
		config:      &config.Config{},
		cookieStore: sessions.NewCookieStore([]byte(strings.Repeat("h", 64)), []byte(strings.Repeat("b", 32))),
		logger:      slog.Default(),
	}
}

// seedSession writes session values into req and attaches the resulting cookie
// so a subsequent session lookup in the same request sees them.
func seedSession(t *testing.T, p *Portal, req *http.Request, values map[string]any) {
	t.Helper()
	sess, err := p.cookieStore.Get(req, sessionName)
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

	p.config.OIDC.AllowedGroups = []string{"yubivault-users"}

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
	p.config.OIDC.AllowedGroups = []string{"yubivault-users"}
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
