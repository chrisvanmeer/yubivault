// Package portal is the HTTP front end of YubiVault: sessions, OIDC login,
// middleware and all user facing handlers.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"yubivault/internal/attestation"
	"yubivault/internal/config"
	"yubivault/internal/pki"
)

const (
	maxUploadSize   = 2 << 20 // 2 MB upload limit
	sessionName     = "yubivault_session"
	sessionMaxAge   = 3600
	oidcTimeout     = 15 * time.Second
	limiterSweepAge = 10 * time.Minute
)

// Options wires the portal to its dependencies.
type Options struct {
	Config *config.Config
	// Templates contains the page templates at templates/*.html relative to
	// the embedded project root FS.
	Templates fs.FS
	// Static contains the embedded project root FS, including static/.
	Static fs.FS
	Logger *slog.Logger
}

// Portal serves the YubiVault web interface.
type Portal struct {
	config        *config.Config
	logger        *slog.Logger
	attest        *attestation.Verifier
	pki           *pki.Service
	templates     *template.Template
	static        http.Handler
	cookieStore   *sessions.CookieStore
	oauth2Config  oauth2.Config
	oidcVerifier  *oidc.IDTokenVerifier
	endSessionURL string
	loginLimiter  *ipLimiter
	signLimiter   *ipLimiter
}

// New builds a fully wired Portal. It fails fast on configuration or
// dependency problems so systemd reports a crash instead of a broken service.
func New(opts Options) (*Portal, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	cfg := opts.Config

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	roots, err := attestation.LoadRoots(cfg.Yubico.RootCAFile)
	if err != nil {
		return nil, err
	}
	verifier, err := attestation.New(attestation.Options{
		Roots:           roots,
		AllowedKeyTypes: cfg.AllowedKeyTypes(),
		StrictSlotCheck: cfg.StrictSlotCheck(),
	})
	if err != nil {
		return nil, err
	}

	pkiSvc, err := pki.New(pki.Options{
		Address:         cfg.Vault.Address,
		PKIMount:        cfg.Vault.PKIMount,
		PKIRole:         cfg.Vault.PKIRole,
		AuthMount:       cfg.Vault.AuthMount,
		AuthRole:        cfg.Vault.AuthRole,
		AppRoleMount:    cfg.Vault.AppRoleMount,
		AppRoleRoleID:   cfg.Vault.AppRoleRoleID,
		AppRoleSecretID: cfg.Vault.AppRoleSecretID,
		RevokeExisting:  cfg.Vault.RevokeExisting,
		RevokeMode:      cfg.Vault.RevokeMode,
		CertTTL:         cfg.Vault.CertTTL,
		CertTTLMax:      cfg.Vault.CertTTLMax,
	})
	if err != nil {
		return nil, err
	}

	// Templates is the embedded project root FS containing templates/*.html.
	tmpl, err := template.ParseFS(opts.Templates, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML templates: %w", err)
	}

	staticFS, err := fs.Sub(opts.Static, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded static assets: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), oidcTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.OIDC.Issuer, err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Single secret, two derived keys: a 64 byte HMAC key and a 32 byte AES
	// key, so the session payload (including the raw OIDC ID token) is
	// encrypted at rest and not merely signed.
	secret := []byte(cfg.Server.SessionSecret)
	hashKey := sha512.Sum512(secret)
	blockKey := sha256.Sum256(secret)
	cookieStore := sessions.NewCookieStore(hashKey[:], blockKey[:])
	cookieStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		Secure:   cfg.CookieSecure(),
		SameSite: http.SameSiteLaxMode,
	}

	return &Portal{
		config:        cfg,
		logger:        logger,
		attest:        verifier,
		pki:           pkiSvc,
		templates:     tmpl,
		static:        http.FileServer(http.FS(staticFS)),
		cookieStore:   cookieStore,
		oauth2Config:  oauthCfg,
		oidcVerifier:  provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}),
		endSessionURL: discoverEndSessionEndpoint(ctx, cfg.OIDC.Issuer),
		loginLimiter:  newIPLimiter(cfg.RateLimitLogin(), cfg.RateLimitLogin()),
		signLimiter:   newIPLimiter(cfg.RateLimitSign(), cfg.RateLimitSign()),
	}, nil
}

// Handler returns the complete route table wrapped in the middleware chain.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", p.static))
	mux.HandleFunc("/", p.handleIndex)

	mux.HandleFunc("/login", p.rateLimit(p.loginLimiter, p.handleLogin))
	mux.HandleFunc("/callback", p.handleCallback)
	mux.HandleFunc("/logout", p.handleLogout)
	if p.config.CertificatesEnabled() {
		mux.HandleFunc("/certs", p.requireAuth(p.handleInventory))
	}

	mux.HandleFunc("/manual/raw", p.requireAuth(p.handleManualRaw))
	mux.HandleFunc("/manual/asset/", p.requireAuth(p.handleManualAsset))

	mux.HandleFunc("/api/sign-csr", p.requireAuth(p.rateLimit(p.signLimiter, p.handleSignCSR)))
	mux.HandleFunc("/api/active-cert", p.requireAuth(p.handleActiveCert))

	mux.HandleFunc("/healthz", p.handleHealthz)
	mux.HandleFunc("/readyz", p.handleReadyz)

	var handler http.Handler = mux
	handler = p.originCheck(handler)
	handler = p.requestLog(handler)
	handler = p.securityHeaders(handler)
	return handler
}

// discoverEndSessionEndpoint looks up the IdP's RP-initiated logout endpoint.
// It is optional: when unavailable, logout stays a local session clear.
func discoverEndSessionEndpoint(ctx context.Context, issuer string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("could not discover OIDC end_session_endpoint", "error", err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	var doc struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return ""
	}
	return doc.EndSessionEndpoint
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

// loadSession reads the session and, when valid, re-saves it so the cookie
// expiration slides forward on activity.
func (p *Portal) loadSession(w http.ResponseWriter, r *http.Request) (*sessions.Session, error) {
	session, err := p.cookieStore.Get(r, sessionName)
	if err != nil {
		return nil, err
	}
	if !session.IsNew {
		if err := session.Save(r, w); err != nil {
			return session, err
		}
	}
	return session, nil
}

// sessionIdentity returns the OIDC identity and raw ID token, or empty
// strings when the visitor is not authenticated.
func (p *Portal) sessionIdentity(r *http.Request) (string, string) {
	session, err := p.cookieStore.Get(r, sessionName)
	if err != nil {
		return "", ""
	}
	identity, _ := session.Values["user_identity"].(string)
	token, _ := session.Values["raw_id_token"].(string)
	return identity, token
}

// sessionEmail returns the OIDC email claim stored at login, or "" when the
// visitor is not authenticated.
func (p *Portal) sessionEmail(r *http.Request) string {
	session, err := p.cookieStore.Get(r, sessionName)
	if err != nil {
		return ""
	}
	email, _ := session.Values["user_email"].(string)
	return email
}

// certCN renders the administrator-configured certificate Common Name for an
// identity and checks it against the configured pattern.
func (p *Portal) certCN(identity, email string) (string, error) {
	cn, err := attestation.RenderCN(identity, email, p.config.CNTemplate(), p.config.CNDomain())
	if err != nil {
		return "", err
	}
	if err := p.config.ValidateCNPattern(cn); err != nil {
		return "", err
	}
	return cn, nil
}

func (p *Portal) isAuthenticated(r *http.Request) bool {
	identity, token := p.sessionIdentity(r)
	return identity != "" && token != ""
}

func newOAuthState() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.URLEncoding.EncodeToString(buf)
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// securityHeaders is applied to every response.
func (p *Portal) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The manual is embedded via an iframe (PDF) or shown inline, so it
		// must permit same-origin framing. Everything else is locked down.
		frameAncestors, xFrameOptions := "'none'", "DENY"
		if r.URL.Path == "/manual/raw" {
			frameAncestors, xFrameOptions = "'self'", "SAMEORIGIN"
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", xFrameOptions)
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors "+frameAncestors+"; base-uri 'self'; form-action 'self'")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// requestLog emits one structured log line per request.
func (p *Portal) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		}
		p.logger.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote", clientIP(r)),
		)
	})
}

// originCheck rejects state changing requests whose Origin/Referer does not
// match this host, as defence in depth against CSRF.
func (p *Portal) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r) {
				http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
				return
			}
			if referrer := r.Header.Get("Referer"); referrer != "" && !sameOrigin(referrer, r) {
				http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(rawURL string, r *http.Request) bool {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return false
	}
	authority := rawURL[i+3:]
	if j := strings.IndexByte(authority, '/'); j >= 0 {
		authority = authority[:j]
	}
	return strings.EqualFold(authority, r.Host)
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			fwd = fwd[:i]
		}
		return strings.TrimSpace(fwd)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ipLimiter is a small per-IP token bucket registry with lazy sweeping.
type ipLimiter struct {
	mu        sync.Mutex
	visitors  map[string]*visitor
	rate      rate.Limit
	burst     int
	lastSweep time.Time
}

type visitor struct {
	lim  *rate.Limiter
	last time.Time
}

func newIPLimiter(perMin, burst int) *ipLimiter {
	return &ipLimiter{
		visitors:  make(map[string]*visitor),
		rate:      rate.Limit(float64(perMin) / 60.0),
		burst:     burst,
		lastSweep: time.Now(),
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if time.Since(l.lastSweep) > time.Minute {
		for key, v := range l.visitors {
			if time.Since(v.last) > limiterSweepAge {
				delete(l.visitors, key)
			}
		}
		l.lastSweep = time.Now()
	}

	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{lim: rate.NewLimiter(l.rate, l.burst)}
		l.visitors[ip] = v
	}
	v.last = time.Now()
	return v.lim.Allow()
}

// requireAuth rejects unauthenticated API calls with 401 so the client can
// send the visitor through /login again.
func (p *Portal) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.isAuthenticated(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = sessionExpiredTemplate.Execute(w, nil)
			return
		}
		next(w, r)
	}
}

var sessionExpiredTemplate = template.Must(template.New("session-expired").Parse(
	`<div class="animate-slide-up p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/60 text-amber-900 dark:text-amber-200 rounded-xl shadow-sm">
		<h3 class="font-bold text-base mb-1">Session expired</h3>
		<p class="text-xs mb-3">Your login session has ended. Log in again to continue.</p>
		<a href="/login" class="inline-flex items-center px-3.5 py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold rounded-lg transition shadow-sm">Log in again</a>
	</div>`))

func (p *Portal) rateLimit(limiter *ipLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r)) {
			renderError(w, http.StatusTooManyRequests,
				"Too many requests. Please wait a moment and try again.")
			return
		}
		next(w, r)
	}
}
