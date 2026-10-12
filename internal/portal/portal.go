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
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"yubivault/internal/attestation"
	"yubivault/internal/audit"
	"yubivault/internal/config"
	"yubivault/internal/pki"
)

const (
	maxUploadSize   = 2 << 20 // 2 MB upload limit
	sessionName     = "yubivault_session"
	oidcTimeout     = 15 * time.Second
	oidcReadyTTL    = 60 * time.Second
	limiterSweepAge = 10 * time.Minute
)

// Session value keys.
const (
	sessionLoginKey  = "user_login_at"
	sessionActiveKey = "user_active_at"
	sessionIdentityK = "user_identity"
	sessionEmailKey  = "user_email"
	sessionGroupsKey = "user_groups"
	sessionTokenKey  = "raw_id_token"
	sessionStateKey  = "oauth_state"
	sessionNonceKey  = "oauth_nonce"
)

// Options wires the portal to its dependencies.
type Options struct {
	Config *config.Config
	// Templates contains the page templates at templates/*.html relative to
	// the embedded project root FS.
	Templates fs.FS
	// Static contains the embedded project root FS, including static/.
	Static fs.FS
	// Audit is the audit trail logger. It may be nil when audit logging is
	// disabled; Log calls on nil loggers are no-ops.
	Audit  *audit.Logger
	Logger *slog.Logger
}

// Portal serves the YubiVault web interface.
type Portal struct {
	logger    *slog.Logger
	templates *template.Template
	static    http.Handler
	audit     *audit.Logger

	// rt holds the configuration together with every dependency that is
	// derived from it. It is swapped atomically by Reload so a configuration
	// change is applied live, without restarting the process and without
	// racing in-flight requests.
	rt atomic.Pointer[portalRuntime]

	oidcMu       sync.Mutex
	oidcCheckAt  time.Time
	oidcCheckErr error
}

// portalRuntime bundles the live configuration with the components derived
// from it. A single atomic snapshot keeps a request consistent even while a
// reload swaps the whole set.
type portalRuntime struct {
	config        *config.Config
	attest        *attestation.Verifier
	pki           *pki.Service
	cookieStore   *sessions.CookieStore
	oauth2Config  *oauth2.Config
	oidcVerifier  *oidc.IDTokenVerifier
	endSessionURL string
	loginLimiter  *ipLimiter
	signLimiter   *ipLimiter
}

// runtime returns the current configuration snapshot.
func (p *Portal) runtime() *portalRuntime { return p.rt.Load() }

// config returns the live configuration. Values read through it reflect the
// most recent successful reload.
func (p *Portal) config() *config.Config { return p.rt.Load().config }

func (p *Portal) attest() *attestation.Verifier { return p.rt.Load().attest }

func (p *Portal) pki() *pki.Service { return p.rt.Load().pki }

func (p *Portal) cookieStore() *sessions.CookieStore { return p.rt.Load().cookieStore }

func (p *Portal) oauth2Config() *oauth2.Config { return p.rt.Load().oauth2Config }

func (p *Portal) oidcVerifier() *oidc.IDTokenVerifier { return p.rt.Load().oidcVerifier }

func (p *Portal) endSessionURL() string { return p.rt.Load().endSessionURL }

func (p *Portal) loginLimiter() *ipLimiter { return p.rt.Load().loginLimiter }

func (p *Portal) signLimiter() *ipLimiter { return p.rt.Load().signLimiter }

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

	// Templates is the embedded project root FS containing templates/*.html.
	tmpl, err := template.ParseFS(opts.Templates, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML templates: %w", err)
	}

	staticFS, err := fs.Sub(opts.Static, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded static assets: %w", err)
	}

	rt, err := buildRuntime(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), oidcTimeout)
	defer cancel()
	if err := configureOIDC(ctx, rt); err != nil {
		return nil, err
	}

	p := &Portal{
		logger:    logger,
		templates: tmpl,
		static:    http.FileServer(http.FS(staticFS)),
		audit:     opts.Audit,
	}
	p.rt.Store(rt)
	return p, nil
}

// buildRuntime constructs the configuration-derived dependencies. It performs
// no network access, so it is cheap enough to call on every reload.
func buildRuntime(cfg *config.Config) (*portalRuntime, error) {
	roots, err := attestation.LoadRoots(cfg.Yubico.RootCAFile)
	if err != nil {
		return nil, err
	}
	verifier, err := attestation.New(attestation.Options{
		Roots:           roots,
		AllowedKeyTypes: cfg.AllowedKeyTypes(),
		StrictSlotCheck: cfg.StrictSlotCheck(),
		MinFirmware:     cfg.MinFirmware(),
		MinSerial:       cfg.MinSerial(),
	})
	if err != nil {
		return nil, err
	}

	pkiSvc, err := pki.New(pkiOptions(cfg))
	if err != nil {
		return nil, err
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
		MaxAge:   int(cfg.SessionMaxAge().Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure(),
		SameSite: http.SameSiteLaxMode,
	}

	return &portalRuntime{
		config:       cfg,
		attest:       verifier,
		pki:          pkiSvc,
		cookieStore:  cookieStore,
		loginLimiter: newIPLimiter(cfg.RateLimitLogin(), cfg.RateLimitLogin()),
		signLimiter:  newIPLimiter(cfg.RateLimitSign(), cfg.RateLimitSign()),
	}, nil
}

// configureOIDC performs OIDC discovery and stores the resulting verifier,
// OAuth2 client and end-session endpoint on rt. It is the only step that
// talks to the identity provider, so Reload calls it only when the OIDC
// settings actually changed.
func configureOIDC(ctx context.Context, rt *portalRuntime) error {
	cfg := rt.config
	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.OIDC.Issuer, err)
	}
	rt.oauth2Config = &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	rt.oidcVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	rt.endSessionURL = discoverEndSessionEndpoint(ctx, cfg.OIDC.Issuer)
	return nil
}

// Reload applies a freshly loaded configuration without restarting the
// process. Per-request values (allowed groups, key types, CN template,
// minimum firmware/serial, device fingerprints, session timeouts, ...) take
// effect immediately. Dependencies derived from the configuration are rebuilt:
// the attestation verifier, the Vault client, the rate limiters and the
// session cookie store. A changed session_secret invalidates existing
// sessions, and a changed OIDC provider is re-discovered, which requires the
// identity provider to be reachable at reload time. When any rebuild fails the
// previous configuration stays in effect and the error is returned.
func (p *Portal) Reload(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("configuration is nil")
	}
	old := p.runtime()
	rt, err := buildRuntime(cfg)
	if err != nil {
		return err
	}
	if old != nil && !oidcConfigChanged(old.config, cfg) {
		rt.oauth2Config = old.oauth2Config
		rt.oidcVerifier = old.oidcVerifier
		rt.endSessionURL = old.endSessionURL
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), oidcTimeout)
		defer cancel()
		if err := configureOIDC(ctx, rt); err != nil {
			return err
		}
	}
	p.rt.Store(rt)
	return nil
}

// oidcConfigChanged reports whether the OIDC settings that require a network
// re-discovery changed between two configurations.
func oidcConfigChanged(old, new *config.Config) bool {
	if old == nil || new == nil {
		return true
	}
	return old.OIDC.Issuer != new.OIDC.Issuer ||
		old.OIDC.ClientID != new.OIDC.ClientID ||
		old.OIDC.ClientSecret != new.OIDC.ClientSecret ||
		old.OIDC.RedirectURL != new.OIDC.RedirectURL
}

// pkiOptions maps the shared Vault configuration to the PKI service options.
// It is used both by New and --check-config.
func pkiOptions(cfg *config.Config) pki.Options {
	return pki.Options{
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
	}
}

// Check validates the runtime dependencies of the configuration without
// starting the server. It is used by the --check-config CLI flag.
func Check(cfg *config.Config, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	var errs []string
	record := func(what string, err error) {
		if err == nil {
			logger.Info("check ok", "check", what)
			return
		}
		logger.Error("check failed", "check", what, "error", err)
		errs = append(errs, fmt.Sprintf("%s: %v", what, err))
	}

	roots, err := attestation.LoadRoots(cfg.Yubico.RootCAFile)
	if err != nil {
		record("yubico roots", err)
	} else if _, err := attestation.New(attestation.Options{
		Roots:           roots,
		AllowedKeyTypes: cfg.AllowedKeyTypes(),
		StrictSlotCheck: cfg.StrictSlotCheck(),
		MinFirmware:     cfg.MinFirmware(),
		MinSerial:       cfg.MinSerial(),
	}); err != nil {
		record("attestation verifier", err)
	}

	pkiSvc, err := pki.New(pkiOptions(cfg))
	if err != nil {
		record("vault service", err)
	} else {
		record("vault", pkiSvc.Healthy())
		if cfg.Vault.RevokeExisting {
			record("vault approle", pkiSvc.CheckAppRole())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), oidcTimeout)
	defer cancel()
	if _, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer); err != nil {
		record("oidc discovery", err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Handler returns the complete route table wrapped in the middleware chain.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", p.static))
	mux.HandleFunc("/", p.handleIndex)

	// The route table is fixed at startup. Endpoints that depend on a
	// hot-reloadable flag (e.g. ui.certificates_enabled) stay registered and
	// re-check the live configuration per request.
	mux.HandleFunc("/login", p.rateLimit(p.loginLimiter, p.handleLogin))
	mux.HandleFunc("/callback", p.handleCallback)
	mux.HandleFunc("/logout", p.handleLogout)
	mux.HandleFunc("/certs", p.requireAuth(p.requireMember(p.handleInventory)))

	mux.HandleFunc("/manual/raw", p.requireAuth(p.requireMember(p.handleManualRaw)))
	mux.HandleFunc("/manual/asset/", p.requireAuth(p.requireMember(p.handleManualAsset)))

	mux.HandleFunc("/api/sign-csr", p.requireAuth(p.requireMember(p.rateLimit(p.signLimiter, p.handleSignCSR))))
	mux.HandleFunc("/api/preview-attest", p.requireAuth(p.requireMember(p.rateLimit(p.signLimiter, p.handlePreviewAttest))))
	mux.HandleFunc("/api/active-cert", p.requireAuth(p.requireMember(p.handleActiveCert)))

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

// loadSession reads the session and, when it is still fresh, re-saves it so
// the cookie expiration and the idle window slide forward on activity. An
// expired session is saved untouched so the expiry is not silently reset.
func (p *Portal) loadSession(w http.ResponseWriter, r *http.Request) (*sessions.Session, error) {
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return nil, err
	}
	if !session.IsNew {
		now := time.Now()
		if sessionFresh(sessionTime(session.Values[sessionLoginKey]), sessionTime(session.Values[sessionActiveKey]), now,
			p.config().SessionMaxAge(), p.config().SessionIdleTimeout()) {
			session.Values[sessionActiveKey] = now.UTC().Format(time.RFC3339)
		}
		if err := session.Save(r, w); err != nil {
			return session, err
		}
	}
	return session, nil
}

// sessionState reports whether the visitor is authenticated and whether the
// session is still within its absolute maximum age and idle timeout.
func (p *Portal) sessionState(r *http.Request) (authenticated, fresh bool) {
	identity, token := p.sessionIdentity(r)
	authenticated = identity != "" && token != ""
	if !authenticated {
		return authenticated, true
	}
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return authenticated, false
	}
	return authenticated, sessionFresh(sessionTime(session.Values[sessionLoginKey]), sessionTime(session.Values[sessionActiveKey]),
		time.Now(), p.config().SessionMaxAge(), p.config().SessionIdleTimeout())
}

// sessionFresh reports whether a session with the given login and activity
// timestamps is still valid under the max age and idle limits. Zero
// timestamps (e.g. sessions created before this feature) stay valid.
func sessionFresh(loginAt, activeAt, now time.Time, maxAge, idle time.Duration) bool {
	if !loginAt.IsZero() && now.Sub(loginAt) > maxAge {
		return false
	}
	if !activeAt.IsZero() && now.Sub(activeAt) > idle {
		return false
	}
	return true
}

// sessionTime converts a stored RFC3339 timestamp back to a time.Time.
func sessionTime(v any) time.Time {
	s, _ := v.(string)
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// touchActivity slides the idle window of a valid session forward.
func (p *Portal) touchActivity(w http.ResponseWriter, r *http.Request) {
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return
	}
	session.Values[sessionActiveKey] = time.Now().UTC().Format(time.RFC3339)
	_ = session.Save(r, w)
}

// invalidateSession clears every value and expires the cookie. It clones the
// options so the shared store defaults are not mutated.
func (p *Portal) invalidateSession(w http.ResponseWriter, r *http.Request) {
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return
	}
	for k := range session.Values {
		delete(session.Values, k)
	}
	opts := *session.Options
	opts.MaxAge = -1
	session.Options = &opts
	_ = session.Save(r, w)
}

// sessionIdentity returns the OIDC identity and raw ID token, or empty
// strings when the visitor is not authenticated.
func (p *Portal) sessionIdentity(r *http.Request) (string, string) {
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return "", ""
	}
	identity, _ := session.Values[sessionIdentityK].(string)
	token, _ := session.Values[sessionTokenKey].(string)
	return identity, token
}

// sessionEmail returns the OIDC email claim stored at login, or "" when the
// visitor is not authenticated.
func (p *Portal) sessionEmail(r *http.Request) string {
	session, err := p.cookieStore().Get(r, sessionName)
	if err != nil {
		return ""
	}
	email, _ := session.Values[sessionEmailKey].(string)
	return email
}

// certCN renders the administrator-configured certificate Common Name for an
// identity and checks it against the configured pattern.
func (p *Portal) certCN(identity, email string) (string, error) {
	cn, err := attestation.RenderCN(identity, email, p.config().CNTemplate(), p.config().CNDomain())
	if err != nil {
		return "", err
	}
	if err := p.config().ValidateCNPattern(cn); err != nil {
		return "", err
	}
	return cn, nil
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

// requireAuth rejects unauthenticated or expired sessions with 401 so the
// client can send the visitor through /login again. Expired sessions are
// invalidated before the error is rendered.
func (p *Portal) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authenticated, fresh := p.sessionState(r)
		if !authenticated || !fresh {
			if authenticated {
				p.invalidateSession(w, r)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = sessionExpiredTemplate.Execute(w, nil)
			return
		}
		p.touchActivity(w, r)
		next(w, r)
	}
}

var sessionExpiredTemplate = template.Must(template.New("session-expired").Parse(
	`<div class="animate-slide-up p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/60 text-amber-900 dark:text-amber-200 rounded-xl shadow-sm">
		<h3 class="font-bold text-base mb-1">Session expired</h3>
		<p class="text-xs mb-3">Your login session has ended. Log in again to continue.</p>
		<a href="/login" class="inline-flex items-center px-3.5 py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold rounded-lg transition shadow-sm">Log in again</a>
	</div>`))

// requireMember rejects authenticated users that are not members of one of
// the configured allowed groups. When no groups are configured every
// authenticated user passes.
func (p *Portal) requireMember(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.isMember(r) {
			identity, _ := p.sessionIdentity(r)
			p.audit.Log(audit.Event{Event: audit.EventIssueDenied, Outcome: audit.OutcomeDenied,
				Reason: "not a member of an allowed group", Identity: identity, RemoteIP: clientIP(r)})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = notMemberTemplate.Execute(w, nil)
			return
		}
		next(w, r)
	}
}

var notMemberTemplate = template.Must(template.New("not-member").Parse(
	`<div class="animate-slide-up p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/60 text-amber-900 dark:text-amber-200 rounded-xl shadow-sm">
		<h3 class="font-bold text-base mb-1">Access restricted</h3>
		<p class="text-xs mb-3">Your account is not a member of a group allowed to issue certificates. Contact your administrator.</p>
		<a href="/logout" class="inline-flex items-center px-3.5 py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold rounded-lg transition shadow-sm">Log out</a>
	</div>`))

// rateLimit guards a handler with a per-IP token bucket. The limiter is
// resolved per request through getLimiter so a reload can swap in new rate
// limits without rebuilding the route table.
func (p *Portal) rateLimit(getLimiter func() *ipLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !getLimiter().allow(clientIP(r)) {
			renderError(w, http.StatusTooManyRequests,
				"Too many requests. Please wait a moment and try again.")
			return
		}
		next(w, r)
	}
}
