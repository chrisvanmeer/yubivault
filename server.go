package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	vault "github.com/hashicorp/vault/api"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

const (
	MaxUploadSize = 2 << 20 // 2 MB upload limit
	SessionName   = "yubivault_session"
)

type Config struct {
	Server struct {
		ListenAddr    string `yaml:"listen_addr"`
		SessionSecret string `yaml:"session_secret"`
		Debug         bool   `yaml:"debug"`
	} `yaml:"server"`
	UI struct {
		Title      string `yaml:"title"`
		ShortTitle string `yaml:"short_title"`
	} `yaml:"ui"`
	Vault struct {
		Address         string `yaml:"address"`
		PKIMount        string `yaml:"pki_mount"`
		PKIRole         string `yaml:"pki_role"`
		AuthMount       string `yaml:"auth_mount"`
		AuthRole        string `yaml:"auth_role"`
		RevokeExisting  bool   `yaml:"revoke_existing"`
		AppRoleMount    string `yaml:"approle_mount"`
		AppRoleRoleID   string `yaml:"approle_role_id"`
		AppRoleSecretID string `yaml:"approle_secret_id"`
	} `yaml:"vault"`
	OIDC struct {
		Issuer       string `yaml:"issuer"`
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		RedirectURL  string `yaml:"redirect_url"`
	} `yaml:"oidc"`
	Yubico struct {
		RootCAFile string `yaml:"root_ca_file"`
		RSABits    int    `yaml:"rsa_bits"`
	} `yaml:"yubico"`
}

type Server struct {
	config       *Config
	vaultConfig  *vault.Config
	yubicoRoots  *x509.CertPool
	templates    *template.Template
	cookieStore  *sessions.CookieStore
	oauth2Config oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
}

func LoadConfig(path string) (*Config, error) {
	if path == "config.yaml" {
		if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
			if _, err := os.Stat("/etc/yubivault/config.yaml"); err == nil {
				path = "/etc/yubivault/config.yaml"
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file '%s': %w", path, err)
	}

	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = "127.0.0.1:8080"
	}
	if cfg.UI.Title == "" {
		cfg.UI.Title = "YubiVault Portal"
	}
	if cfg.UI.ShortTitle == "" {
		cfg.UI.ShortTitle = "YBV"
	}
	if cfg.Vault.PKIMount == "" {
		cfg.Vault.PKIMount = "pki_int"
	}
	if cfg.Vault.PKIRole == "" {
		cfg.Vault.PKIRole = "openvpn-nl"
	}
	if cfg.Vault.AuthMount == "" {
		cfg.Vault.AuthMount = "oidc"
	}
	if cfg.Vault.AuthRole == "" {
		cfg.Vault.AuthRole = "default"
	}
	if cfg.Vault.AppRoleMount == "" {
		cfg.Vault.AppRoleMount = "approle"
	}
	if cfg.Yubico.RootCAFile == "" {
		cfg.Yubico.RootCAFile = "yubico-roots.pem"
	}
	if cfg.Yubico.RSABits == 0 {
		cfg.Yubico.RSABits = 3072
	}

	return &cfg, nil
}

func loadYubicoRoots(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if path != "" {
		pemData, err := os.ReadFile(path)
		if err == nil {
			if ok := pool.AppendCertsFromPEM(pemData); !ok {
				return nil, fmt.Errorf("failed to parse PEM certificates from '%s'", path)
			}
			log.Printf("Successfully loaded Yubico Root CAs from '%s'", path)
			return pool, nil
		}
		log.Printf("[WARN] Could not read Yubico Root CA file '%s' (%v). Operating with system cert pool.", path, err)
	}

	return pool, nil
}

func NewServer(cfg *Config) (*Server, error) {
	ctx := context.Background()

	vConfig := vault.DefaultConfig()
	vConfig.Address = cfg.Vault.Address

	yubicoRoots, err := loadYubicoRoots(cfg.Yubico.RootCAFile)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML templates: %w", err)
	}

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", cfg.OIDC.Issuer, err)
	}

	oidcVerifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	oauth2Config := oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	cookieStore := sessions.NewCookieStore([]byte(cfg.Server.SessionSecret))
	cookieStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	return &Server{
		config:       cfg,
		vaultConfig:  vConfig,
		yubicoRoots:  yubicoRoots,
		templates:    tmpl,
		cookieStore:  cookieStore,
		oauth2Config: oauth2Config,
		oidcVerifier: oidcVerifier,
	}, nil
}

func main() {
	installFlag := flag.Bool("install", false, "Install YubiVault as a systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall YubiVault systemd service")
	flag.Parse()

	if *installFlag {
		if err := installService(); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		os.Exit(0)
	}

	if *uninstallFlag {
		if err := uninstallService(); err != nil {
			log.Fatalf("Uninstallation failed: %v", err)
		}
		os.Exit(0)
	}

	configPath := getEnvOrDefault("CONFIG_FILE", "config.yaml")
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("Server initialization error: %v", err)
	}

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/login", srv.handleLogin)
	http.HandleFunc("/callback", srv.handleCallback)
	http.HandleFunc("/logout", srv.handleLogout)

	http.HandleFunc("/", srv.handleIndex)
	http.HandleFunc("/api/sign-csr", srv.requireAuth(srv.handleSignCSR))

	log.Printf("YubiVault Portal listening on http://%s (Debug: %v, Auto-Revoke: %v)", cfg.Server.ListenAddr, cfg.Server.Debug, cfg.Vault.RevokeExisting)
	log.Fatal(http.ListenAndServe(cfg.Server.ListenAddr, nil))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	stateBuf := make([]byte, 16)
	_, _ = rand.Read(stateBuf)
	state := base64.URLEncoding.EncodeToString(stateBuf)

	session, _ := s.cookieStore.Get(r, SessionName)
	session.Values["oauth_state"] = state
	_ = session.Save(r, w)

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := s.cookieStore.Get(r, SessionName)

	savedState, ok := session.Values["oauth_state"].(string)
	if !ok || savedState != r.URL.Query().Get("state") {
		http.Error(w, "Invalid OAuth state token", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "OAuth token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID Token received from OIDC provider", http.StatusInternalServerError)
		return
	}

	idToken, err := s.oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID Token verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	_ = idToken.Claims(&claims)

	identity := claims.PreferredUsername
	if identity == "" {
		identity = claims.Email
	}

	session.Values["user_identity"] = identity
	session.Values["raw_id_token"] = rawIDToken
	delete(session.Values, "oauth_state")
	_ = session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.cookieStore.Get(r, SessionName)
	delete(session.Values, "user_identity")
	delete(session.Values, "raw_id_token")
	session.Options.MaxAge = -1
	_ = session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.cookieStore.Get(r, SessionName)
		_, hasIdentity := session.Values["user_identity"].(string)
		_, hasToken := session.Values["raw_id_token"].(string)

		if !hasIdentity || !hasToken {
			renderError(w, "Session expired. Please reload the page and log in again.")
			return
		}
		next(w, r)
	}
}

func (s *Server) getSessionValues(r *http.Request) (string, string) {
	session, _ := s.cookieStore.Get(r, SessionName)
	identity, _ := session.Values["user_identity"].(string)
	token, _ := session.Values["raw_id_token"].(string)
	return identity, token
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	userIdentity, token := s.getSessionValues(r)
	isLoggedIn := userIdentity != "" && token != ""

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"IsLoggedIn":     isLoggedIn,
		"UserIdentity":   userIdentity,
		"RSABits":        s.config.Yubico.RSABits,
		"UITitle":        s.config.UI.Title,
		"UIShortTitle":   s.config.UI.ShortTitle,
		"RevokeExisting": s.config.Vault.RevokeExisting,
	})
}

func (s *Server) handleSignCSR(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)
	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		renderError(w, "Upload exceeds 2MB payload limit.")
		return
	}

	selectedSlot := r.FormValue("slot")
	if selectedSlot != "9c" {
		selectedSlot = "9a"
	}

	userIdentity, userOIDCToken := s.getSessionValues(r)

	csrPEM, err := readFileFromForm(r, "csr")
	if err != nil {
		renderError(w, "Failed to read CSR file.")
		return
	}

	attestPEM, err := readFileFromForm(r, "attest")
	if err != nil {
		renderError(w, "Failed to read attestation certificate file.")
		return
	}

	intPEM, err := readFileFromForm(r, "intermediate")
	if err != nil {
		renderError(w, "Failed to read intermediate certificate file.")
		return
	}

	csr, err := s.verifyAttestation(csrPEM, attestPEM, intPEM, userIdentity)
	if err != nil {
		log.Printf("[SECURITY REJECTION] User: %s, Error: %v", userIdentity, err)
		renderError(w, fmt.Sprintf("Attestation Verification Failed: %v", err))
		return
	}

	// Step 1: Revoke existing certificates using Portal AppRole Credentials (if enabled)
	if s.config.Vault.RevokeExisting {
		if err := s.revokePreviousCertificates(csr.Subject.CommonName); err != nil {
			log.Printf("[WARN] Failed during revocation of previous certificates for user %s: %v", csr.Subject.CommonName, err)
		}
	}

	// Step 2: Sign new certificate using the USER'S delegated OIDC token
	vClient, err := vault.NewClient(s.vaultConfig)
	if err != nil {
		renderError(w, "Failed to connect to Vault service.")
		return
	}

	vaultAuthPath := fmt.Sprintf("auth/%s/login", s.config.Vault.AuthMount)
	authResp, err := vClient.Logical().Write(vaultAuthPath, map[string]interface{}{
		"jwt":  userOIDCToken,
		"role": s.config.Vault.AuthRole,
	})
	if err != nil || authResp == nil || authResp.Auth == nil {
		log.Printf("[VAULT AUTH ERROR] User: %s, Error: %v", userIdentity, err)
		renderError(w, "Vault rejected OIDC authentication.")
		return
	}

	clientToken := authResp.Auth.ClientToken
	vClient.SetToken(clientToken)

	if s.config.Server.Debug {
		log.Printf("[DEBUG] User: %s | Generated Vault Client Token: %s", userIdentity, clientToken)
		log.Printf("[DEBUG] Assigned Policies: %v", authResp.Auth.Policies)
	}

	vaultSignPath := fmt.Sprintf("%s/sign/%s", s.config.Vault.PKIMount, s.config.Vault.PKIRole)
	signResp, err := vClient.Logical().Write(vaultSignPath, map[string]interface{}{
		"csr":         string(csrPEM),
		"common_name": csr.Subject.CommonName,
	})
	if err != nil {
		log.Printf("[VAULT SIGN REJECTED] User: %s, Path: %s, Error: %v", userIdentity, vaultSignPath, err)
		renderError(w, "Vault PKI engine rejected the certificate signing request.")
		return
	}

	certData, ok := signResp.Data["certificate"].(string)
	if !ok {
		renderError(w, "Invalid response payload received from Vault PKI engine.")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div id="cert-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/80 backdrop-blur-sm animate-fade-in">
			<div class="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl shadow-2xl max-w-2xl w-full p-6 relative flex flex-col max-h-[90vh]">
				<div class="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-700 mb-4">
					<div class="flex items-center space-x-3">
						<div class="w-10 h-10 rounded-full bg-green-100 dark:bg-green-900/50 flex items-center justify-center text-green-600 dark:text-green-400">
							<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
						</div>
						<div>
							<h3 class="text-lg font-bold text-slate-900 dark:text-white">Certificate Issued Successfully</h3>
							<p class="text-xs text-slate-500 dark:text-slate-400">Hardware origin verified via YubiKey PIV Attestation Chain.</p>
						</div>
					</div>
					<button onclick="document.getElementById('cert-modal').remove()" type="button" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 transition cursor-pointer">
						<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
					</button>
				</div>

				<div class="relative flex-1 mb-4 space-y-3">
					<textarea id="issued-cert-text" readonly class="w-full h-60 p-4 font-mono text-xs border border-slate-200 dark:border-slate-700 rounded-xl bg-slate-900 text-green-400 focus:outline-none resize-none leading-relaxed">%s</textarea>
					
					<div class="p-3 bg-slate-100 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-700 rounded-xl">
						<p class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">Import Certificate into YubiKey:</p>
						<p class="text-[11px] text-slate-500 dark:text-slate-400 mb-2">First download the certificate, and ensure it is saved in the same directory where you executed the previous <code class="font-mono text-slate-700 dark:text-slate-300 bg-slate-200 dark:bg-slate-800 px-1 py-0.5 rounded">ykman</code> commands.</p>
						<div class="relative group">
							<button onclick="copyToClipboard(this, 'import-cmd-modal')" type="button" class="absolute top-1 right-1 p-1 rounded bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer" title="Copy code">
								<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
							</button>
							<code id="import-cmd-modal" class="block text-xs font-mono text-green-600 dark:text-green-400 pr-8 overflow-x-auto">ykman piv certificates import %s user.crt -v -m &lt;mgmt key&gt; -P &lt;pin&gt;</code>
						</div>
					</div>
				</div>

				<div class="flex items-center justify-end space-x-3 pt-2 border-t border-slate-200 dark:border-slate-700">
					<button onclick="copyCertToClipboard(this)" type="button" class="inline-flex items-center px-4 py-2.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 text-xs font-bold rounded-lg transition cursor-pointer">
						<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
						Copy to Clipboard
					</button>
					<button onclick="downloadCert()" type="button" class="inline-flex items-center px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition shadow-sm cursor-pointer">
						<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
						Download Certificate (.crt)
					</button>
				</div>
			</div>
		</div>
	`, template.HTMLEscapeString(certData), template.HTMLEscapeString(selectedSlot))
}

// Strictly revokes active, unexpired certificates matching the Common Name using Portal AppRole credentials
func (s *Server) revokePreviousCertificates(commonName string) error {
	if s.config.Vault.AppRoleRoleID == "" || s.config.Vault.AppRoleSecretID == "" {
		return errors.New("missing AppRole credentials in configuration for certificate revocation")
	}

	appClient, err := vault.NewClient(s.vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create Vault AppRole client: %w", err)
	}

	appRoleLoginPath := fmt.Sprintf("auth/%s/login", s.config.Vault.AppRoleMount)
	authResp, err := appClient.Logical().Write(appRoleLoginPath, map[string]interface{}{
		"role_id":   s.config.Vault.AppRoleRoleID,
		"secret_id": s.config.Vault.AppRoleSecretID,
	})
	if err != nil || authResp == nil || authResp.Auth == nil {
		return fmt.Errorf("AppRole authentication failed: %w", err)
	}

	appClient.SetToken(authResp.Auth.ClientToken)

	listPath := fmt.Sprintf("%s/certs", s.config.Vault.PKIMount)
	secret, err := appClient.Logical().List(listPath)
	if err != nil || secret == nil || secret.Data == nil {
		return nil
	}

	rawKeys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil
	}

	now := time.Now()

	for _, rawKey := range rawKeys {
		serial, ok := rawKey.(string)
		if !ok {
			continue
		}

		certSecret, err := appClient.Logical().Read(fmt.Sprintf("%s/cert/%s", s.config.Vault.PKIMount, serial))
		if err != nil || certSecret == nil || certSecret.Data == nil {
			continue
		}

		if revocationTime, ok := certSecret.Data["revocation_time"]; ok {
			var revTime int64
			switch v := revocationTime.(type) {
			case int64:
				revTime = v
			case float64:
				revTime = int64(v)
			case json.Number:
				revTime, _ = v.Int64()
			}
			if revTime > 0 {
				continue
			}
		}

		certPEM, ok := certSecret.Data["certificate"].(string)
		if !ok {
			continue
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if now.After(cert.NotAfter) {
			continue
		}

		if cert.Subject.CommonName == commonName {
			log.Printf("[APPROLE REVOCATION] Revoking prior active certificate (Serial: %s) for user: %s", serial, commonName)
			revokePath := fmt.Sprintf("%s/revoke", s.config.Vault.PKIMount)
			_, err := appClient.Logical().Write(revokePath, map[string]interface{}{
				"serial_number": serial,
			})
			if err != nil {
				log.Printf("[WARN] Failed to revoke serial %s: %v", serial, err)
			}
		}
	}

	return nil
}

func (s *Server) verifyAttestation(csrPEM, attestPEM, intPEM []byte, expectedIdentity string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR PEM format")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	rsaKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() != s.config.Yubico.RSABits {
		return nil, fmt.Errorf("key size mismatch: expected RSA %d-bit", s.config.Yubico.RSABits)
	}

	if csr.Subject.CommonName != expectedIdentity {
		return nil, fmt.Errorf("CSR Common Name '%s' does not match OIDC identity '%s'", csr.Subject.CommonName, expectedIdentity)
	}

	block, _ = pem.Decode(attestPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid attestation certificate PEM format")
	}
	attestCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	block, _ = pem.Decode(intPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid intermediate certificate PEM format")
	}
	intCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intCert)

	opts := x509.VerifyOptions{
		Roots:         s.yubicoRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := attestCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("attestation chain verification failed against Yubico Root CA: %w", err)
	}

	csrPubDER, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	attestPubDER, _ := x509.MarshalPKIXPublicKey(attestCert.PublicKey)
	if !bytes.Equal(csrPubDER, attestPubDER) {
		return nil, errors.New("CSR public key does not match hardware attestation public key")
	}

	isHardwareGenerated := false
	for _, ext := range attestCert.Extensions {
		if len(ext.Id) >= 6 && ext.Id[0] == 1 && ext.Id[1] == 3 && ext.Id[2] == 6 && ext.Id[3] == 1 && ext.Id[4] == 4 && ext.Id[5] == 1 {
			oidStr := ext.Id.String()
			if len(oidStr) >= 21 && oidStr[:21] == "1.3.6.1.4.1.41482.3.3" {
				isHardwareGenerated = true
				break
			}
		}
	}

	if !isHardwareGenerated {
		return nil, errors.New("key lacks Yubico hardware origin OIDs; must be generated inside the YubiKey")
	}

	return csr, nil
}

func installService() error {
	if os.Geteuid() != 0 {
		return errors.New("install must be run with root privileges (e.g. sudo ./yubivault --install)")
	}

	log.Println("Installing YubiVault systemd service...")

	log.Println("Creating yubivault system user...")
	execCmd("useradd", "--system", "--no-create-home", "--user-group", "yubivault")

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	targetBin := "/usr/local/bin/yubivault"
	if err := copyFile(execPath, targetBin, 0755); err != nil {
		return fmt.Errorf("failed to copy binary to %s: %w", targetBin, err)
	}
	log.Printf("Copied binary to %s", targetBin)

	etcDir := "/etc/yubivault"
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", etcDir, err)
	}

	if _, err := os.Stat("config.yaml"); err == nil {
		targetCfg := etcDir + "/config.yaml"
		if _, err := os.Stat(targetCfg); os.IsNotExist(err) {
			if err := copyFile("config.yaml", targetCfg, 0600); err == nil {
				log.Printf("Copied config.yaml to %s", targetCfg)
			}
		}
	}

	copyDirIfExists("templates", etcDir+"/templates")
	copyDirIfExists("static", etcDir+"/static")
	if _, err := os.Stat("yubico-roots.pem"); err == nil {
		_ = copyFile("yubico-roots.pem", etcDir+"/yubico-roots.pem", 0644)
	}

	log.Println("Setting ownership of /etc/yubivault to yubivault user...")
	execCmd("chown", "-R", "yubivault:yubivault", etcDir)

	serviceContent := `[Unit]
Description=YubiVault - Hardware Attested VPN Portal
After=network.target

[Service]
Type=simple
User=yubivault
Group=yubivault
WorkingDirectory=/etc/yubivault
ExecStart=/usr/local/bin/yubivault
Restart=always
RestartSec=5
Environment=CONFIG_FILE=/etc/yubivault/config.yaml

[Install]
WantedBy=multi-user.target
`
	servicePath := "/etc/systemd/system/yubivault.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}
	log.Printf("Created systemd service file at %s", servicePath)

	execCmd("systemctl", "daemon-reload")
	execCmd("systemctl", "enable", "yubivault")
	execCmd("systemctl", "start", "yubivault")

	log.Println("YubiVault service installed, enabled, and started successfully!")
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run with root privileges (e.g. sudo ./yubivault --uninstall)")
	}

	log.Println("Uninstalling YubiVault systemd service...")

	execCmd("systemctl", "stop", "yubivault")
	execCmd("systemctl", "disable", "yubivault")

	servicePath := "/etc/systemd/system/yubivault.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		log.Printf("[WARN] Failed to remove %s: %v", servicePath, err)
	} else {
		log.Printf("Removed %s", servicePath)
	}

	execCmd("systemctl", "daemon-reload")

	binPath := "/usr/local/bin/yubivault"
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[WARN] Failed to remove %s: %v", binPath, err)
	} else {
		log.Printf("Removed %s", binPath)
	}

	log.Println("Removing yubivault system user...")
	execCmd("userdel", "yubivault")

	log.Println("YubiVault systemd service uninstalled. Configuration directory /etc/yubivault was preserved.")
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func copyDirIfExists(srcDir, dstDir string) {
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = os.MkdirAll(dstDir, 0755)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		srcPath := srcDir + "/" + entry.Name()
		dstPath := dstDir + "/" + entry.Name()
		if !entry.IsDir() {
			_ = copyFile(srcPath, dstPath, 0644)
		}
	}
	log.Printf("Copied directory %s -> %s", srcDir, dstDir)
}

func execCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	_ = cmd.Run()
}

func readFileFromForm(r *http.Request, fieldName string) ([]byte, error) {
	file, _, err := r.FormFile(fieldName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func renderError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `
		<div class="p-4 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-200 rounded-lg">
			<h3 class="font-bold text-base mb-1">Request Rejected</h3>
			<p class="text-xs">%s</p>
		</div>
	`, template.HTMLEscapeString(msg))
}

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
