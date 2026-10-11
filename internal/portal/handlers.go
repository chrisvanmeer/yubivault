package portal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"

	"yubivault/internal/attestation"
	"yubivault/internal/config"
	"yubivault/internal/pki"
)

// issuedCert holds the properties of a freshly signed certificate shown in
// the success modal.
type issuedCert struct {
	CertPEM  string
	Serial   string
	CN       string
	Slot     string
	KeyType  string
	NotAfter string
	Issued   int
	Warnings []string
}

// ---------------------------------------------------------------------------
// Page & OAuth handlers
// ---------------------------------------------------------------------------

func (p *Portal) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Refresh the session cookie so an active visitor's login slides forward.
	if _, err := p.loadSession(w, r); err != nil {
		p.logger.Debug("session refresh failed", "error", err)
	}

	identity, token := p.sessionIdentity(r)
	isLoggedIn := identity != "" && token != ""

	data := map[string]any{
		"IsLoggedIn":          isLoggedIn,
		"UserIdentity":        identity,
		"CertCN":              attestation.NormalizeCN(identity),
		"KeyTypes":            keyTypeChoices(p.config),
		"UITitle":             p.config.UI.Title,
		"UIShortTitle":        p.config.UI.ShortTitle,
		"RevokeExisting":      p.config.Vault.RevokeExisting,
		"SingleKeyType":       len(p.config.AllowedKeyTypes()) == 1,
		"HasAppRole":          p.config.Vault.AppRoleRoleID != "" && p.config.Vault.AppRoleSecretID != "",
		"CertificatesEnabled": p.config.CertificatesEnabled(),
	}
	p.addManualData(data, r)
	p.renderTemplate(w, "index.html", data)
}

func (p *Portal) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (p *Portal) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	checks := map[string]string{"vault": "ok"}
	ready := true
	if err := p.pki.Healthy(); err != nil {
		checks["vault"] = err.Error()
		ready = false
	}
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": map[bool]string{true: "ready", false: "unavailable"}[ready],
		"checks": checks,
	})
}

func (p *Portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := newOAuthState()
	nonce := newOAuthState()

	session, err := p.cookieStore.Get(r, sessionName)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Unable to create a session. Please retry.")
		return
	}
	session.Values["oauth_state"] = state
	session.Values["oauth_nonce"] = nonce
	if err := session.Save(r, w); err != nil {
		renderError(w, http.StatusInternalServerError, "Unable to persist the session. Please retry.")
		return
	}

	authURL := p.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *Portal) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		desc := r.URL.Query().Get("error_description")
		renderError(w, http.StatusBadRequest,
			fmt.Sprintf("The identity provider rejected the login: %s %s", errMsg, desc))
		return
	}

	session, err := p.cookieStore.Get(r, sessionName)
	if err != nil {
		renderError(w, http.StatusBadRequest, "Session not found. Please log in again.")
		return
	}

	savedState, _ := session.Values["oauth_state"].(string)
	if savedState == "" || savedState != r.URL.Query().Get("state") {
		renderError(w, http.StatusBadRequest, "Invalid OAuth state token.")
		return
	}

	oauth2Token, err := p.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		p.logger.Error("OAuth token exchange failed", "error", err)
		renderError(w, http.StatusBadGateway, "OAuth token exchange failed.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		renderError(w, http.StatusBadGateway, "No ID token received from the identity provider.")
		return
	}

	savedNonce, _ := session.Values["oauth_nonce"].(string)
	idToken, err := p.oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		p.logger.Error("ID token verification failed", "error", err)
		renderError(w, http.StatusBadGateway, "ID token verification failed.")
		return
	}
	// go-oidc exposes the nonce but leaves the comparison to the caller.
	if savedNonce == "" || idToken.Nonce != savedNonce {
		renderError(w, http.StatusBadRequest, "Invalid OIDC nonce. Please log in again.")
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
	if err := attestation.ValidateIdentity(identity); err != nil {
		p.logger.Warn("rejected login due to unusable identity", "identity", identity, "error", err)
		renderError(w, http.StatusForbidden,
			"Your account name cannot be used as a certificate Common Name. Contact your administrator.")
		return
	}

	session.Values["user_identity"] = identity
	session.Values["raw_id_token"] = rawIDToken
	delete(session.Values, "oauth_state")
	delete(session.Values, "oauth_nonce")
	if err := session.Save(r, w); err != nil {
		renderError(w, http.StatusInternalServerError, "Unable to persist the session.")
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Portal) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := p.cookieStore.Get(r, sessionName)
	if err == nil {
		rawIDToken, _ := session.Values["raw_id_token"].(string)
		delete(session.Values, "user_identity")
		delete(session.Values, "raw_id_token")
		delete(session.Values, "oauth_state")
		delete(session.Values, "oauth_nonce")
		session.Options.MaxAge = -1
		_ = session.Save(r, w)

		// RP-initiated logout at the identity provider when configured.
		if p.endSessionURL != "" && p.config.OIDC.LogoutRedirectURI != "" {
			target := p.endSessionURL
			target = addQuery(target, "id_token_hint", rawIDToken)
			target = addQuery(target, "post_logout_redirect_uri", p.config.OIDC.LogoutRedirectURI)
			target = addQuery(target, "client_id", p.config.OIDC.ClientID)
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Certificate issuance
// ---------------------------------------------------------------------------

func (p *Portal) handleSignCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		renderError(w, http.StatusRequestEntityTooLarge, "Upload exceeds the 2MB payload limit.")
		return
	}

	identity, rawIDToken := p.sessionIdentity(r)
	if identity == "" || rawIDToken == "" {
		renderError(w, http.StatusUnauthorized, "Your session has expired. Please log in again.")
		return
	}
	cn := attestation.NormalizeCN(identity)
	if err := attestation.ValidateCN(cn); err != nil {
		renderError(w, http.StatusForbidden,
			"Your account name cannot be used as a certificate Common Name.")
		return
	}

	selectedSlot := r.FormValue("slot")
	if selectedSlot != "9a" && selectedSlot != "9c" {
		renderError(w, http.StatusBadRequest, "Invalid PIV slot selected.")
		return
	}

	selectedKeyType := r.FormValue("key_type")
	if selectedKeyType == "" {
		renderError(w, http.StatusBadRequest, "No key type selected.")
		return
	}
	if !isAllowedKeyType(p.config, selectedKeyType) {
		renderError(w, http.StatusBadRequest, fmt.Sprintf("Key type '%s' is not enabled.", selectedKeyType))
		return
	}

	csrPEM, err := readFileFromForm(r, "csr")
	if err != nil {
		renderError(w, http.StatusBadRequest, "Failed to read the CSR file.")
		return
	}
	attestPEM, err := readFileFromForm(r, "attest")
	if err != nil {
		renderError(w, http.StatusBadRequest, "Failed to read the attestation certificate file.")
		return
	}
	intPEM, err := readFileFromForm(r, "intermediate")
	if err != nil {
		renderError(w, http.StatusBadRequest, "Failed to read the intermediate certificate file.")
		return
	}

	csr, _, err := p.attest.Verify(csrPEM, attestPEM, intPEM, cn, selectedSlot, selectedKeyType)
	if err != nil {
		p.logger.Warn("attestation rejected",
			"identity", identity, "slot", selectedSlot, "key_type", selectedKeyType, "error", err)
		renderError(w, http.StatusBadRequest, fmt.Sprintf("Attestation verification failed: %v", err))
		return
	}

	// Determine whether the user already has a revocable certificate. The
	// confirmation warning is only rendered when one actually exists.
	var pendingRevocations []pki.ActiveCert
	if p.config.Vault.RevokeExisting {
		active, err := p.pki.FindActiveCertificates(cn)
		switch {
		case err != nil && p.pki.StrictRevocation():
			p.logger.Error("could not determine existing certificates", "identity", identity, "error", err)
			renderError(w, http.StatusBadGateway,
				"Unable to verify whether you already have an active certificate. Please try again later.")
			return
		case err != nil:
			p.logger.Warn("skipping revocation check (best_effort mode)", "identity", identity, "error", err)
		case len(active) > 0 && r.FormValue("confirm_revoke") != "true":
			w.WriteHeader(http.StatusConflict)
			p.renderTemplate(w, "confirm_revoke.html", map[string]any{
				"UserIdentity": identity,
				"CertCN":       cn,
				"ActiveCerts":  active,
			})
			return
		default:
			pendingRevocations = active
		}
	}

	certPEM, serial, err := p.pki.IssueCertificate(cn, string(csrPEM), rawIDToken)
	if err != nil {
		p.logger.Error("certificate signing failed", "identity", identity, "error", err)
		renderError(w, http.StatusBadGateway,
			"Vault rejected the certificate signing request.")
		return
	}

	issued := issuedCert{
		CertPEM: certPEM,
		Serial:  serial,
		CN:      csr.Subject.CommonName,
		Slot:    selectedSlot,
		KeyType: selectedKeyType,
		Issued:  len(pendingRevocations),
	}
	if parsed, err := pki.ParseCertificate(certPEM); err == nil {
		issued.NotAfter = parsed.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
		if parsed.Subject.CommonName != cn {
			issued.Warnings = append(issued.Warnings,
				fmt.Sprintf("Vault issued a certificate for CN '%s' instead of '%s'. Check the Vault PKI role configuration.",
					parsed.Subject.CommonName, cn))
		}
	}

	// Revoke previous certificates only after the new one was issued, so a
	// failed signing request never leaves the user without a certificate.
	if len(pendingRevocations) > 0 {
		toRevoke := make([]string, 0, len(pendingRevocations))
		for _, c := range pendingRevocations {
			if c.Serial == serial {
				continue
			}
			toRevoke = append(toRevoke, c.Serial)
		}
		if err := p.pki.RevokeCertificates(toRevoke); err != nil {
			p.logger.Error("revocation after issuance failed",
				"identity", identity, "serials", toRevoke, "error", err)
			issued.Warnings = append(issued.Warnings,
				fmt.Sprintf("The new certificate was issued, but %d previous certificate(s) could not be revoked. Revoke them manually in Vault.",
					len(toRevoke)))
		}
	}

	p.renderTemplate(w, "cert_modal.html", issued)
}

// handleActiveCert reports whether the authenticated user currently holds an
// active (non-revoked, non-expired) certificate.
func (p *Portal) handleActiveCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return
	}

	identity, _ := p.sessionIdentity(r)
	active, err := p.pki.FindActiveCertificates(attestation.NormalizeCN(identity))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		p.logger.Warn("active certificate lookup failed", "identity", identity, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false, "unknown": true})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"active": len(active) > 0,
		"count":  len(active),
	})
}

// handleInventory renders the certificate inventory using the portal
// AppRole credentials.
func (p *Portal) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/certs" {
		http.NotFound(w, r)
		return
	}

	identity, token := p.sessionIdentity(r)
	isLoggedIn := identity != "" && token != ""

	if !isLoggedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := map[string]any{
		"IsLoggedIn":          true,
		"UserIdentity":        identity,
		"CertCN":              attestation.NormalizeCN(identity),
		"UITitle":             p.config.UI.Title,
		"UIShortTitle":        p.config.UI.ShortTitle,
		"HasAppRole":          p.config.Vault.AppRoleRoleID != "" && p.config.Vault.AppRoleSecretID != "",
		"CertificatesEnabled": p.config.CertificatesEnabled(),
	}
	p.addManualData(data, r)

	if hasAppRole, _ := data["HasAppRole"].(bool); hasAppRole {
		certs, err := p.pki.ListCertificates()
		if err != nil {
			p.logger.Error("inventory listing failed", "identity", identity, "error", err)
			data["LoadError"] = err.Error()
		} else {
			activeCount := 0
			for _, c := range certs {
				if c.Active() {
					activeCount++
				}
			}
			data["Certs"] = certs
			data["ActiveCount"] = activeCount
		}
	}

	p.renderTemplate(w, "inventory.html", data)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readFileFromForm(r *http.Request, fieldName string) ([]byte, error) {
	file, _, err := r.FormFile(fieldName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

// manualDoc is one configured manual document (per OS or the fallback).
type manualDoc struct {
	Key   string
	Label string
	IsPDF bool
	HTML  template.HTML
	URL   string
}

// manualData bundles every available manual for the modal.
type manualData struct {
	Available bool
	Docs      []manualDoc
	Selected  string
}

// manualOSOrder controls the tab order of per-OS manuals.
var manualOSOrder = []string{"macos", "windows", "linux", "android", "ios"}

// manualOSLabels maps an OS key to a friendly tab label.
var manualOSLabels = map[string]string{
	"macos":   "macOS",
	"windows": "Windows",
	"linux":   "Linux",
	"android": "Android",
	"ios":     "iOS",
	"default": "Manual",
}

// manualLabel returns the display label for a manual key.
func manualLabel(key string) string {
	if l, ok := manualOSLabels[key]; ok {
		return l
	}
	if key == "" {
		return "Manual"
	}
	return strings.ToUpper(key[:1]) + key[1:]
}

// clientOS derives an OS key from the request's User-Agent.
func clientOS(r *http.Request) string {
	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"):
		return "ios"
	case strings.Contains(ua, "windows"):
		return "windows"
	case strings.Contains(ua, "mac os x"), strings.Contains(ua, "macintosh"):
		return "macos"
	case strings.Contains(ua, "linux"):
		return "linux"
	}
	return ""
}

// orderedManualKeys returns the configured manual keys in a stable, preferred
// order (macos, windows, linux, ...) followed by custom keys alphabetically.
func orderedManualKeys(paths map[string]string) []string {
	seen := make(map[string]bool, len(paths))
	keys := make([]string, 0, len(paths))
	for _, k := range manualOSOrder {
		if _, ok := paths[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0)
	for k := range paths {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

// docsContain reports whether key is present in docs.
func docsContain(docs []manualDoc, key string) bool {
	for _, d := range docs {
		if d.Key == key {
			return true
		}
	}
	return false
}

// manualAssetPrefix is the URL prefix under which manual media is served.
const manualAssetPrefix = "/manual/asset/"

// manualMarkdown renders the Markdown manuals. Relative image sources are
// rewritten to the manual asset endpoint so media stored alongside the manuals
// (inside ui.manual_dir) resolves correctly in the browser.
var manualMarkdown = goldmark.New(
	goldmark.WithExtensions(manualAssetExtension{prefix: manualAssetPrefix}),
)

// manualAssetExtension registers a renderer that rewrites relative image URLs.
type manualAssetExtension struct{ prefix string }

func (e manualAssetExtension) Extend(m goldmark.Markdown) {
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(&manualImageRenderer{prefix: e.prefix}, 500),
	))
}

// manualImageRenderer mirrors goldmark's default image renderer but prefixes
// relative destinations with the asset endpoint.
type manualImageRenderer struct{ prefix string }

func (r *manualImageRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindImage, r.renderImage)
}

func (r *manualImageRenderer) renderImage(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n, ok := node.(*ast.Image)
	if !ok {
		return ast.WalkContinue, nil
	}
	dest := string(n.Destination)
	if isRelativeAsset(dest) {
		dest = r.prefix + path.Clean(dest)
	}
	_, _ = w.WriteString(`<img src="`)
	_, _ = w.Write(util.EscapeHTML(util.URLEscape([]byte(dest), true)))
	_, _ = w.WriteString(`" alt="`)
	_, _ = w.Write(util.EscapeHTML(imageAltText(n, source)))
	_, _ = w.WriteString(`"`)
	if n.Title != nil {
		_, _ = w.WriteString(` title="`)
		_, _ = w.Write(util.EscapeHTML(n.Title))
		_, _ = w.WriteString(`"`)
	}
	_, _ = w.WriteString(">")
	return ast.WalkSkipChildren, nil
}

// imageAltText collects the plain-text alt label from an image node's
// children.
func imageAltText(n ast.Node, source []byte) []byte {
	var buf bytes.Buffer
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			buf.Write(t.Segment.Value(source))
		}
	}
	return buf.Bytes()
}

// isRelativeAsset reports whether u is a relative media reference that should
// be resolved against the manual asset endpoint.
func isRelativeAsset(u string) bool {
	if u == "" || strings.HasPrefix(u, "/") || strings.HasPrefix(u, "#") ||
		strings.HasPrefix(u, "data:") || strings.Contains(u, ":") {
		return false
	}
	return true
}

// loadManualDoc reads and prepares one manual document.
func (p *Portal) loadManualDoc(key, file string) (manualDoc, bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		p.logger.Warn("failed to read manual file", "path", file, "error", err)
		return manualDoc{}, false
	}
	doc := manualDoc{
		Key:   key,
		Label: manualLabel(key),
		URL:   "/manual/raw?os=" + urlQueryEscape(key),
	}
	if strings.EqualFold(filepath.Ext(file), ".pdf") {
		doc.IsPDF = true
		return doc, true
	}
	var buf bytes.Buffer
	if err := manualMarkdown.Convert(data, &buf); err != nil {
		p.logger.Warn("failed to render manual markdown", "path", file, "error", err)
		return manualDoc{}, false
	}
	// goldmark does not render raw HTML unless explicitly enabled, so this
	// output is safe to inject without additional sanitisation.
	doc.HTML = template.HTML(buf.String())
	return doc, true
}

// loadManuals prepares every configured manual and picks a default tab for the
// visitor based on the request's User-Agent.
func (p *Portal) loadManuals(r *http.Request) manualData {
	paths := p.config.ManualFiles()
	if len(paths) == 0 {
		return manualData{}
	}

	docs := make([]manualDoc, 0, len(paths))
	for _, key := range orderedManualKeys(paths) {
		if doc, ok := p.loadManualDoc(key, paths[key]); ok {
			docs = append(docs, doc)
		}
	}
	if len(docs) == 0 {
		return manualData{}
	}

	selected := clientOS(r)
	if _, ok := paths[selected]; !ok {
		selected = ""
	}
	if selected == "" {
		if _, ok := paths["default"]; ok {
			selected = "default"
		}
	}
	if !docsContain(docs, selected) {
		selected = docs[0].Key
	}
	return manualData{Available: true, Docs: docs, Selected: selected}
}

// addManualData injects the manual fields into a template data map.
func (p *Portal) addManualData(data map[string]any, r *http.Request) {
	m := p.loadManuals(r)
	data["ManualAvailable"] = m.Available
	data["ManualDocs"] = m.Docs
	data["ManualSelected"] = m.Selected
}

// handleManualRaw streams the configured manual document. Documents are served
// inline so they can be embedded; ?download=1 forces a download.
func (p *Portal) handleManualRaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return
	}
	path := p.config.ManualPath(r.URL.Query().Get("os"))
	if path == "" {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		p.logger.Error("failed to read manual file", "path", path, "error", err)
		http.Error(w, "Manual unavailable.", http.StatusInternalServerError)
		return
	}
	if strings.EqualFold(filepath.Ext(path), ".pdf") {
		w.Header().Set("Content-Type", "application/pdf")
	} else {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	}
	disposition := "inline"
	if r.URL.Query().Get("download") != "" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disposition, filepath.Base(path)))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// handleManualAsset serves media (images) referenced from the Markdown manuals.
// Only regular files inside ui.manual_dir are exposed; path traversal is
// neutralised before resolution.
func (p *Portal) handleManualAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return
	}
	base := filepath.Clean(p.config.ManualDir())
	if base == "" || base == "." {
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, manualAssetPrefix)
	full := filepath.Join(base, filepath.FromSlash(path.Clean("/"+rel)))
	if full != base && !strings.HasPrefix(full, base+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, full)
}

// isAllowedKeyType reports whether the administrator enabled keyType.
func isAllowedKeyType(cfg *config.Config, keyType string) bool {
	for _, kt := range cfg.AllowedKeyTypes() {
		if kt == keyType {
			return true
		}
	}
	return false
}
