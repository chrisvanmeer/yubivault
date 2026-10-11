// Package pki wraps the HashiCorp Vault PKI operations the portal performs:
// user delegated signing, AppRole driven inventory and revocation.
package pki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// Options configures the PKI service.
type Options struct {
	Address         string
	PKIMount        string
	PKIRole         string
	AuthMount       string
	AuthRole        string
	AppRoleMount    string
	AppRoleRoleID   string
	AppRoleSecretID string
	RevokeExisting  bool
	RevokeMode      string
	CertTTL         string
	CertTTLMax      string
}

// ActiveCert describes a certificate that exists in the Vault PKI engine.
type ActiveCert struct {
	Serial   string    `json:"serial"`
	CN       string    `json:"cn"`
	NotAfter time.Time `json:"not_after"`
	Revoked  bool      `json:"revoked"`
	Expired  bool      `json:"expired"`
}

// Active reports whether the certificate is currently usable.
func (a ActiveCert) Active() bool { return !a.Revoked && !a.Expired }

// Service performs PKI operations against Vault.
type Service struct {
	opts        Options
	vaultConfig *vault.Config
}

// New builds a PKI service and validates the required options.
func New(opts Options) (*Service, error) {
	if opts.Address == "" {
		return nil, errors.New("vault address is required")
	}
	if opts.PKIMount == "" || opts.PKIRole == "" {
		return nil, errors.New("vault PKI mount and role are required")
	}
	vConfig := vault.DefaultConfig()
	vConfig.Address = opts.Address
	vConfig.Timeout = 15 * time.Second
	return &Service{opts: opts, vaultConfig: vConfig}, nil
}

// RevokeExisting reports whether the administrator wants previous
// certificates revoked on issuance.
func (s *Service) RevokeExisting() bool { return s.opts.RevokeExisting }

// StrictRevocation reports whether revocation failures must abort the request.
func (s *Service) StrictRevocation() bool { return s.opts.RevokeMode == "strict" }

// CheckAppRole validates the configured portal AppRole credentials by
// performing a login. It is used by --check-config and the readiness probe.
func (s *Service) CheckAppRole() error {
	_, err := s.appRoleClient()
	return err
}

func (s *Service) newClient() (*vault.Client, error) {
	return vault.NewClient(s.vaultConfig)
}

// appRoleClient authenticates with the portal's own AppRole credentials.
// These are only used for inventory and revocation, never to issue
// certificates on behalf of a user.
func (s *Service) appRoleClient() (*vault.Client, error) {
	if s.opts.AppRoleRoleID == "" || s.opts.AppRoleSecretID == "" {
		return nil, errors.New("missing AppRole credentials in configuration")
	}
	client, err := s.newClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	path := fmt.Sprintf("auth/%s/login", s.opts.AppRoleMount)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"role_id":   s.opts.AppRoleRoleID,
		"secret_id": s.opts.AppRoleSecretID,
	})
	if err != nil {
		return nil, fmt.Errorf("AppRole authentication failed: %w", err)
	}
	if resp == nil || resp.Auth == nil {
		return nil, errors.New("AppRole authentication returned no auth info")
	}
	client.SetToken(resp.Auth.ClientToken)
	return client, nil
}

// IssueCertificate exchanges the user's raw ID token for a Vault token and
// signs the CSR with it, so the certificate is always issued in the name of
// the authenticated user. The TTL is only sent when the administrator
// configured one; otherwise Vault applies its own role defaults.
func (s *Service) IssueCertificate(cn, csrPEM, rawIDToken string) (string, string, error) {
	client, err := s.newClient()
	if err != nil {
		return "", "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	loginPath := fmt.Sprintf("auth/%s/login", s.opts.AuthMount)
	resp, err := client.Logical().Write(loginPath, map[string]interface{}{
		"jwt":  rawIDToken,
		"role": s.opts.AuthRole,
	})
	if err != nil {
		return "", "", fmt.Errorf("vault rejected OIDC authentication: %w", err)
	}
	if resp == nil || resp.Auth == nil {
		return "", "", errors.New("vault returned no auth info for OIDC login")
	}
	client.SetToken(resp.Auth.ClientToken)

	signPath := fmt.Sprintf("%s/sign/%s", s.opts.PKIMount, s.opts.PKIRole)
	payload := map[string]interface{}{
		"csr":         csrPEM,
		"common_name": cn,
	}
	if s.opts.CertTTL != "" {
		payload["ttl"] = s.opts.CertTTL
	}
	if s.opts.CertTTLMax != "" {
		payload["ttl_max"] = s.opts.CertTTLMax
	}

	signResp, err := client.Logical().Write(signPath, payload)
	if err != nil {
		return "", "", fmt.Errorf("vault PKI rejected the signing request: %w", err)
	}
	if signResp == nil || signResp.Data == nil {
		return "", "", errors.New("vault PKI returned an empty response")
	}
	certPEM, ok := signResp.Data["certificate"].(string)
	if !ok || certPEM == "" {
		return "", "", errors.New("vault PKI response did not contain a certificate")
	}
	serial, _ := signResp.Data["serial_number"].(string)
	return certPEM, serial, nil
}

// FindActiveCertificates returns non-revoked, non-expired certificates whose
// Common Name equals cn.
func (s *Service) FindActiveCertificates(cn string) ([]ActiveCert, error) {
	client, err := s.appRoleClient()
	if err != nil {
		return nil, err
	}
	certs, err := s.listCertificates(client, cn)
	if err != nil {
		return nil, err
	}
	active := make([]ActiveCert, 0, len(certs))
	for _, c := range certs {
		if c.Active() {
			active = append(active, c)
		}
	}
	return active, nil
}

// ListCertificates returns every certificate in the PKI engine, marking the
// ones that are revoked or expired.
func (s *Service) ListCertificates() ([]ActiveCert, error) {
	client, err := s.appRoleClient()
	if err != nil {
		return nil, err
	}
	return s.listCertificates(client, "")
}

func (s *Service) listCertificates(client *vault.Client, filterCN string) ([]ActiveCert, error) {
	listPath := fmt.Sprintf("%s/certs", s.opts.PKIMount)
	secret, err := client.Logical().List(listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates in '%s': %w", listPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	rawKeys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}

	now := time.Now()
	certs := make([]ActiveCert, 0, len(rawKeys))
	for _, raw := range rawKeys {
		serial, ok := raw.(string)
		if !ok {
			continue
		}
		entry, err := readCertificate(client, s.opts.PKIMount, serial, now)
		if err != nil {
			slog.Warn("skipping certificate during inventory", "serial", serial, "error", err)
			continue
		}
		if filterCN != "" && entry.CN != filterCN {
			continue
		}
		certs = append(certs, entry)
	}

	sortCertificates(certs)
	return certs, nil
}

// sortCertificates orders certificates from most to least recent. NotAfter is
// the best available proxy for issuance time: with a fixed TTL, a later
// issuance expires later. Ties break on serial, descending.
func sortCertificates(certs []ActiveCert) {
	sort.SliceStable(certs, func(i, j int) bool {
		if certs[i].NotAfter.Equal(certs[j].NotAfter) {
			return certs[i].Serial > certs[j].Serial
		}
		return certs[i].NotAfter.After(certs[j].NotAfter)
	})
}

// RevokeCertificates revokes the given serials and reports how many failed.
func (s *Service) RevokeCertificates(serials []string) error {
	if len(serials) == 0 {
		return nil
	}
	client, err := s.appRoleClient()
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/revoke", s.opts.PKIMount)
	var failed []string
	for _, serial := range serials {
		if _, err := client.Logical().Write(path, map[string]interface{}{"serial_number": serial}); err != nil {
			slog.Error("failed to revoke certificate", "serial", serial, "error", err)
			failed = append(failed, serial)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to revoke %d of %d certificates (%v)", len(failed), len(serials), failed)
	}
	return nil
}

// Healthy reports whether the Vault server is reachable.
func (s *Service) Healthy() error {
	client, err := s.newClient()
	if err != nil {
		return err
	}
	health, err := client.Sys().Health()
	if err != nil {
		return err
	}
	if health == nil {
		return errors.New("empty health response")
	}
	return nil
}

func readCertificate(client *vault.Client, mount, serial string, now time.Time) (ActiveCert, error) {
	secret, err := client.Logical().Read(fmt.Sprintf("%s/cert/%s", mount, serial))
	if err != nil {
		return ActiveCert{}, err
	}
	if secret == nil || secret.Data == nil {
		return ActiveCert{}, fmt.Errorf("empty response for serial %s", serial)
	}

	entry := ActiveCert{Serial: serial}

	if v, ok := secret.Data["revocation_time"]; ok {
		if revTime, ok := toInt64(v); ok && revTime > 0 {
			entry.Revoked = true
		}
	}
	if cn, ok := secret.Data["common_name"].(string); ok {
		entry.CN = cn
	}
	if notAfter, ok := toInt64(secret.Data["expiration"]); ok && notAfter > 0 {
		entry.NotAfter = time.Unix(notAfter, 0)
	}

	if entry.CN == "" || entry.NotAfter.IsZero() {
		if parsed, err := ParseCertificatePEMField(secret.Data); err == nil {
			if entry.CN == "" {
				entry.CN = parsed.Subject.CommonName
			}
			if entry.NotAfter.IsZero() {
				entry.NotAfter = parsed.NotAfter
			}
		}
	}

	if !entry.NotAfter.IsZero() && now.After(entry.NotAfter) {
		entry.Expired = true
	}
	return entry, nil
}

// ParseCertificatePEMField extracts the PEM certificate from a Vault secret
// payload.
func ParseCertificatePEMField(data map[string]interface{}) (*x509.Certificate, error) {
	certPEM, ok := data["certificate"].(string)
	if !ok {
		return nil, errors.New("no certificate field in response")
	}
	return ParseCertificate(certPEM)
}

// ParseCertificate parses a PEM encoded certificate.
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func toInt64(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n, true
		}
		if f, err := t.Float64(); err == nil {
			return int64(f), true
		}
		return 0, false
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n, true
		}
		return 0, false
	default:
		return 0, false
	}
}
