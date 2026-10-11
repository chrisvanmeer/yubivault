// Package attestation verifies that a certificate signing request originates
// from a key generated inside a genuine YubiKey PIV slot.
package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// yubicoOriginOID is the Yubico key origin prefix: any extension under
// 1.3.6.1.4.1.41482.3.3.x asserts the key was generated inside a YubiKey.
var yubicoOriginOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}

var (
	identityRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,254}$`)
	cnRe       = regexp.MustCompile(`^[a-z0-9._+-]{1,64}$`)
	attestCNRe = regexp.MustCompile(`(?i)^YubiKey PIV Attestation (9a|9c)$`)
)

// Options configures a Verifier.
type Options struct {
	// Roots must contain the operator supplied Yubico PIV root CAs only.
	Roots *x509.CertPool
	// AllowedKeyTypes lists the configured key types, e.g. rsa3072, eccp256.
	AllowedKeyTypes []string
	// StrictSlotCheck requires the attestation subject to name the selected
	// PIV slot.
	StrictSlotCheck bool
}

// Verifier validates YubiKey PIV attestation chains.
type Verifier struct {
	roots           *x509.CertPool
	allowedKeyTypes map[string]bool
	strictSlotCheck bool
}

// New builds a Verifier from the given options.
func New(opts Options) (*Verifier, error) {
	if opts.Roots == nil {
		return nil, errors.New("attestation root certificate pool is required")
	}
	allowed := make(map[string]bool, len(opts.AllowedKeyTypes))
	for _, kt := range opts.AllowedKeyTypes {
		allowed[kt] = true
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one allowed key type is required")
	}
	return &Verifier{
		roots:           opts.Roots,
		allowedKeyTypes: allowed,
		strictSlotCheck: opts.StrictSlotCheck,
	}, nil
}

// LoadRoots builds a certificate pool that ONLY contains the operator
// supplied Yubico roots. Falling back to the system trust store would let any
// locally trusted CA forge a hardware attestation, so a missing or unreadable
// file is an error.
func LoadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("no Yubico root CA file configured")
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Yubico Root CA file '%s': %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid PEM certificates found in '%s'", path)
	}
	return pool, nil
}

// NormalizeCN derives the certificate Common Name from an OIDC identity:
// everything before the first '@', lowercased. "Chris@Example.com" -> "chris".
func NormalizeCN(identity string) string {
	local := identity
	if i := strings.IndexByte(identity, '@'); i >= 0 {
		local = identity[:i]
	}
	return strings.ToLower(local)
}

// ValidateIdentity rejects identities that cannot produce a safe Common Name
// or safe terminal command lines in the portal UI.
func ValidateIdentity(identity string) error {
	if !identityRe.MatchString(identity) {
		return errors.New("identity contains unsupported characters")
	}
	return ValidateCN(NormalizeCN(identity))
}

// ValidateCN checks that a Common Name is safe to embed in terminal commands.
func ValidateCN(cn string) error {
	if !cnRe.MatchString(cn) {
		return fmt.Errorf(
			"common name '%s' must be 1-64 chars of a-z, 0-9, dot, underscore, plus or hyphen", cn)
	}
	return nil
}

// Verify proves that the CSR was produced by a key generated inside a
// genuine YubiKey PIV slot. It returns the parsed CSR and the attestation
// certificate for display purposes.
func (v *Verifier) Verify(csrPEM, attestPEM, intPEM []byte, expectedCN, selectedSlot, selectedKeyType string) (*x509.CertificateRequest, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("invalid CSR PEM format")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR self-signature is invalid: %w", err)
	}

	if err := ValidateCN(expectedCN); err != nil {
		return nil, nil, err
	}
	if csr.Subject.CommonName != expectedCN {
		return nil, nil, fmt.Errorf(
			"CSR Common Name '%s' must be '%s' (lowercase username, without domain)",
			csr.Subject.CommonName, expectedCN)
	}

	keyType, err := PublicKeyType(csr.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if !v.allowedKeyTypes[keyType] {
		return nil, nil, fmt.Errorf(
			"key type '%s' is not enabled by the administrator (allowed: %s)",
			keyType, strings.Join(v.sortedAllowed(), ", "))
	}
	if selectedKeyType != "" && selectedKeyType != keyType {
		return nil, nil, fmt.Errorf(
			"selected key type '%s' does not match the attested key type '%s'",
			selectedKeyType, keyType)
	}

	block, _ = pem.Decode(attestPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid attestation certificate PEM format")
	}
	attestCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	block, _ = pem.Decode(intPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid intermediate certificate PEM format")
	}
	intCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intCert)

	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := attestCert.Verify(opts); err != nil {
		return nil, nil, fmt.Errorf("attestation chain verification failed against Yubico Root CA: %w", err)
	}

	csrPubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode CSR public key: %w", err)
	}
	attestPubDER, err := x509.MarshalPKIXPublicKey(attestCert.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode attestation public key: %w", err)
	}
	if !bytes.Equal(csrPubDER, attestPubDER) {
		return nil, nil, errors.New("CSR public key does not match hardware attestation public key")
	}

	if err := v.verifySlot(attestCert, selectedSlot); err != nil {
		return nil, nil, err
	}

	if !HasYubicoOriginOID(attestCert) {
		return nil, nil, errors.New(
			"key lacks Yubico hardware origin OIDs; the key must be generated inside the YubiKey")
	}

	return csr, attestCert, nil
}

// verifySlot ensures the attestation statement was created for the PIV slot
// the user selected in the portal. Attestation subjects follow the Yubico
// naming scheme "YubiKey PIV Attestation 9a".
func (v *Verifier) verifySlot(attestCert *x509.Certificate, selectedSlot string) error {
	m := attestCNRe.FindStringSubmatch(attestCert.Subject.CommonName)
	if m == nil {
		if v.strictSlotCheck {
			return fmt.Errorf(
				"attestation certificate subject '%s' does not match the expected Yubico PIV attestation naming scheme",
				attestCert.Subject.CommonName)
		}
		return nil
	}
	if !strings.EqualFold(m[1], selectedSlot) {
		return fmt.Errorf("attestation is for PIV slot %s but slot %s was selected in the portal",
			strings.ToLower(m[1]), selectedSlot)
	}
	return nil
}

// HasYubicoOriginOID reports whether the certificate carries a Yubico key
// origin extension (1.3.6.1.4.1.41482.3.3.x).
func HasYubicoOriginOID(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if len(ext.Id) < len(yubicoOriginOID) {
			continue
		}
		if ext.Id[:len(yubicoOriginOID)].Equal(yubicoOriginOID) {
			return true
		}
	}
	return false
}

// PublicKeyType maps a public key to a configured key type name.
func PublicKeyType(pub any) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen()), nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "eccp256", nil
		case elliptic.P384():
			return "eccp384", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

func (v *Verifier) sortedAllowed() []string {
	out := make([]string, 0, len(v.allowedKeyTypes))
	for _, kt := range []string{"rsa2048", "rsa3072", "rsa4096", "eccp256", "eccp384"} {
		if v.allowedKeyTypes[kt] {
			out = append(out, kt)
		}
	}
	return out
}
