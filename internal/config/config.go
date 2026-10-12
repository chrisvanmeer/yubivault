package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RevokeModeStrict     = "strict"
	RevokeModeBestEffort = "best_effort"
	MinSessionSecretLen  = 32
	DefaultRatePerMin    = 10

	defaultLogDir   = "/var/log/yubivault"
	defaultLogFile  = "yubivault.log"
	defaultLogOwner = "yubivault"
	defaultLogGroup = "yubivault"

	exampleSessionSecret = "super-secret-32-byte-key-here!!"

	// DefaultCNPattern is the default cn.pattern: a shell-safe set of
	// characters, at most 64 long. It is matched against the whole CN.
	DefaultCNPattern = "[a-z0-9._+@-]{1,64}"

	// defaultSessionMaxAge is the absolute login session lifetime.
	defaultSessionMaxAge = time.Hour
	// defaultSessionIdleTimeout is the per-session inactivity limit.
	defaultSessionIdleTimeout = 30 * time.Minute
)

// versionRe accepts a firmware version such as "5.4.3" or "2.4.4".
var versionRe = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// unsignedRe accepts a non-negative integer such as a YubiKey serial number.
var unsignedRe = regexp.MustCompile(`^[0-9]+$`)

// deviceFPRe accepts a normalized device fingerprint "sha256:" + 64 hex.
var deviceFPRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// cnPlaceholders are the placeholders understood in cn.template.
var cnPlaceholders = []string{"{user}", "{email}", "{domain}"}

// cnPlaceholderRe matches any {..} token so unknown placeholders are reported.
var cnPlaceholderRe = regexp.MustCompile(`\{[^}]*\}`)

// cnLiteralRe matches the characters a template may contain outside its
// placeholders. The rendered CN is lowercased before validation.
var cnLiteralRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]*$`)

// supportedKeyTypes maps the configured key type to the canonical ykman
// algorithm name.
var supportedKeyTypes = map[string]string{
	"rsa2048": "RSA2048",
	"rsa3072": "RSA3072",
	"rsa4096": "RSA4096",
	"eccp256": "ECCP256",
	"eccp384": "ECCP384",
}

// YkmanAlgorithm returns the ykman algorithm name for a configured key type.
func YkmanAlgorithm(keyType string) (string, bool) {
	algo, ok := supportedKeyTypes[keyType]
	return algo, ok
}

// SupportedKeyTypes returns every key type the portal understands.
func SupportedKeyTypes() []string {
	return []string{"rsa2048", "rsa3072", "rsa4096", "eccp256", "eccp384"}
}

type Config struct {
	Server struct {
		ListenAddr     string `yaml:"listen_addr"`
		SessionSecret  string `yaml:"session_secret"`
		Debug          bool   `yaml:"debug"`
		CookieSecure   *bool  `yaml:"cookie_secure"`
		RateLimitLogin int    `yaml:"rate_limit_login_per_min"`
		RateLimitSign  int    `yaml:"rate_limit_sign_per_min"`
		// SessionMaxAge bounds the absolute lifetime of a login session
		// (default 1h), regardless of activity.
		SessionMaxAge string `yaml:"session_max_age"`
		// SessionIdleTimeout logs a user out when they have not made a request
		// for this long (default 30m). It must not exceed SessionMaxAge.
		SessionIdleTimeout string `yaml:"session_idle_timeout"`
	} `yaml:"server"`
	UI struct {
		Title               string `yaml:"title"`
		ShortTitle          string `yaml:"short_title"`
		CertificatesEnabled *bool  `yaml:"certificates_enabled"`
		// ManualDir is the single directory that holds the manuals and any media
		// (images) they reference. ManualFile and Manuals are resolved relative
		// to it unless they are absolute. Media referenced from Markdown is
		// served from this directory at /manual/asset/.
		ManualDir string `yaml:"manual_dir"`
		// ManualFile points at an optional PDF or Markdown manual shown when no
		// per-OS entry in Manuals matches the visitor. When empty no fallback
		// manual is offered.
		ManualFile string `yaml:"manual_file"`
		// Manuals maps an OS label (macos, windows, linux, ...) to a PDF or
		// Markdown manual. The UI shows one tab per entry and preselects the
		// visitor's OS.
		Manuals map[string]string `yaml:"manuals"`
	} `yaml:"ui"`
	CN struct {
		// Template renders the certificate Common Name. Supported
		// placeholders: {user} (the local part of the OIDC identity,
		// lowercased), {email} (the OIDC email claim, falling back to the
		// identity) and {domain}. Literal text (prefixes/suffixes) is
		// allowed, e.g. "{user}@{domain}".
		Template string `yaml:"template"`
		// Domain substitutes the {domain} placeholder in Template.
		Domain string `yaml:"domain"`
		// Pattern is a RE2 regular expression the final Common Name must
		// match in full. It complements the built-in shell-safe check.
		Pattern string `yaml:"pattern"`
		// AllowUserOverride lets the visitor edit the Common Name in the UI.
		// The value is still validated against Template's placeholders and
		// Pattern by the server.
		AllowUserOverride bool `yaml:"allow_user_override"`
	} `yaml:"cn"`
	Vault struct {
		Address         string `yaml:"address"`
		PKIMount        string `yaml:"pki_mount"`
		PKIRole         string `yaml:"pki_role"`
		AuthMount       string `yaml:"auth_mount"`
		AuthRole        string `yaml:"auth_role"`
		RevokeExisting  bool   `yaml:"revoke_existing"`
		RevokeMode      string `yaml:"revoke_mode"`
		AppRoleMount    string `yaml:"approle_mount"`
		AppRoleRoleID   string `yaml:"approle_role_id"`
		AppRoleSecretID string `yaml:"approle_secret_id"`
		CertTTL         string `yaml:"cert_ttl"`
		CertTTLMax      string `yaml:"cert_ttl_max"`
	} `yaml:"vault"`
	OIDC struct {
		Issuer            string `yaml:"issuer"`
		ClientID          string `yaml:"client_id"`
		ClientSecret      string `yaml:"client_secret"`
		RedirectURL       string `yaml:"redirect_url"`
		LogoutRedirectURI string `yaml:"logout_redirect_uri"`
		// AllowedGroups restricts certificate issuance (and the derived
		// inventory/manual endpoints) to OIDC users holding at least one of
		// these groups. An empty list allows every authenticated user.
		AllowedGroups []string `yaml:"allowed_groups"`
		// GroupsClaim names the ID token claim that carries the user's group
		// memberships. It defaults to "groups" and may hold a delimited string
		// or an array of strings.
		GroupsClaim string `yaml:"groups_claim"`
	} `yaml:"oidc"`
	Yubico struct {
		RootCAFile      string   `yaml:"root_ca_file"`
		RSABits         int      `yaml:"rsa_bits"` // legacy, superseded by key_types
		KeyTypes        []string `yaml:"key_types"`
		StrictSlotCheck *bool    `yaml:"strict_slot_check"`
		// MinFirmware rejects YubiKeys whose attestation reports a firmware
		// version below the given major.minor.patch. An attestation without a
		// firmware version is also rejected (fail-closed). Empty disables.
		MinFirmware string `yaml:"min_firmware"`
		// MinSerial rejects YubiKeys whose attestation serial number is below
		// this value. An attestation without a serial is also rejected when
		// set (fail-closed). Empty disables.
		MinSerial string `yaml:"min_serial"`
		// DeviceFingerprints is an optional per-Common-Name allowlist of device
		// fingerprints (sha256:...) from the attestation certificate public
		// key. Only Common Names listed here are pinned; when a CN has no
		// entry its key may be used from any device. The fingerprint is always
		// recorded in the audit trail.
		DeviceFingerprints map[string][]string `yaml:"device_fingerprints"`
	} `yaml:"yubico"`
	Logging struct {
		// Dir is the directory log files are written to. A nil value selects
		// the default (/var/log/yubivault); an explicit empty string disables
		// file logging so logs go to stderr/journald only.
		Dir   *string `yaml:"dir"`
		File  string  `yaml:"file"`
		Owner string  `yaml:"owner"`
		Group string  `yaml:"group"`
	} `yaml:"logging"`
	Audit struct {
		// Enabled toggles the append-only audit trail. It defaults to true.
		// Because the audit trail is the security record of a CA front-end, an
		// enabled audit log must be writable or the process refuses to start.
		Enabled *bool `yaml:"enabled"`
		// Dir is the directory the audit log is written to. It defaults to
		// logging.dir. When file logging is disabled (logging.dir is empty)
		// this must be set explicitly.
		Dir *string `yaml:"dir"`
		// File is the audit log file name inside audit.dir.
		File string `yaml:"file"`
	} `yaml:"audit"`

	// logDirExplicit records whether logging.dir was present in the file (as
	// opposed to being defaulted). It is set by Load.
	logDirExplicit bool
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// CookieSecure reports whether session cookies carry the Secure attribute.
func (c *Config) CookieSecure() bool { return boolOr(c.Server.CookieSecure, true) }

// SessionMaxAge is the absolute lifetime of a login session.
func (c *Config) SessionMaxAge() time.Duration {
	if d, err := time.ParseDuration(c.Server.SessionMaxAge); err == nil {
		return d
	}
	return defaultSessionMaxAge
}

// SessionIdleTimeout is the inactivity limit of a login session.
func (c *Config) SessionIdleTimeout() time.Duration {
	if d, err := time.ParseDuration(c.Server.SessionIdleTimeout); err == nil {
		return d
	}
	return defaultSessionIdleTimeout
}

// StrictSlotCheck reports whether the attestation subject must name the PIV
// slot the user selected.
func (c *Config) StrictSlotCheck() bool { return boolOr(c.Yubico.StrictSlotCheck, true) }

// CertificatesEnabled reports whether the certificate inventory page is
// exposed to users. It defaults to true.
func (c *Config) CertificatesEnabled() bool { return boolOr(c.UI.CertificatesEnabled, true) }

// ManualDir returns the directory that holds the manuals and their media.
func (c *Config) ManualDir() string { return c.UI.ManualDir }

// resolveManual joins a configured manual path with ui.manual_dir unless it is
// already absolute. It returns "" for an empty path.
func (c *Config) resolveManual(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.UI.ManualDir, p)
}

// ManualFiles returns every configured manual as a key -> resolved path map,
// with the fallback ui.manual_file stored under the "default" key. Paths are
// resolved against ui.manual_dir when relative.
func (c *Config) ManualFiles() map[string]string {
	files := make(map[string]string, len(c.UI.Manuals)+1)
	for key, p := range c.UI.Manuals {
		if resolved := c.resolveManual(p); resolved != "" {
			files[key] = resolved
		}
	}
	if resolved := c.resolveManual(c.UI.ManualFile); resolved != "" {
		files["default"] = resolved
	}
	return files
}

// ManualPath resolves the manual document for an OS key, falling back to the
// single ui.manual_file. It returns "" when no manual is configured.
func (c *Config) ManualPath(osKey string) string {
	if osKey != "" {
		if p, ok := c.UI.Manuals[osKey]; ok {
			if resolved := c.resolveManual(p); resolved != "" {
				return resolved
			}
		}
	}
	return c.resolveManual(c.UI.ManualFile)
}

// CNTemplate returns the configured Common Name template.
func (c *Config) CNTemplate() string { return c.CN.Template }

// CNDomain returns the domain substituted for the {domain} placeholder.
func (c *Config) CNDomain() string { return c.CN.Domain }

// CNPattern returns the RE2 pattern the final Common Name must match in full.
func (c *Config) CNPattern() string { return c.CN.Pattern }

// AllowCNOverride reports whether the visitor may edit the Common Name in the
// UI. It defaults to false.
func (c *Config) AllowCNOverride() bool { return c.CN.AllowUserOverride }

// compileCNPattern anchors the configured pattern so it must match the whole
// Common Name, not just a substring.
func compileCNPattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("^(?:" + pattern + ")$")
}

// ValidateCNPattern reports whether cn satisfies the configured cn.pattern.
func (c *Config) ValidateCNPattern(cn string) error {
	re, err := compileCNPattern(c.CN.Pattern)
	if err != nil {
		return fmt.Errorf("cn.pattern is not a valid regular expression: %w", err)
	}
	if !re.MatchString(cn) {
		return fmt.Errorf("common name '%s' does not match the required format", cn)
	}
	return nil
}

// RateLimitLogin is the allowed number of login attempts per minute per IP.
func (c *Config) RateLimitLogin() int {
	if c.Server.RateLimitLogin <= 0 {
		return DefaultRatePerMin
	}
	return c.Server.RateLimitLogin
}

// RateLimitSign is the allowed number of signing requests per minute per IP.
func (c *Config) RateLimitSign() int {
	if c.Server.RateLimitSign <= 0 {
		return DefaultRatePerMin
	}
	return c.Server.RateLimitSign
}

// AllowedKeyTypes returns the normalized, ordered list of key types the
// administrator allows users to choose from.
func (c *Config) AllowedKeyTypes() []string {
	if len(c.Yubico.KeyTypes) > 0 {
		return c.Yubico.KeyTypes
	}
	if c.Yubico.RSABits != 0 {
		return []string{fmt.Sprintf("rsa%d", c.Yubico.RSABits)}
	}
	return []string{"rsa3072"}
}

// Load reads, defaults and validates the configuration file.
func Load(path string) (*Config, error) {
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

	cfg.logDirExplicit = cfg.Logging.Dir != nil
	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration in '%s': %w", path, err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = "127.0.0.1:8080"
	}
	if c.UI.Title == "" {
		c.UI.Title = "YubiVault Portal"
	}
	if c.UI.ShortTitle == "" {
		c.UI.ShortTitle = "YBV"
	}
	if c.Vault.PKIMount == "" {
		c.Vault.PKIMount = "pki_int"
	}
	if c.Vault.PKIRole == "" {
		c.Vault.PKIRole = "openvpn-nl"
	}
	if c.Vault.AuthMount == "" {
		c.Vault.AuthMount = "oidc"
	}
	if c.Vault.AuthRole == "" {
		c.Vault.AuthRole = "default"
	}
	if c.Vault.AppRoleMount == "" {
		c.Vault.AppRoleMount = "approle"
	}
	if c.Vault.RevokeMode == "" {
		c.Vault.RevokeMode = RevokeModeStrict
	}
	if c.CN.Template == "" {
		c.CN.Template = "{user}"
	}
	if c.CN.Pattern == "" {
		c.CN.Pattern = DefaultCNPattern
	}
	if c.Yubico.RootCAFile == "" {
		c.Yubico.RootCAFile = "yubico-roots.pem"
	}
	if c.Yubico.RSABits == 0 && len(c.Yubico.KeyTypes) == 0 {
		c.Yubico.RSABits = 3072
	}
	if len(c.Yubico.KeyTypes) > 0 {
		normalized := make([]string, 0, len(c.Yubico.KeyTypes))
		for _, kt := range c.Yubico.KeyTypes {
			normalized = append(normalized, strings.ToLower(strings.TrimSpace(kt)))
		}
		c.Yubico.KeyTypes = normalized
	}
	if c.Logging.Dir == nil {
		dir := defaultLogDir
		c.Logging.Dir = &dir
	}
	if c.Logging.File == "" {
		c.Logging.File = defaultLogFile
	}
	if c.Logging.Owner == "" {
		c.Logging.Owner = defaultLogOwner
	}
	if c.Logging.Group == "" {
		c.Logging.Group = defaultLogGroup
	}
	if c.Audit.File == "" {
		c.Audit.File = "audit.log"
	}
	if c.OIDC.GroupsClaim == "" {
		c.OIDC.GroupsClaim = "groups"
	}
	if len(c.OIDC.AllowedGroups) > 0 {
		trimmed := make([]string, 0, len(c.OIDC.AllowedGroups))
		for _, g := range c.OIDC.AllowedGroups {
			if g = strings.TrimSpace(g); g != "" {
				trimmed = append(trimmed, g)
			}
		}
		c.OIDC.AllowedGroups = trimmed
	}
	if len(c.Yubico.DeviceFingerprints) > 0 {
		normalized := make(map[string][]string, len(c.Yubico.DeviceFingerprints))
		for cn, fps := range c.Yubico.DeviceFingerprints {
			if cn = strings.ToLower(strings.TrimSpace(cn)); cn == "" {
				continue
			}
			var clean []string
			for _, fp := range fps {
				if fp = strings.ToLower(strings.TrimSpace(fp)); fp != "" {
					clean = append(clean, fp)
				}
			}
			if len(clean) > 0 {
				normalized[cn] = clean
			}
		}
		c.Yubico.DeviceFingerprints = normalized
	}
}

// LogDir returns the directory log files are written to. It returns an empty
// string when file logging is disabled (logs then go to stderr/journald).
func (c *Config) LogDir() string {
	if c.Logging.Dir == nil {
		return ""
	}
	return *c.Logging.Dir
}

// LogDirExplicit reports whether logging.dir was set in the configuration
// file. An explicit directory is treated as mandatory (the process refuses to
// start if it cannot be used), whereas the default is best-effort so local
// (unprivileged) runs fall back to stderr.
func (c *Config) LogDirExplicit() bool { return c.logDirExplicit }

// LogFilePath returns the active log file path, or "" when file logging is
// disabled.
func (c *Config) LogFilePath() string {
	dir := c.LogDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, c.Logging.File)
}

// AuditEnabled reports whether the audit trail is enabled. It defaults to true.
func (c *Config) AuditEnabled() bool { return boolOr(c.Audit.Enabled, true) }

// AuditDir returns the directory the audit log is written to. When audit.dir
// is unset it follows logging.dir so a single log directory keeps both the
// service log and the audit record.
func (c *Config) AuditDir() string {
	if c.Audit.Dir != nil {
		return *c.Audit.Dir
	}
	return c.LogDir()
}

// AuditFilePath returns the active audit log path, or "" when audit logging is
// disabled.
func (c *Config) AuditFilePath() string {
	dir := c.AuditDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, c.Audit.File)
}

// AllowedGroups returns the OIDC groups allowed to issue certificates. Empty
// means every authenticated user.
func (c *Config) AllowedGroups() []string { return c.OIDC.AllowedGroups }

// MinFirmware returns the minimum required YubiKey firmware version, or "".
func (c *Config) MinFirmware() string { return c.Yubico.MinFirmware }

// MinSerial returns the minimum required YubiKey serial number, or "".
func (c *Config) MinSerial() string { return c.Yubico.MinSerial }

// DeviceFingerprints returns the normalized per-Common-Name device fingerprint
// allowlist. It is always non-nil (possibly empty).
func (c *Config) DeviceFingerprints() map[string][]string {
	return c.Yubico.DeviceFingerprints
}

// GroupsClaim returns the ID token claim carrying the user's groups.
func (c *Config) GroupsClaim() string {
	if c.OIDC.GroupsClaim == "" {
		return "groups"
	}
	return c.OIDC.GroupsClaim
}

// Validate performs fail-fast checks so misconfiguration surfaces at startup
// instead of on the first user request.
func (c *Config) Validate() error {
	var errs []string

	if len(c.Server.SessionSecret) < MinSessionSecretLen {
		errs = append(errs, fmt.Sprintf(
			"server.session_secret is required and must be at least %d characters (got %d)",
			MinSessionSecretLen, len(c.Server.SessionSecret)))
	} else if c.Server.SessionSecret == exampleSessionSecret {
		errs = append(errs, "server.session_secret must not be the example value from config.yaml.example")
	}

	if c.Vault.Address == "" {
		errs = append(errs, "vault.address is required (e.g. https://vault.example.com)")
	} else if !strings.HasPrefix(c.Vault.Address, "http://") && !strings.HasPrefix(c.Vault.Address, "https://") {
		errs = append(errs, "vault.address must start with http:// or https://")
	}

	switch c.Vault.RevokeMode {
	case RevokeModeStrict, RevokeModeBestEffort:
	default:
		errs = append(errs, fmt.Sprintf("vault.revoke_mode must be '%s' or '%s' (got '%s')",
			RevokeModeStrict, RevokeModeBestEffort, c.Vault.RevokeMode))
	}

	if c.Vault.RevokeExisting {
		if c.Vault.AppRoleRoleID == "" {
			errs = append(errs, "vault.approle_role_id is required when vault.revoke_existing is enabled")
		}
		if c.Vault.AppRoleSecretID == "" {
			errs = append(errs, "vault.approle_secret_id is required when vault.revoke_existing is enabled")
		}
	}

	for name, val := range map[string]string{
		"vault.cert_ttl":     c.Vault.CertTTL,
		"vault.cert_ttl_max": c.Vault.CertTTLMax,
	} {
		if val == "" {
			continue
		}
		if _, err := time.ParseDuration(val); err != nil {
			errs = append(errs, fmt.Sprintf(
				"%s must be a Go duration such as '720h' or '168h' (got '%s')", name, val))
		}
	}

	if c.OIDC.Issuer == "" {
		errs = append(errs, "oidc.issuer is required (e.g. https://idp.example.com/realms/master)")
	}
	if c.OIDC.ClientID == "" {
		errs = append(errs, "oidc.client_id is required")
	}
	if c.OIDC.RedirectURL == "" {
		errs = append(errs, "oidc.redirect_url is required (e.g. https://yubivault.example.com/callback)")
	}

	for _, d := range []struct{ name, val string }{
		{"server.session_max_age", c.Server.SessionMaxAge},
		{"server.session_idle_timeout", c.Server.SessionIdleTimeout},
	} {
		if d.val == "" {
			continue
		}
		if p, err := time.ParseDuration(d.val); err != nil {
			errs = append(errs, fmt.Sprintf(
				"%s must be a Go duration such as '8h' or '30m' (got '%s')", d.name, d.val))
		} else if p <= 0 {
			errs = append(errs, fmt.Sprintf("%s must be a positive duration (got '%s')", d.name, d.val))
		}
	}
	if c.SessionIdleTimeout() > c.SessionMaxAge() {
		errs = append(errs,
			fmt.Sprintf("server.session_idle_timeout (%s) must not exceed server.session_max_age (%s)",
				c.SessionIdleTimeout(), c.SessionMaxAge()))
	}

	if c.Yubico.MinFirmware != "" && !versionRe.MatchString(c.Yubico.MinFirmware) {
		errs = append(errs, fmt.Sprintf(
			"yubico.min_firmware must be a firmware version such as '5.4.3' (got '%s')", c.Yubico.MinFirmware))
	}
	if c.Yubico.MinSerial != "" && !unsignedRe.MatchString(c.Yubico.MinSerial) {
		errs = append(errs, fmt.Sprintf(
			"yubico.min_serial must be a non-negative integer (got '%s')", c.Yubico.MinSerial))
	}
	for cn, fps := range c.Yubico.DeviceFingerprints {
		if cn == "" {
			errs = append(errs, "yubico.device_fingerprints keys must not be empty")
			continue
		}
		for _, fp := range fps {
			if !deviceFPRe.MatchString(fp) {
				errs = append(errs, fmt.Sprintf(
					"yubico.device_fingerprints[%s]: '%s' must look like 'sha256:' followed by 64 hex characters", cn, fp))
			}
		}
	}

	if err := validateCNTemplate(c.CN.Template, c.CN.Domain); err != nil {
		errs = append(errs, err.Error())
	}
	if c.CN.Pattern == "" {
		errs = append(errs, "cn.pattern must not be empty")
	} else if _, err := compileCNPattern(c.CN.Pattern); err != nil {
		errs = append(errs, fmt.Sprintf("cn.pattern is not a valid regular expression: %v", err))
	}

	if c.Yubico.RootCAFile == "" {
		errs = append(errs, "yubico.root_ca_file is required")
	} else if _, err := os.Stat(c.Yubico.RootCAFile); err != nil {
		errs = append(errs, fmt.Sprintf("yubico.root_ca_file '%s' is not readable: %v", c.Yubico.RootCAFile, err))
	}

	for _, kt := range c.AllowedKeyTypes() {
		if _, ok := supportedKeyTypes[kt]; !ok {
			errs = append(errs, fmt.Sprintf(
				"unknown yubico key type '%s' (supported: %s)",
				kt, strings.Join(SupportedKeyTypes(), ", ")))
		}
	}

	if manualNeedsDir(c.UI.ManualFile, c.UI.Manuals) && c.UI.ManualDir == "" {
		errs = append(errs, "ui.manual_dir is required when ui.manuals or ui.manual_file use relative paths")
	}
	if c.UI.ManualDir != "" {
		if info, err := os.Stat(c.UI.ManualDir); err != nil {
			errs = append(errs, fmt.Sprintf("ui.manual_dir '%s' is not readable: %v", c.UI.ManualDir, err))
		} else if !info.IsDir() {
			errs = append(errs, fmt.Sprintf("ui.manual_dir '%s' is not a directory", c.UI.ManualDir))
		}
	}

	errs = validateManual("ui.manual_file", c.resolveManual(c.UI.ManualFile), errs)
	for key, path := range c.UI.Manuals {
		if key == "" {
			errs = append(errs, "ui.manuals keys must not be empty")
			continue
		}
		errs = validateManual("ui.manuals."+key, c.resolveManual(path), errs)
	}

	if c.LogDir() != "" {
		if strings.ContainsAny(c.Logging.File, `/\`) {
			errs = append(errs, "logging.file must be a bare file name without path separators")
		}
		if c.Logging.Owner == "" {
			errs = append(errs, "logging.owner must not be empty when logging.dir is set")
		}
		if c.Logging.Group == "" {
			errs = append(errs, "logging.group must not be empty when logging.dir is set")
		}
	}

	if c.AuditEnabled() {
		if c.AuditFilePath() == "" {
			errs = append(errs, "audit is enabled but no directory is available; set audit.dir or disable it with audit.enabled: false")
		}
		if strings.ContainsAny(c.Audit.File, `/\`) {
			errs = append(errs, "audit.file must be a bare file name without path separators")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// manualNeedsDir reports whether any configured manual uses a relative path
// and therefore needs ui.manual_dir to resolve it.
func manualNeedsDir(file string, manuals map[string]string) bool {
	if file != "" && !filepath.IsAbs(file) {
		return true
	}
	for _, p := range manuals {
		if p != "" && !filepath.IsAbs(p) {
			return true
		}
	}
	return false
}

// validateCNTemplate checks that a Common Name template only uses known
// placeholders and safe literal characters, and that {domain} has a value.
func validateCNTemplate(tmpl, domain string) error {
	if tmpl == "" {
		return errors.New("cn.template must not be empty")
	}
	for _, ph := range cnPlaceholderRe.FindAllString(tmpl, -1) {
		switch ph {
		case "{user}", "{email}", "{domain}":
		default:
			return fmt.Errorf(
				"cn.template contains unknown placeholder %s (allowed: {user}, {email}, {domain})", ph)
		}
	}
	if strings.Contains(tmpl, "{domain}") && domain == "" {
		return errors.New("cn.domain is required when cn.template uses {domain}")
	}
	literal := tmpl
	for _, ph := range cnPlaceholders {
		literal = strings.ReplaceAll(literal, ph, "")
	}
	if !cnLiteralRe.MatchString(literal) {
		return fmt.Errorf(
			"cn.template '%s' may only contain the placeholders {user}, {email}, {domain} and the characters a-z A-Z 0-9 . _ + @ -", tmpl)
	}
	return nil
}

// validateManual appends validation errors for a single manual document. A
// blank path is allowed (the manual is simply not offered).
func validateManual(label, path string, errs []string) []string {
	if path == "" {
		return errs
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf", ".md", ".markdown":
	default:
		errs = append(errs, label+" must be a .pdf or .md/.markdown file")
	}
	if _, err := os.Stat(path); err != nil {
		errs = append(errs, fmt.Sprintf("%s '%s' is not readable: %v", label, path, err))
	}
	return errs
}
