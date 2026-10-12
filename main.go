// YubiVault is a hardware attested certificate portal: it verifies that a
// CSR was generated inside a physical YubiKey before delegating the signing
// request to HashiCorp Vault / OpenBao.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	"yubivault/internal/audit"
	"yubivault/internal/config"
	"yubivault/internal/install"
	"yubivault/internal/portal"
)

var (
	//go:embed templates/*.html
	templateFS embed.FS

	//go:embed static
	staticFS embed.FS
)

func main() {
	installFlag := flag.Bool("install", false, "Install YubiVault as a systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall the YubiVault systemd service")
	checkConfigFlag := flag.Bool("check-config", false, "Validate the configuration and its dependencies, then exit")
	verifyAuditFlag := flag.Bool("verify-audit", false, "Verify the integrity of the audit trail's hash chain, then exit")
	version := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *version {
		fmt.Println("yubivault")
		return
	}

	if *verifyAuditFlag {
		cfg, err := config.Load(envOrDefault("CONFIG_FILE", "config.yaml"))
		if err != nil {
			slog.Error("configuration invalid", "error", err)
			os.Exit(1)
		}
		if !cfg.AuditEnabled() {
			fmt.Println("audit trail is disabled, nothing to verify")
			return
		}
		path := cfg.AuditFilePath()
		if path == "" {
			slog.Error("audit verification failed", "error", "audit trail has no directory configured")
			os.Exit(1)
		}
		if n, err := audit.Verify(path); err != nil {
			slog.Error("audit trail verification failed", "line", n, "path", path, "error", err)
			os.Exit(1)
		}
		fmt.Printf("audit trail OK: %s\n", path)
		return
	}

	if *checkConfigFlag {
		cfg, err := config.Load(envOrDefault("CONFIG_FILE", "config.yaml"))
		if err != nil {
			slog.Error("configuration invalid", "error", err)
			os.Exit(1)
		}
		if cfg.AuditEnabled() {
			logger, err := openAudit(cfg)
			if err != nil {
				slog.Error("configuration invalid", "error", err)
				os.Exit(1)
			}
			_ = logger.Close()
		}
		if err := portal.Check(cfg, slog.Default()); err != nil {
			slog.Error("configuration check failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("configuration OK")
		return
	}

	if *installFlag {
		cfg, err := config.Load(envOrDefault("CONFIG_FILE", "config.yaml"))
		if err != nil {
			slog.Error("installation failed: could not load configuration", "error", err)
			os.Exit(1)
		}
		if err := install.Install(cfg); err != nil {
			slog.Error("installation failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if *uninstallFlag {
		if err := install.Uninstall(); err != nil {
			slog.Error("uninstallation failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := envOrDefault("CONFIG_FILE", "config.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	logger, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()
	slog.SetDefault(logger)

	auditLogger, err := openAudit(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = auditLogger.Close() }()

	p, err := portal.New(portal.Options{
		Config:    cfg,
		Templates: templateFS,
		Static:    staticFS,
		Logger:    slog.Default(),
		Audit:     auditLogger,
	})
	if err != nil {
		return fmt.Errorf("server initialization error: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Poll config.yaml and hot-reload it in place. A reload is logged only when
	// the configuration actually changed, so an unchanged file stays silent.
	go watchConfig(ctx, configPath, cfg, p)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("YubiVault portal listening",
			"addr", cfg.Server.ListenAddr,
			"debug", cfg.Server.Debug,
			"auto_revoke", cfg.Vault.RevokeExisting,
			"key_types", cfg.AllowedKeyTypes())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// configReloadInterval is how often config.yaml is polled for changes. Polling
// avoids platform-specific file watching and is cheap for a small file.
const configReloadInterval = 10 * time.Second

// watchConfig reloads config.yaml in place when it changes, without restarting
// the process. It stays silent while the file is unchanged; an invalid file is
// reported once per distinct error so a broken edit is visible without
// spamming the log every interval. On success the change is logged and the new
// configuration becomes active. Values that cannot be changed at runtime
// (listen address, log/audit destinations) are applied on the next restart.
func watchConfig(ctx context.Context, path string, initial *config.Config, p *portal.Portal) {
	ticker := time.NewTicker(configReloadInterval)
	defer ticker.Stop()

	active := initial
	var appliedInfo os.FileInfo
	lastErr := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A stat is far cheaper than reading and parsing the YAML, and
			// lets an unchanged file (the common case) skip everything.
			info, statErr := os.Stat(path)
			if statErr != nil {
				if msg := statErr.Error(); msg != lastErr {
					slog.Warn("configuration reload skipped: file is unreadable", "path", path, "error", statErr)
					lastErr = msg
				}
				continue
			}
			if fileUnchanged(appliedInfo, info) {
				continue
			}
			next, err := config.Load(path)
			if err != nil {
				if msg := err.Error(); msg != lastErr {
					slog.Warn("configuration reload skipped: file is invalid", "path", path, "error", err)
					lastErr = msg
				}
				continue
			}
			lastErr = ""
			if reflect.DeepEqual(active, next) {
				appliedInfo = info
				continue
			}
			if err := p.Reload(next); err != nil {
				slog.Error("configuration reload failed; keeping the previous configuration",
					"path", path, "error", err)
				continue
			}
			slog.Info("configuration reloaded", "path", path)
			active = next
			appliedInfo = info
		}
	}
}

// fileUnchanged reports whether current refers to the same on-disk state as the
// previously applied snapshot. It lets the config watchdog skip loading and
// parsing an unchanged file, and is a no-op when either snapshot is missing.
func fileUnchanged(prev, current os.FileInfo) bool {
	if prev == nil || current == nil {
		return false
	}
	return prev.ModTime().Equal(current.ModTime()) && prev.Size() == current.Size()
}

// newLogger builds the process logger. When file logging is configured it
// writes to both stderr (captured by journald) and the log file.
//
// The default log directory is best-effort: if it cannot be used (for example
// when running unprivileged on macOS), the process falls back to stderr. A
// directory set explicitly in the configuration is mandatory and makes
// startup fail, so a production misconfiguration never goes unnoticed.
func newLogger(cfg *config.Config) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	if cfg.Server.Debug || os.Getenv("DEBUG") == "1" || os.Getenv("DEBUG") == "true" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	stderrLogger := func() (*slog.Logger, func(), error) {
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), func() {}, nil
	}

	path := cfg.LogFilePath()
	if path == "" {
		return stderrLogger()
	}

	if err := os.MkdirAll(cfg.LogDir(), 0o750); err != nil {
		if cfg.LogDirExplicit() {
			return nil, nil, fmt.Errorf("failed to create log directory %s: %w", cfg.LogDir(), err)
		}
		slog.New(slog.NewTextHandler(os.Stderr, opts)).
			Warn("log directory unavailable, logging to stderr", "dir", cfg.LogDir(), "error", err)
		return stderrLogger()
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		if cfg.LogDirExplicit() {
			return nil, nil, fmt.Errorf("failed to open log file %s: %w", path, err)
		}
		slog.New(slog.NewTextHandler(os.Stderr, opts)).
			Warn("log file unavailable, logging to stderr", "path", path, "error", err)
		return stderrLogger()
	}

	slog.New(slog.NewTextHandler(os.Stderr, opts)).Info("logging to file", "path", path)
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, f), opts)), func() { _ = f.Close() }, nil
}

// openAudit opens the append-only audit trail. The audit log is the security
// record of the portal, so an enabled but unusable audit destination fails
// startup (fail-fast) instead of silently dropping security events. A nil
// logger is returned when audit logging is disabled.
func openAudit(cfg *config.Config) (*audit.Logger, error) {
	if !cfg.AuditEnabled() {
		slog.Info("audit trail disabled")
		return nil, nil
	}
	path := cfg.AuditFilePath()
	if path == "" {
		return nil, errors.New("audit trail is enabled but no directory is configured; set audit.dir or disable it with audit.enabled: false")
	}
	if err := os.MkdirAll(cfg.AuditDir(), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory %s: %w", cfg.AuditDir(), err)
	}
	l, err := audit.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log %s: %w", path, err)
	}
	slog.Info("audit trail enabled", "path", path)
	return l, nil
}
