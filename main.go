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
	"syscall"
	"time"

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
	version := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *version {
		fmt.Println("yubivault")
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

	p, err := portal.New(portal.Options{
		Config:    cfg,
		Templates: templateFS,
		Static:    staticFS,
		Logger:    slog.Default(),
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
