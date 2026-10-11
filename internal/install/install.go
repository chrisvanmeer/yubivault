// Package install manages the systemd service installation of YubiVault.
package install

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	"yubivault/internal/config"
)

const (
	serviceName    = "yubivault"
	servicePath    = "/etc/systemd/system/yubivault.service"
	binaryPath     = "/usr/local/bin/yubivault"
	configDir      = "/etc/yubivault"
	logrotatePath  = "/etc/logrotate.d/yubivault"
	serviceAccount = "yubivault"
)

func serviceUnit(cfg *config.Config) string {
	readWritePaths := ""
	if dir := cfg.LogDir(); dir != "" {
		readWritePaths = "ReadWritePaths=" + dir + "\n"
	}

	return `[Unit]
Description=YubiVault - Hardware Attested VPN Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=yubivault
Group=yubivault
WorkingDirectory=/etc/yubivault
ExecStart=/usr/local/bin/yubivault
Restart=always
RestartSec=5
Environment=CONFIG_FILE=/etc/yubivault/config.yaml

# Hardening: the portal only needs to read its config, talk to Vault/OIDC and
# write its log file.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
` + readWritePaths + `
[Install]
WantedBy=multi-user.target
`
}

// Install stages the binary, configuration, log directory and unit file.
func Install(cfg *config.Config) error {
	if os.Geteuid() != 0 {
		return errors.New("install must be run with root privileges (e.g. sudo ./yubivault --install)")
	}

	slog.Info("installing YubiVault systemd service")

	if err := ensureServiceUser(); err != nil {
		return err
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}
	// Re-installing from the already installed binary must not copy the file
	// onto itself (that would truncate the running executable).
	if filepath.Clean(execPath) == filepath.Clean(binaryPath) {
		slog.Info("binary already installed at target path, skipping copy", "path", binaryPath)
	} else {
		if err := copyFile(execPath, binaryPath, 0o755); err != nil {
			return fmt.Errorf("failed to copy binary to %s: %w", binaryPath, err)
		}
		slog.Info("installed binary", "path", binaryPath)
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", configDir, err)
	}

	var seededExample bool

	if _, err := os.Stat("config.yaml"); err == nil {
		targetCfg := filepath.Join(configDir, "config.yaml")
		if _, err := os.Stat(targetCfg); os.IsNotExist(err) {
			if err := copyFile("config.yaml", targetCfg, 0o600); err != nil {
				return fmt.Errorf("failed to install config: %w", err)
			}
			slog.Info("installed configuration", "path", targetCfg)
		} else {
			slog.Info("configuration already present, keeping existing file", "path", targetCfg)
		}
	} else if _, statErr := os.Stat(filepath.Join(configDir, "config.yaml")); os.IsNotExist(statErr) {
		example := "config.yaml.example"
		if _, err := os.Stat(example); err == nil {
			targetCfg := filepath.Join(configDir, "config.yaml")
			if err := copyFile(example, targetCfg, 0o600); err != nil {
				return fmt.Errorf("failed to install example configuration: %w", err)
			}
			seededExample = true
			slog.Warn("installed example configuration (requires manual editing)",
				"path", targetCfg,
				"note", "edit session_secret, vault, oidc and other values before starting the service")
		} else {
			slog.Warn("no config.yaml or config.yaml.example found in the current directory and none installed; "+
				"the service will not start until you provide one",
				"expected", filepath.Join(configDir, "config.yaml"))
		}
	} else if _, statErr := os.Stat(filepath.Join(configDir, "config.yaml")); os.IsNotExist(statErr) {
		slog.Warn("no config.yaml found in the current directory and none installed; "+
			"the service will not start until you provide one",
			"expected", filepath.Join(configDir, "config.yaml"))
	}

	if _, err := os.Stat("yubico-roots.pem"); err == nil {
		if err := copyFile("yubico-roots.pem", filepath.Join(configDir, "yubico-roots.pem"), 0o644); err != nil {
			return fmt.Errorf("failed to install Yubico root CAs: %w", err)
		}
		slog.Info("installed Yubico root CAs", "path", filepath.Join(configDir, "yubico-roots.pem"))
	} else if _, statErr := os.Stat(filepath.Join(configDir, "yubico-roots.pem")); os.IsNotExist(statErr) {
		slog.Warn("no yubico-roots.pem found in the current directory and none installed; "+
			"attestation verification will fail until you provide one",
			"expected", filepath.Join(configDir, "yubico-roots.pem"))
	}

	if err := run("chown", "-R", serviceAccount+":"+serviceAccount, configDir); err != nil {
		return fmt.Errorf("failed to set ownership of %s: %w", configDir, err)
	}

	if err := setupLogging(cfg); err != nil {
		return err
	}

	if err := os.WriteFile(servicePath, []byte(serviceUnit(cfg)), 0o644); err != nil {
		return fmt.Errorf("failed to write systemd unit: %w", err)
	}
	slog.Info("created systemd unit", "path", servicePath)

	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serviceName},
	} {
		if err := run(args[0], args[1:]...); err != nil {
			return fmt.Errorf("systemd step failed: %w", err)
		}
	}

	if seededExample {
		slog.Warn("skipping systemctl start because the example configuration was installed; " +
			"edit /etc/yubivault/config.yaml to set valid values, then run 'sudo systemctl start yubivault'")
		slog.Info("service enabled but not started", "service", serviceName)
		return nil
	}

	slog.Info("YubiVault service installed, enabled and started")
	return nil
} // setupLogging creates the configured log directory and file, assigns them to
// the service account, and installs a logrotate snippet. It is a no-op when
// file logging is disabled (logging.dir is empty).
func setupLogging(cfg *config.Config) error {
	dir := cfg.LogDir()
	if dir == "" {
		slog.Info("file logging disabled (logging.dir is empty); logs go to stderr/journald")
		return nil
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	logPath := cfg.LogFilePath()
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("failed to create log file %s: %w", logPath, err)
	}
	_ = f.Close()

	if err := chownPath(dir, cfg.Logging.Owner, cfg.Logging.Group); err != nil {
		return err
	}
	if err := chownPath(logPath, cfg.Logging.Owner, cfg.Logging.Group); err != nil {
		return err
	}
	slog.Info("prepared log directory",
		"dir", dir, "owner", cfg.Logging.Owner, "group", cfg.Logging.Group)

	return installLogrotate(cfg)
}

// installLogrotate writes /etc/logrotate.d/yubivault so the service log file is
// rotated. copytruncate is used because the running process keeps its file
// descriptor open.
func installLogrotate(cfg *config.Config) error {
	content := fmt.Sprintf(`# Generated by yubivault --install. Manual edits are overwritten on reinstall.
%s/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 %s %s
    su %s %s
}
`, cfg.LogDir(), cfg.Logging.Owner, cfg.Logging.Group, cfg.Logging.Owner, cfg.Logging.Group)

	if err := os.WriteFile(logrotatePath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write logrotate config: %w", err)
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		slog.Warn("logrotate not found on PATH; log rotation will not run until it is installed",
			"path", logrotatePath)
	}
	slog.Info("installed logrotate config", "path", logrotatePath)
	return nil
}

// chownPath sets the owner and group of path to the named user and group.
func chownPath(path, owner, group string) error {
	u, err := user.Lookup(owner)
	if err != nil {
		return fmt.Errorf("unknown user %q: %w", owner, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("unknown group %q: %w", group, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid for %q: %w", owner, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid for %q: %w", group, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("failed to chown %s to %s:%s: %w", path, owner, group, err)
	}
	return nil
}

// Uninstall removes the service but preserves /etc/yubivault.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run with root privileges (e.g. sudo ./yubivault --uninstall)")
	}

	slog.Info("uninstalling YubiVault systemd service")

	// Stopping a unit that was never installed is not an error.
	if err := run("systemctl", "stop", serviceName); err != nil {
		slog.Warn("could not stop service", "error", err)
	}
	if err := run("systemctl", "disable", serviceName); err != nil {
		slog.Warn("could not disable service", "error", err)
	}

	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", servicePath, err)
	}
	slog.Info("removed systemd unit", "path", servicePath)

	if err := os.Remove(logrotatePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", logrotatePath, err)
	}
	slog.Info("removed logrotate config", "path", logrotatePath)

	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w", err)
	}

	if err := os.Remove(binaryPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", binaryPath, err)
	}
	slog.Info("removed binary", "path", binaryPath)

	if err := run("userdel", serviceAccount); err != nil {
		slog.Warn("could not remove service user (it may not exist)", "error", err)
	}

	slog.Info("YubiVault service uninstalled; configuration in " + configDir + " was preserved")
	return nil
}

func ensureServiceUser() error {
	if err := run("id", "-u", serviceAccount); err == nil {
		return nil
	}
	slog.Info("creating system user", "user", serviceAccount)
	if err := run("useradd", "--system", "--no-create-home", "--user-group", serviceAccount); err != nil {
		return fmt.Errorf("failed to create service user: %w", err)
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
