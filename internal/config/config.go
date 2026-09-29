package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultAddress = "127.0.0.1:8088"
	DefaultDataDir = "./data"
	// DefaultBootstrapAdmin is the identity that receives the admin role on a
	// fresh data directory before any operator is registered.
	DefaultBootstrapAdmin = "cellar-admin"
)

// Config contains process-level settings that are resolved before any
// repository or HTTP server is created.
type Config struct {
	Address           string
	DataDir           string
	BootstrapAdmin    string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

func FromEnv() (Config, error) {
	cfg := Config{
		Address:           valueOrDefault("CELLAR_CONTROL_ADDR", DefaultAddress),
		DataDir:           valueOrDefault("CELLAR_CONTROL_DATA_DIR", DefaultDataDir),
		BootstrapAdmin:    valueOrDefault("CELLAR_CONTROL_BOOTSTRAP_ADMIN", DefaultBootstrapAdmin),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
	return cfg.Validate()
}

func (c Config) Validate() (Config, error) {
	c.Address = strings.TrimSpace(c.Address)
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.BootstrapAdmin = strings.ToLower(strings.TrimSpace(c.BootstrapAdmin))
	if c.Address == "" {
		return Config{}, fmt.Errorf("address cannot be empty")
	}
	if c.DataDir == "" {
		return Config{}, fmt.Errorf("data directory cannot be empty")
	}
	if c.BootstrapAdmin == "" {
		return Config{}, fmt.Errorf("bootstrap admin cannot be empty")
	}
	absolute, err := filepath.Abs(c.DataDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve data directory: %w", err)
	}
	c.DataDir = filepath.Clean(absolute)
	if c.ReadHeaderTimeout <= 0 || c.ReadTimeout <= 0 || c.WriteTimeout <= 0 {
		return Config{}, fmt.Errorf("HTTP timeouts must be positive")
	}
	if c.IdleTimeout <= 0 || c.ShutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("idle and shutdown timeouts must be positive")
	}
	return c, nil
}

func (c Config) EnsureDataDir() error {
	if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	return nil
}

func valueOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
