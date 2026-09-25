// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads Central's configuration.
//
// Sources, lowest to highest precedence:
//  1. built-in defaults,
//  2. <data dir>/central.state.toml — machine-managed, written by the setup wizard
//     (storage settings with the API key sealed by the master key),
//  3. the operator's config file (--config, default <data dir>/central.toml, optional),
//  4. CENTRAL_* environment variables,
//  5. command-line flags.
//
// Secrets may be supplied as *_FILE variables (Docker/Kubernetes secrets) instead of inline.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Shaalan15/central/server/internal/crypto"
)

// TLS modes for the UI/API listener.
const (
	// TLSOff serves plain HTTP. Use behind a TLS-terminating reverse proxy or on localhost.
	TLSOff = "off"
	// TLSFiles uses a provided certificate and key (reloaded when the files change).
	TLSFiles = "files"
	// TLSACME obtains certificates from Let's Encrypt (or another ACME CA) automatically.
	TLSACME = "acme"
	// TLSSelfSigned serves a certificate issued by Central's internal CA (testing/LAN only).
	TLSSelfSigned = "self-signed"
)

// Storage drivers.
const (
	DriverAppwrite = "appwrite"
	DriverMemory   = "memory"
)

// Config is the full server configuration.
type Config struct {
	DataDir string `toml:"data_dir"`
	// Dev enables development mode: memory store persisted to <data dir>/dev-store.json,
	// relaxed cookie security on http://localhost, verbose logs. Never use in production.
	Dev bool `toml:"dev"`

	HTTP  HTTPConfig  `toml:"http"`
	Agent AgentConfig `toml:"agent"`

	// PublicURL and AgentURL override the URLs saved by the setup wizard.
	PublicURL string `toml:"public_url"`
	AgentURL  string `toml:"agent_url"`

	MasterKeyFile string        `toml:"master_key_file"`
	MasterKey     crypto.Secret `toml:"-"`

	Storage StorageConfig `toml:"storage"`
	Log     LogConfig     `toml:"log"`

	// storageSource records where the storage settings came from (for the setup wizard).
	storageSource string
}

// HTTPConfig configures the UI/API listener.
type HTTPConfig struct {
	Addr string    `toml:"addr"`
	TLS  TLSConfig `toml:"tls"`
	// TrustedProxies lists proxy addresses/CIDRs whose X-Forwarded-For/-Proto are honoured.
	TrustedProxies []string `toml:"trusted_proxies"`
}

// TLSConfig configures TLS for the UI/API listener.
type TLSConfig struct {
	Mode        string   `toml:"mode"`
	CertFile    string   `toml:"cert_file"`
	KeyFile     string   `toml:"key_file"`
	ACMEEmail   string   `toml:"acme_email"`
	ACMEDomains []string `toml:"acme_domains"`
	// ACMEDirectory overrides the ACME directory URL (default Let's Encrypt production).
	ACMEDirectory string `toml:"acme_directory"`
}

// AgentConfig configures the agent listener (always TLS with the internal CA).
type AgentConfig struct {
	Addr string `toml:"addr"`
}

// StorageConfig selects and configures the storage driver.
type StorageConfig struct {
	Driver   string         `toml:"driver"`
	Appwrite AppwriteConfig `toml:"appwrite"`
	// MemoryPath is the snapshot file for the memory driver ("" = volatile).
	MemoryPath string `toml:"memory_path"`
}

// AppwriteConfig connects to Appwrite 2.x.
type AppwriteConfig struct {
	Endpoint   string        `toml:"endpoint"`
	ProjectID  string        `toml:"project_id"`
	DatabaseID string        `toml:"database_id"`
	APIKey     crypto.Secret `toml:"-"`
	// APIKeySealed is the API key encrypted with the master key (written by the wizard).
	APIKeySealed string `toml:"api_key_sealed"`
	APIKeyFile   string `toml:"api_key_file"`
	CABundleFile string `toml:"ca_bundle_file"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Defaults returns the built-in defaults.
func Defaults() Config {
	return Config{
		DataDir: "/var/lib/central",
		HTTP:    HTTPConfig{Addr: ":8080", TLS: TLSConfig{Mode: TLSOff}},
		Agent:   AgentConfig{Addr: ":9443"},
		Log:     LogConfig{Level: "info", Format: "json"},
	}
}

// StateFileName is the machine-managed config file inside the data directory.
const StateFileName = "central.state.toml"

// Flags are command-line overrides (empty values are ignored).
type Flags struct {
	ConfigFile string
	DataDir    string
	Dev        bool
	HTTPAddr   string
	AgentAddr  string
}

// Load resolves the configuration.
func Load(flags Flags, env func(string) string) (Config, error) {
	if env == nil {
		env = os.Getenv
	}
	cfg := Defaults()

	// The data dir decides where the state and default config files live, so resolve it first.
	dataDir := firstNonEmpty(flags.DataDir, env("CENTRAL_DATA_DIR"))
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if flags.Dev || parseBool(env("CENTRAL_DEV")) {
		cfg.Dev = true
		if dataDir == "" {
			cfg.DataDir = "./.central"
		}
		cfg.Log.Format = "text"
		cfg.Log.Level = "debug"
	}

	statePath := filepath.Join(cfg.DataDir, StateFileName)
	if err := decodeFileIfExists(statePath, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Storage.Driver != "" {
		cfg.storageSource = "state"
	}
	configFile := flags.ConfigFile
	explicitConfig := configFile != ""
	if configFile == "" {
		configFile = firstNonEmpty(env("CENTRAL_CONFIG"), filepath.Join(cfg.DataDir, "central.toml"))
		explicitConfig = env("CENTRAL_CONFIG") != ""
	}
	before := cfg.Storage.Driver
	if explicitConfig {
		if err := decodeFile(configFile, &cfg); err != nil {
			return Config{}, err
		}
	} else if err := decodeFileIfExists(configFile, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Storage.Driver != before {
		cfg.storageSource = "config"
	}

	applyEnv(&cfg, env)
	if flags.HTTPAddr != "" {
		cfg.HTTP.Addr = flags.HTTPAddr
	}
	if flags.AgentAddr != "" {
		cfg.Agent.Addr = flags.AgentAddr
	}
	if flags.DataDir != "" {
		cfg.DataDir = flags.DataDir
	}
	if cfg.Dev && cfg.Storage.Driver == "" {
		cfg.Storage.Driver = DriverMemory
		cfg.Storage.MemoryPath = filepath.Join(cfg.DataDir, "dev-store.json")
		cfg.storageSource = "dev"
	}
	if cfg.MasterKeyFile == "" {
		cfg.MasterKeyFile = filepath.Join(cfg.DataDir, "master.key")
	}
	if err := cfg.resolveSecretFiles(); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

func applyEnv(cfg *Config, env func(string) string) {
	setStr := func(dst *string, key string) {
		if v := env(key); v != "" {
			*dst = v
		}
	}
	setStr(&cfg.HTTP.Addr, "CENTRAL_HTTP_ADDR")
	setStr(&cfg.Agent.Addr, "CENTRAL_AGENT_ADDR")
	setStr(&cfg.PublicURL, "CENTRAL_PUBLIC_URL")
	setStr(&cfg.AgentURL, "CENTRAL_AGENT_URL")
	setStr(&cfg.HTTP.TLS.Mode, "CENTRAL_TLS_MODE")
	setStr(&cfg.HTTP.TLS.CertFile, "CENTRAL_TLS_CERT_FILE")
	setStr(&cfg.HTTP.TLS.KeyFile, "CENTRAL_TLS_KEY_FILE")
	setStr(&cfg.HTTP.TLS.ACMEEmail, "CENTRAL_ACME_EMAIL")
	setStr(&cfg.HTTP.TLS.ACMEDirectory, "CENTRAL_ACME_DIRECTORY")
	if v := env("CENTRAL_ACME_DOMAINS"); v != "" {
		cfg.HTTP.TLS.ACMEDomains = splitList(v)
	}
	if v := env("CENTRAL_TRUSTED_PROXIES"); v != "" {
		cfg.HTTP.TrustedProxies = splitList(v)
	}
	setStr(&cfg.MasterKeyFile, "CENTRAL_MASTER_KEY_FILE")
	if v := env("CENTRAL_MASTER_KEY"); v != "" {
		cfg.MasterKey = crypto.Secret(v)
	}
	if v := env("CENTRAL_STORAGE_DRIVER"); v != "" {
		cfg.Storage.Driver = v
		cfg.storageSource = "env"
	}
	setStr(&cfg.Storage.Appwrite.Endpoint, "CENTRAL_APPWRITE_ENDPOINT")
	setStr(&cfg.Storage.Appwrite.ProjectID, "CENTRAL_APPWRITE_PROJECT")
	setStr(&cfg.Storage.Appwrite.DatabaseID, "CENTRAL_APPWRITE_DATABASE_ID")
	setStr(&cfg.Storage.Appwrite.APIKeyFile, "CENTRAL_APPWRITE_API_KEY_FILE")
	setStr(&cfg.Storage.Appwrite.CABundleFile, "CENTRAL_APPWRITE_CA_FILE")
	if v := env("CENTRAL_APPWRITE_API_KEY"); v != "" {
		cfg.Storage.Appwrite.APIKey = crypto.Secret(v)
	}
	if env("CENTRAL_APPWRITE_ENDPOINT") != "" && env("CENTRAL_STORAGE_DRIVER") == "" {
		cfg.Storage.Driver = DriverAppwrite
		cfg.storageSource = "env"
	}
	setStr(&cfg.Log.Level, "CENTRAL_LOG_LEVEL")
	setStr(&cfg.Log.Format, "CENTRAL_LOG_FORMAT")
}

func (c *Config) resolveSecretFiles() error {
	if f := c.Storage.Appwrite.APIKeyFile; f != "" && c.Storage.Appwrite.APIKey == "" {
		b, err := os.ReadFile(f) //nolint:gosec // path from trusted configuration
		if err != nil {
			return fmt.Errorf("config: read Appwrite API key file: %w", err)
		}
		c.Storage.Appwrite.APIKey = crypto.Secret(strings.TrimSpace(string(b)))
	}
	return nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	var errs []error
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir must be set"))
	}
	switch c.HTTP.TLS.Mode {
	case TLSOff, TLSSelfSigned:
	case TLSFiles:
		if c.HTTP.TLS.CertFile == "" || c.HTTP.TLS.KeyFile == "" {
			errs = append(errs, errors.New("tls mode \"files\" requires cert_file and key_file"))
		}
	case TLSACME:
		if len(c.HTTP.TLS.ACMEDomains) == 0 {
			errs = append(errs, errors.New("tls mode \"acme\" requires acme_domains"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown tls mode %q (off, files, acme, self-signed)", c.HTTP.TLS.Mode))
	}
	for _, p := range c.HTTP.TrustedProxies {
		if _, err := ParsePrefix(p); err != nil {
			errs = append(errs, fmt.Errorf("trusted_proxies: %w", err))
		}
	}
	for name, u := range map[string]string{"public_url": c.PublicURL, "agent_url": c.AgentURL} {
		if u == "" {
			continue
		}
		if err := ValidateBaseURL(u); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	switch c.Storage.Driver {
	case "":
	case DriverMemory:
		if !c.Dev {
			errs = append(errs, errors.New("the memory storage driver is only allowed in --dev mode"))
		}
	case DriverAppwrite:
		a := c.Storage.Appwrite
		if a.Endpoint == "" || a.ProjectID == "" {
			errs = append(errs, errors.New("appwrite storage requires endpoint and project_id"))
		}
		if a.APIKey == "" && a.APIKeySealed == "" {
			errs = append(errs, errors.New("appwrite storage requires an API key (CENTRAL_APPWRITE_API_KEY[_FILE])"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown storage driver %q", c.Storage.Driver))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("unknown log level %q", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("unknown log format %q", c.Log.Format))
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

// StorageConfigured reports whether a storage driver is configured.
func (c *Config) StorageConfigured() bool { return c.Storage.Driver != "" }

// StoragePreconfigured reports whether storage comes from operator configuration (env, config
// file or dev mode) rather than the setup wizard's state file.
func (c *Config) StoragePreconfigured() bool {
	return c.StorageConfigured() && c.storageSource != "state"
}

// StatePath returns the path of the machine-managed state file.
func (c *Config) StatePath() string { return filepath.Join(c.DataDir, StateFileName) }

// ParsePrefix parses an IP address or CIDR.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ValidateBaseURL checks an absolute http(s) URL without credentials, query or fragment.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("must use https (or http for local development)")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be a bare base URL like https://central.example.com")
	}
	return nil
}

// StateFile is the machine-managed configuration written by the setup wizard.
type StateFile struct {
	Storage StorageConfig `toml:"storage"`
}

// WriteState persists the wizard's storage configuration (0600). Secrets must already be
// sealed: APIKey is never written (it is tagged toml:"-").
func WriteState(dataDir string, st StateFile) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Managed by Central's setup wizard. Secrets are encrypted with the master key.\n")
	if err := toml.NewEncoder(&sb).Encode(st); err != nil {
		return err
	}
	return crypto.WriteFileAtomic(filepath.Join(dataDir, StateFileName), []byte(sb.String()), 0o600)
}

func decodeFile(path string, cfg *Config) error {
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return fmt.Errorf("config: %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	return nil
}

func decodeFileIfExists(path string, cfg *Config) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return decodeFile(path, cfg)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
