package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// AppConfig holds the application configuration.
type AppConfig struct {
	Server struct {
		Host         string `json:"host"`
		Port         string `json:"port"`
		LogRequests  bool   `json:"log_requests"`
		LogResponses bool   `json:"log_responses"`
		PprofEnabled bool   `json:"pprof_enabled"`
		PprofAddr    string `json:"pprof_addr"`
	} `json:"server"`
	FreeSWITCH struct {
		DefaultDomain string `json:"default_domain"`
	} `json:"freeswitch"`
	Cache struct {
		Enabled         bool   `json:"enabled"`
		SecurityTTL     string `json:"security_ttl"`
		CleanupInterval string `json:"cleanup_interval"`
	} `json:"cache"`
	Security struct {
		Enabled                bool     `json:"enabled"`
		ESLHost                string   `json:"esl_host"`
		ESLPort                string   `json:"esl_port"`
		ESLPassword            string   `json:"esl_password"`
		ESLAllowedCommands     []string `json:"esl_allowed_commands"`
		MaxFailedAttempts      int      `json:"max_failed_attempts"`
		FailedAttemptsWindow   string   `json:"failed_attempts_window"`
		AutoBlockEnabled       bool     `json:"auto_block_enabled"`
		BlockDuration          string   `json:"block_duration"`
		WhitelistEnabled       bool     `json:"whitelist_enabled"`
		WhitelistTTL           string   `json:"whitelist_ttl"`
		TrustedNetworks        []string `json:"trusted_networks"`
		UntrustedNetworks      []string `json:"untrusted_networks"`
		IPTablesChain          string   `json:"iptables_chain"`
		IPSetName              string   `json:"ipset_name"`
		DryRun                 bool     `json:"dry_run"`
		AutoWhitelistOnSuccess bool     `json:"auto_whitelist_on_success"`
		ESLLogLevel            string   `json:"esl_log_level"`
		ReconnectBackoff       string   `json:"reconnect_backoff"`
		MaxWrongCallStates     int      `json:"max_wrong_call_states"`
		WrongCallStateWindow   string   `json:"wrong_call_state_window"`
		// ChanDaemon is the D39 central IP-ban repository integration: this
		// node reports every firewall block to chanDaemon, and chanDaemon
		// pushes customer/operator unbans back to the unban endpoint
		// (DELETE /api/v1/ips/:ip/block), gated by AllowedAPIIPs.
		ChanDaemon struct {
			Enabled       bool     `json:"enabled"`
			ReportURL     string   `json:"report_url"`
			BlockerURL    string   `json:"blocker_url"`
			ServiceName   string   `json:"service_name"`
			ReportTimeout string   `json:"report_timeout"`
			AllowedAPIIPs []string `json:"allowed_api_ips"`
		} `json:"chandaemon"`
		RateLimit struct {
			Enabled            bool   `json:"enabled"`
			CallRateLimit      int    `json:"call_rate_limit"`
			CallRateInterval   string `json:"call_rate_interval"`
			RegistrationLimit  int    `json:"registration_limit"`
			RegistrationWindow string `json:"registration_window"`
			AutoBlockOnExceed  bool   `json:"auto_block_on_exceed"`
			BlockDuration      string `json:"block_duration"`
			WhitelistBypass    bool   `json:"whitelist_bypass"`
			CleanupInterval    string `json:"cleanup_interval"`
		} `json:"rate_limit"`
	} `json:"security"`
}

// defaultFreeSWITCHDomain is the placeholder domain used when no
// configuration value is provided. example.com is the IANA-reserved domain
// for documentation and examples (RFC 2606).
const defaultFreeSWITCHDomain = "example.com"

// defaultIPTablesChain is the chain the single ipset match-set DROP rule is
// inserted into; it must be a chain the kernel actually traverses.
const defaultIPTablesChain = "INPUT"

// projectName is the daemon's identity, reused as the default ipset name and
// the chanDaemon service identity (D40).
const projectName = "freeswitch-security"

// defaultLoopbackIP is the IPv4 loopback address used for several listen and
// allow-list defaults; defaultLoopbackIPv6 is its IPv6 counterpart.
const (
	defaultLoopbackIP   = "127.0.0.1"
	defaultLoopbackIPv6 = "::1"
)

// chanDaemon (D39) integration defaults. Reporting is ON by default and points
// at the production ingress; set ReportURL empty (or Enabled false) for a
// standalone install. ServiceName (D40) distinguishes blocker types in the
// fleet. The API allow-list defaults to the chanDaemon nodes plus loopback so
// the unban endpoint and other state-changing routes are restricted out of the
// box; an empty list leaves the API unrestricted.
const (
	defaultChanDaemonReportURL     = "https://ipban.support.voicetel.com/api/v1/ip-bans/report"
	defaultChanDaemonServiceName   = projectName
	defaultChanDaemonReportTimeout = "5s"
)

// defaultChanDaemonAllowedAPIIPs returns the source IPs/CIDRs permitted to drive
// state-changing API endpoints (the chanDaemon nodes plus loopback). Returned by
// a function because a slice cannot be a Go constant.
func defaultChanDaemonAllowedAPIIPs() []string {
	return []string{"3.17.211.50", "104.225.13.77", "192.73.246.109", defaultLoopbackIP, defaultLoopbackIPv6}
}

var (
	config     *AppConfig
	configOnce sync.Once
)

// defaultConfig returns an AppConfig populated with all defaults.
func defaultConfig() *AppConfig {
	cfg := &AppConfig{}

	// Server defaults
	cfg.Server.Host = defaultLoopbackIP
	cfg.Server.Port = "8088"
	cfg.Server.LogRequests = true
	cfg.Server.LogResponses = false
	cfg.Server.PprofEnabled = false
	cfg.Server.PprofAddr = defaultPprofAddr

	// FreeSWITCH defaults
	cfg.FreeSWITCH.DefaultDomain = defaultFreeSWITCHDomain

	// Cache defaults
	cfg.Cache.Enabled = true
	cfg.Cache.SecurityTTL = "5m"     // TTL for cached HTTP responses
	cfg.Cache.CleanupInterval = "5m" // expiry janitor interval

	// Security defaults
	cfg.Security.Enabled = true
	cfg.Security.ESLHost = defaultLoopbackIP
	cfg.Security.ESLPort = "8021"
	cfg.Security.ESLPassword = "ClueCon"
	// Default allowed ESL commands (common, safe commands)
	cfg.Security.ESLAllowedCommands = []string{
		"status",
		"uptime",
		"version",
	}
	cfg.Security.MaxFailedAttempts = 5
	cfg.Security.FailedAttemptsWindow = "10m"
	cfg.Security.AutoBlockEnabled = true
	cfg.Security.BlockDuration = "1h"
	cfg.Security.WhitelistEnabled = true
	cfg.Security.WhitelistTTL = "24h"
	cfg.Security.TrustedNetworks = []string{
		"127.0.0.1/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	cfg.Security.UntrustedNetworks = []string{}
	cfg.Security.IPTablesChain = defaultIPTablesChain
	cfg.Security.IPSetName = projectName
	cfg.Security.DryRun = false
	cfg.Security.AutoWhitelistOnSuccess = true
	cfg.Security.ESLLogLevel = logLevelInfoStr
	cfg.Security.ReconnectBackoff = "5s"
	cfg.Security.MaxWrongCallStates = 5
	cfg.Security.WrongCallStateWindow = "10m"

	// chanDaemon (D39) reporting + unban fan-out, on by default (fleet parity).
	cfg.Security.ChanDaemon.Enabled = true
	cfg.Security.ChanDaemon.ReportURL = defaultChanDaemonReportURL
	cfg.Security.ChanDaemon.BlockerURL = ""
	cfg.Security.ChanDaemon.ServiceName = defaultChanDaemonServiceName
	cfg.Security.ChanDaemon.ReportTimeout = defaultChanDaemonReportTimeout
	cfg.Security.ChanDaemon.AllowedAPIIPs = defaultChanDaemonAllowedAPIIPs()

	// Rate Limit defaults - centralized here
	cfg.Security.RateLimit.Enabled = true
	cfg.Security.RateLimit.CallRateLimit = 20
	cfg.Security.RateLimit.CallRateInterval = "1m"
	cfg.Security.RateLimit.RegistrationLimit = 10
	cfg.Security.RateLimit.RegistrationWindow = "1m"
	cfg.Security.RateLimit.AutoBlockOnExceed = true
	cfg.Security.RateLimit.BlockDuration = "15m"
	cfg.Security.RateLimit.WhitelistBypass = true
	cfg.Security.RateLimit.CleanupInterval = "5m"

	return cfg
}

// buildConfig constructs the configuration: defaults, then overrides from the
// file at path (creating a default config file when none exists), then
// environment-variable overrides. On error it returns the partially populated
// config alongside the error, mirroring the legacy LoadConfig behavior of
// leaving defaults in place when the file cannot be used.
func buildConfig(path string) (*AppConfig, error) {
	cfg := defaultConfig()

	// Check if config file exists
	_, statErr := os.Stat(path)
	if statErr == nil {
		file, openErr := os.Open(path)
		if openErr != nil {
			log.Printf("Error opening config file: %v", openErr)

			return cfg, fmt.Errorf("opening config file: %w", openErr)
		}
		defer file.Close()

		decErr := json.NewDecoder(file).Decode(cfg)
		if decErr != nil {
			log.Printf("Error decoding config file: %v", decErr)

			return cfg, fmt.Errorf("decoding config file: %w", decErr)
		}
	} else {
		// Create a default config file
		file, createErr := os.Create(path)
		if createErr != nil {
			log.Printf("Error creating config file: %v", createErr)

			return cfg, fmt.Errorf("creating config file: %w", createErr)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")

		encErr := encoder.Encode(cfg)
		if encErr != nil {
			log.Printf("Error encoding config file: %v", encErr)

			return cfg, fmt.Errorf("encoding config file: %w", encErr)
		}
	}

	// Override with environment variables if set
	loadEnvironmentVariables(cfg)

	return cfg, nil
}

// LoadConfig loads configuration from a file. Subsequent calls return the
// cached instance and a nil error.
func LoadConfig(path string) (*AppConfig, error) {
	var loadErr error

	configOnce.Do(func() {
		config, loadErr = buildConfig(path)
	})

	return config, loadErr
}

// GetConfig returns the current configuration.
func GetConfig() *AppConfig {
	if config == nil {
		_, err := LoadConfig("config.json")
		if err != nil {
			log.Fatalf("Error loading configuration: %v", err)
		}
	}

	return config
}

// envBool reads a boolean environment variable. If the variable is set to a
// non-empty value, the dst is overwritten with the parsed value. The strings
// "true", "1", and "yes" (case-insensitive) parse as true; everything else
// parses as false.
func envBool(key string, dst *bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return
	}

	switch strings.ToLower(raw) {
	case "true", "1", "yes":
		*dst = true
	default:
		*dst = false
	}
}

// envString sets *dst to the value of key if the variable is non-empty.
func envString(key string, dst *string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

// envInt sets *dst to the parsed value of key if the variable parses as an int.
func envInt(key string, dst *int) {
	raw := os.Getenv(key)
	if raw == "" {
		return
	}

	n, err := strconv.Atoi(raw)
	if err == nil {
		*dst = n
	}
}

// envJSONStringSlice unmarshals a JSON array of strings from key into *dst.
func envJSONStringSlice(key string, dst *[]string) {
	raw := os.Getenv(key)
	if raw == "" {
		return
	}

	var parsed []string

	err := json.Unmarshal([]byte(raw), &parsed)
	if err == nil {
		*dst = parsed
	}
}

// loadEnvironmentVariables overrides config values with environment variables if set.
func loadEnvironmentVariables(config *AppConfig) {
	// Server
	envString("SERVER_HOST", &config.Server.Host)
	envString("SERVER_PORT", &config.Server.Port)
	envBool("SERVER_LOG_REQUESTS", &config.Server.LogRequests)
	envBool("SERVER_LOG_RESPONSES", &config.Server.LogResponses)
	envBool("SERVER_PPROF_ENABLED", &config.Server.PprofEnabled)
	envString("SERVER_PPROF_ADDR", &config.Server.PprofAddr)

	// FreeSWITCH
	envString("FS_DEFAULT_DOMAIN", &config.FreeSWITCH.DefaultDomain)

	// Cache
	envBool("CACHE_ENABLED", &config.Cache.Enabled)
	envString("CACHE_SECURITY_TTL", &config.Cache.SecurityTTL)
	envString("CACHE_CLEANUP_INTERVAL", &config.Cache.CleanupInterval)

	// Security
	envBool("SECURITY_ENABLED", &config.Security.Enabled)
	envString("SECURITY_ESL_HOST", &config.Security.ESLHost)
	envString("SECURITY_ESL_PORT", &config.Security.ESLPort)
	envString("SECURITY_ESL_PASSWORD", &config.Security.ESLPassword)
	envJSONStringSlice("SECURITY_ESL_ALLOWED_COMMANDS", &config.Security.ESLAllowedCommands)
	envInt("SECURITY_MAX_FAILED_ATTEMPTS", &config.Security.MaxFailedAttempts)
	envString("SECURITY_FAILED_WINDOW", &config.Security.FailedAttemptsWindow)
	envBool("SECURITY_AUTO_BLOCK", &config.Security.AutoBlockEnabled)
	envString("SECURITY_BLOCK_DURATION", &config.Security.BlockDuration)
	envBool("SECURITY_WHITELIST_ENABLED", &config.Security.WhitelistEnabled)
	envString("SECURITY_WHITELIST_TTL", &config.Security.WhitelistTTL)
	envString("SECURITY_IPTABLES_CHAIN", &config.Security.IPTablesChain)
	envString("SECURITY_IPSET_NAME", &config.Security.IPSetName)
	envBool("SECURITY_DRY_RUN", &config.Security.DryRun)
	envBool("SECURITY_AUTO_WHITELIST_ON_SUCCESS", &config.Security.AutoWhitelistOnSuccess)
	envString("SECURITY_ESL_LOG_LEVEL", &config.Security.ESLLogLevel)
	envString("SECURITY_RECONNECT_BACKOFF", &config.Security.ReconnectBackoff)
	envInt("SECURITY_MAX_WRONG_CALL_STATES", &config.Security.MaxWrongCallStates)
	envString("SECURITY_WRONG_CALL_STATE_WINDOW", &config.Security.WrongCallStateWindow)
	envJSONStringSlice("SECURITY_TRUSTED_NETWORKS", &config.Security.TrustedNetworks)
	envJSONStringSlice("SECURITY_UNTRUSTED_NETWORKS", &config.Security.UntrustedNetworks)

	// chanDaemon (D39)
	envBool("SECURITY_CHANDAEMON_ENABLED", &config.Security.ChanDaemon.Enabled)
	envString("SECURITY_CHANDAEMON_REPORT_URL", &config.Security.ChanDaemon.ReportURL)
	envString("SECURITY_CHANDAEMON_BLOCKER_URL", &config.Security.ChanDaemon.BlockerURL)
	envString("SECURITY_CHANDAEMON_SERVICE_NAME", &config.Security.ChanDaemon.ServiceName)
	envString("SECURITY_CHANDAEMON_REPORT_TIMEOUT", &config.Security.ChanDaemon.ReportTimeout)
	envJSONStringSlice("SECURITY_CHANDAEMON_ALLOWED_API_IPS", &config.Security.ChanDaemon.AllowedAPIIPs)

	// Rate limit
	envBool("SECURITY_RATE_LIMIT_ENABLED", &config.Security.RateLimit.Enabled)
	envInt("SECURITY_RATE_LIMIT_CALL_LIMIT", &config.Security.RateLimit.CallRateLimit)
	envString("SECURITY_RATE_LIMIT_CALL_INTERVAL", &config.Security.RateLimit.CallRateInterval)
	envInt("SECURITY_RATE_LIMIT_REG_LIMIT", &config.Security.RateLimit.RegistrationLimit)
	envString("SECURITY_RATE_LIMIT_REG_WINDOW", &config.Security.RateLimit.RegistrationWindow)
	envBool("SECURITY_RATE_LIMIT_AUTO_BLOCK", &config.Security.RateLimit.AutoBlockOnExceed)
	envString("SECURITY_RATE_LIMIT_BLOCK_DURATION", &config.Security.RateLimit.BlockDuration)
	envBool("SECURITY_RATE_LIMIT_WHITELIST_BYPASS", &config.Security.RateLimit.WhitelistBypass)
	envString("SECURITY_RATE_LIMIT_CLEANUP_INTERVAL", &config.Security.RateLimit.CleanupInterval)
}
