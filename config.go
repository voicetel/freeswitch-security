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
	} `json:"server"`
	FreeSWITCH struct {
		DefaultDomain string `json:"default_domain"`
	} `json:"freeswitch"`
	Cache struct {
		Enabled            bool   `json:"enabled"`
		SecurityTTL        string `json:"security_ttl"`
		CleanupInterval    string `json:"cleanup_interval"`
		MaxEntriesInWindow int    `json:"max_entries_in_window"`
		MaxEntrySize       int    `json:"max_entry_size"`
		ShardCount         int    `json:"shard_count"`
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
		AutoWhitelistOnSuccess bool     `json:"auto_whitelist_on_success"`
		ESLLogLevel            string   `json:"esl_log_level"`
		ReconnectBackoff       string   `json:"reconnect_backoff"`
		MaxWrongCallStates     int      `json:"max_wrong_call_states"`
		WrongCallStateWindow   string   `json:"wrong_call_state_window"`
		RateLimit              struct {
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

var (
	config     *AppConfig
	configOnce sync.Once
)

// LoadConfig loads configuration from a file. Subsequent calls return the
// cached instance and a nil error.
func LoadConfig(path string) (*AppConfig, error) {
	var loadErr error

	configOnce.Do(func() {
		config = &AppConfig{}

		// Set defaults
		// Server defaults
		config.Server.Host = "127.0.0.1"
		config.Server.Port = "8088"
		config.Server.LogRequests = true
		config.Server.LogResponses = false

		// FreeSWITCH defaults
		config.FreeSWITCH.DefaultDomain = defaultFreeSWITCHDomain

		// Cache defaults
		config.Cache.Enabled = true
		config.Cache.SecurityTTL = "5m"         // 5 minutes for security cache
		config.Cache.CleanupInterval = "5m"     // 5 minutes cleanup
		config.Cache.MaxEntriesInWindow = 10000 // Maximum items in cache window
		config.Cache.MaxEntrySize = 500         // Maximum entry size in KB
		config.Cache.ShardCount = 1024          // Number of shards in BigCache

		// Security defaults
		config.Security.Enabled = true
		config.Security.ESLHost = "127.0.0.1"
		config.Security.ESLPort = "8021"
		config.Security.ESLPassword = "ClueCon"
		// Default allowed ESL commands (common, safe commands)
		config.Security.ESLAllowedCommands = []string{
			"status",
			"uptime",
			"version",
		}
		config.Security.MaxFailedAttempts = 5
		config.Security.FailedAttemptsWindow = "10m"
		config.Security.AutoBlockEnabled = true
		config.Security.BlockDuration = "1h"
		config.Security.WhitelistEnabled = true
		config.Security.WhitelistTTL = "24h"
		config.Security.TrustedNetworks = []string{
			"127.0.0.1/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		}
		config.Security.UntrustedNetworks = []string{}
		config.Security.IPTablesChain = "FREESWITCH"
		config.Security.AutoWhitelistOnSuccess = true
		config.Security.ESLLogLevel = logLevelInfoStr
		config.Security.ReconnectBackoff = "5s"
		config.Security.MaxWrongCallStates = 5
		config.Security.WrongCallStateWindow = "10m"

		// Rate Limit defaults - centralized here
		config.Security.RateLimit.Enabled = true
		config.Security.RateLimit.CallRateLimit = 20
		config.Security.RateLimit.CallRateInterval = "1m"
		config.Security.RateLimit.RegistrationLimit = 10
		config.Security.RateLimit.RegistrationWindow = "1m"
		config.Security.RateLimit.AutoBlockOnExceed = true
		config.Security.RateLimit.BlockDuration = "15m"
		config.Security.RateLimit.WhitelistBypass = true
		config.Security.RateLimit.CleanupInterval = "5m"

		// Check if config file exists
		if _, statErr := os.Stat(path); statErr == nil {
			file, openErr := os.Open(path)
			if openErr != nil {
				loadErr = fmt.Errorf("opening config file: %w", openErr)
				log.Printf("Error opening config file: %v", openErr)

				return
			}
			defer file.Close()

			if decErr := json.NewDecoder(file).Decode(config); decErr != nil {
				loadErr = fmt.Errorf("decoding config file: %w", decErr)
				log.Printf("Error decoding config file: %v", decErr)

				return
			}
		} else {
			// Create a default config file
			file, createErr := os.Create(path)
			if createErr != nil {
				loadErr = fmt.Errorf("creating config file: %w", createErr)
				log.Printf("Error creating config file: %v", createErr)

				return
			}
			defer file.Close()

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")

			if encErr := encoder.Encode(config); encErr != nil {
				loadErr = fmt.Errorf("encoding config file: %w", encErr)
				log.Printf("Error encoding config file: %v", encErr)

				return
			}
		}

		// Override with environment variables if set
		loadEnvironmentVariables(config)
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
	if raw := os.Getenv(key); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			*dst = n
		}
	}
}

// envJSONStringSlice unmarshals a JSON array of strings from key into *dst.
func envJSONStringSlice(key string, dst *[]string) {
	raw := os.Getenv(key)
	if raw == "" {
		return
	}

	var parsed []string
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
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

	// FreeSWITCH
	envString("FS_DEFAULT_DOMAIN", &config.FreeSWITCH.DefaultDomain)

	// Cache
	envBool("CACHE_ENABLED", &config.Cache.Enabled)
	envString("CACHE_SECURITY_TTL", &config.Cache.SecurityTTL)
	envString("CACHE_CLEANUP_INTERVAL", &config.Cache.CleanupInterval)
	envInt("CACHE_MAX_ENTRIES", &config.Cache.MaxEntriesInWindow)
	envInt("CACHE_MAX_ENTRY_SIZE", &config.Cache.MaxEntrySize)
	envInt("CACHE_SHARD_COUNT", &config.Cache.ShardCount)

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
	envBool("SECURITY_AUTO_WHITELIST_ON_SUCCESS", &config.Security.AutoWhitelistOnSuccess)
	envString("SECURITY_ESL_LOG_LEVEL", &config.Security.ESLLogLevel)
	envString("SECURITY_RECONNECT_BACKOFF", &config.Security.ReconnectBackoff)
	envInt("SECURITY_MAX_WRONG_CALL_STATES", &config.Security.MaxWrongCallStates)
	envString("SECURITY_WRONG_CALL_STATE_WINDOW", &config.Security.WrongCallStateWindow)
	envJSONStringSlice("SECURITY_TRUSTED_NETWORKS", &config.Security.TrustedNetworks)
	envJSONStringSlice("SECURITY_UNTRUSTED_NETWORKS", &config.Security.UntrustedNetworks)

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
