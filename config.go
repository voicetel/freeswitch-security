package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"sync"
)

// AppConfig holds the application configuration
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

var (
	config     *AppConfig
	configOnce sync.Once
)

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*AppConfig, error) {
	var err error
	configOnce.Do(func() {
		config = &AppConfig{}

		// Set defaults
		// Server defaults
		config.Server.Host = "127.0.0.1"
		config.Server.Port = "8088"
		config.Server.LogRequests = true
		config.Server.LogResponses = false

		// FreeSWITCH defaults
		config.FreeSWITCH.DefaultDomain = "example.com"

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
		config.Security.ESLLogLevel = "info"
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
		if _, err := os.Stat(path); err == nil {
			file, err := os.Open(path)
			if err != nil {
				log.Printf("Error opening config file: %v", err)
				return
			}
			defer file.Close()

			decoder := json.NewDecoder(file)
			err = decoder.Decode(config)
			if err != nil {
				log.Printf("Error decoding config file: %v", err)
				return
			}
		} else {
			// Create a default config file
			file, err := os.Create(path)
			if err != nil {
				log.Printf("Error creating config file: %v", err)
				return
			}
			defer file.Close()

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(config)
			if err != nil {
				log.Printf("Error encoding config file: %v", err)
				return
			}
		}

		// Override with environment variables if set
		loadEnvironmentVariables(config)
	})

	return config, err
}

// GetConfig returns the current configuration
func GetConfig() *AppConfig {
	if config == nil {
		_, err := LoadConfig("config.json")
		if err != nil {
			log.Fatalf("Error loading configuration: %v", err)
		}
	}
	return config
}

// loadEnvironmentVariables overrides config values with environment variables if set
func loadEnvironmentVariables(config *AppConfig) {
	// Server environment variables
	if host := os.Getenv("SERVER_HOST"); host != "" {
		config.Server.Host = host
	}
	if port := os.Getenv("SERVER_PORT"); port != "" {
		config.Server.Port = port
	}
	if logReq := os.Getenv("SERVER_LOG_REQUESTS"); logReq != "" {
		config.Server.LogRequests = (logReq == "true" || logReq == "1" || logReq == "yes")
	}
	if logResp := os.Getenv("SERVER_LOG_RESPONSES"); logResp != "" {
		config.Server.LogResponses = (logResp == "true" || logResp == "1" || logResp == "yes")
	}

	// FreeSWITCH environment variables
	if domain := os.Getenv("FS_DEFAULT_DOMAIN"); domain != "" {
		config.FreeSWITCH.DefaultDomain = domain
	}

	// Cache environment variables
	if cacheEnabled := os.Getenv("CACHE_ENABLED"); cacheEnabled != "" {
		config.Cache.Enabled = (cacheEnabled == "true" || cacheEnabled == "1" || cacheEnabled == "yes")
	}
	if securityTTL := os.Getenv("CACHE_SECURITY_TTL"); securityTTL != "" {
		config.Cache.SecurityTTL = securityTTL
	}
	if cleanupInterval := os.Getenv("CACHE_CLEANUP_INTERVAL"); cleanupInterval != "" {
		config.Cache.CleanupInterval = cleanupInterval
	}
	if maxEntries := os.Getenv("CACHE_MAX_ENTRIES"); maxEntries != "" {
		if val, err := strconv.Atoi(maxEntries); err == nil {
			config.Cache.MaxEntriesInWindow = val
		}
	}
	if maxEntrySize := os.Getenv("CACHE_MAX_ENTRY_SIZE"); maxEntrySize != "" {
		if val, err := strconv.Atoi(maxEntrySize); err == nil {
			config.Cache.MaxEntrySize = val
		}
	}
	if shardCount := os.Getenv("CACHE_SHARD_COUNT"); shardCount != "" {
		if val, err := strconv.Atoi(shardCount); err == nil {
			config.Cache.ShardCount = val
		}
	}

	// Security environment variables
	if secEnabled := os.Getenv("SECURITY_ENABLED"); secEnabled != "" {
		config.Security.Enabled = (secEnabled == "true" || secEnabled == "1" || secEnabled == "yes")
	}
	if eslHost := os.Getenv("SECURITY_ESL_HOST"); eslHost != "" {
		config.Security.ESLHost = eslHost
	}
	if eslPort := os.Getenv("SECURITY_ESL_PORT"); eslPort != "" {
		config.Security.ESLPort = eslPort
	}
	if eslPassword := os.Getenv("SECURITY_ESL_PASSWORD"); eslPassword != "" {
		config.Security.ESLPassword = eslPassword
	}
	// Add environment variable for ESL allowed commands
	if eslAllowedCommands := os.Getenv("SECURITY_ESL_ALLOWED_COMMANDS"); eslAllowedCommands != "" {
		var commands []string
		if err := json.Unmarshal([]byte(eslAllowedCommands), &commands); err == nil {
			config.Security.ESLAllowedCommands = commands
		}
	}
	if maxFailedStr := os.Getenv("SECURITY_MAX_FAILED_ATTEMPTS"); maxFailedStr != "" {
		if maxFailed, err := strconv.Atoi(maxFailedStr); err == nil {
			config.Security.MaxFailedAttempts = maxFailed
		}
	}
	if failedWindow := os.Getenv("SECURITY_FAILED_WINDOW"); failedWindow != "" {
		config.Security.FailedAttemptsWindow = failedWindow
	}
	if autoBlock := os.Getenv("SECURITY_AUTO_BLOCK"); autoBlock != "" {
		config.Security.AutoBlockEnabled = (autoBlock == "true" || autoBlock == "1" || autoBlock == "yes")
	}
	if blockDuration := os.Getenv("SECURITY_BLOCK_DURATION"); blockDuration != "" {
		config.Security.BlockDuration = blockDuration
	}
	if whitelistEnabled := os.Getenv("SECURITY_WHITELIST_ENABLED"); whitelistEnabled != "" {
		config.Security.WhitelistEnabled = (whitelistEnabled == "true" || whitelistEnabled == "1" || whitelistEnabled == "yes")
	}
	if whitelistTTL := os.Getenv("SECURITY_WHITELIST_TTL"); whitelistTTL != "" {
		config.Security.WhitelistTTL = whitelistTTL
	}
	if chain := os.Getenv("SECURITY_IPTABLES_CHAIN"); chain != "" {
		config.Security.IPTablesChain = chain
	}
	if autoWhitelist := os.Getenv("SECURITY_AUTO_WHITELIST_ON_SUCCESS"); autoWhitelist != "" {
		config.Security.AutoWhitelistOnSuccess = (autoWhitelist == "true" || autoWhitelist == "1" || autoWhitelist == "yes")
	}
	if eslLogLevel := os.Getenv("SECURITY_ESL_LOG_LEVEL"); eslLogLevel != "" {
		config.Security.ESLLogLevel = eslLogLevel
	}
	if reconnectBackoff := os.Getenv("SECURITY_RECONNECT_BACKOFF"); reconnectBackoff != "" {
		config.Security.ReconnectBackoff = reconnectBackoff
	}
	if maxWrongCallStates := os.Getenv("SECURITY_MAX_WRONG_CALL_STATES"); maxWrongCallStates != "" {
		if val, err := strconv.Atoi(maxWrongCallStates); err == nil {
			config.Security.MaxWrongCallStates = val
		}
	}
	if wrongCallStateWindow := os.Getenv("SECURITY_WRONG_CALL_STATE_WINDOW"); wrongCallStateWindow != "" {
		config.Security.WrongCallStateWindow = wrongCallStateWindow
	}
	if trustedNetworks := os.Getenv("SECURITY_TRUSTED_NETWORKS"); trustedNetworks != "" {
		var networks []string
		if err := json.Unmarshal([]byte(trustedNetworks), &networks); err == nil {
			config.Security.TrustedNetworks = networks
		}
	}

	// Added environment variable for untrusted networks
	if untrustedNetworks := os.Getenv("SECURITY_UNTRUSTED_NETWORKS"); untrustedNetworks != "" {
		var networks []string
		if err := json.Unmarshal([]byte(untrustedNetworks), &networks); err == nil {
			config.Security.UntrustedNetworks = networks
		}
	}

	// Rate Limit environment variables
	if rateLimitEnabled := os.Getenv("SECURITY_RATE_LIMIT_ENABLED"); rateLimitEnabled != "" {
		config.Security.RateLimit.Enabled = (rateLimitEnabled == "true" || rateLimitEnabled == "1" || rateLimitEnabled == "yes")
	}
	if callRateLimit := os.Getenv("SECURITY_RATE_LIMIT_CALL_LIMIT"); callRateLimit != "" {
		if val, err := strconv.Atoi(callRateLimit); err == nil {
			config.Security.RateLimit.CallRateLimit = val
		}
	}
	if callRateInterval := os.Getenv("SECURITY_RATE_LIMIT_CALL_INTERVAL"); callRateInterval != "" {
		config.Security.RateLimit.CallRateInterval = callRateInterval
	}
	if registrationLimit := os.Getenv("SECURITY_RATE_LIMIT_REG_LIMIT"); registrationLimit != "" {
		if val, err := strconv.Atoi(registrationLimit); err == nil {
			config.Security.RateLimit.RegistrationLimit = val
		}
	}
	if registrationWindow := os.Getenv("SECURITY_RATE_LIMIT_REG_WINDOW"); registrationWindow != "" {
		config.Security.RateLimit.RegistrationWindow = registrationWindow
	}
	if autoBlockOnExceed := os.Getenv("SECURITY_RATE_LIMIT_AUTO_BLOCK"); autoBlockOnExceed != "" {
		config.Security.RateLimit.AutoBlockOnExceed = true
	}
	if rateLimitBlockDuration := os.Getenv("SECURITY_RATE_LIMIT_BLOCK_DURATION"); rateLimitBlockDuration != "" {
		config.Security.RateLimit.BlockDuration = rateLimitBlockDuration
	}
	if whitelistBypass := os.Getenv("SECURITY_RATE_LIMIT_WHITELIST_BYPASS"); whitelistBypass != "" {
		config.Security.RateLimit.WhitelistBypass = (whitelistBypass == "true" || whitelistBypass == "1" || whitelistBypass == "yes")
	}
	if rateLimitCleanupInterval := os.Getenv("SECURITY_RATE_LIMIT_CLEANUP_INTERVAL"); rateLimitCleanupInterval != "" {
		config.Security.RateLimit.CleanupInterval = rateLimitCleanupInterval
	}
}
