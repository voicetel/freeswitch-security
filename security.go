package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SecurityManager handles all security-related functionality
type SecurityManager struct {
	whitelist         map[string]WhitelistEntry
	blacklist         map[string]BlacklistEntry
	securityConfig    SecurityConfig
	failedAttempts    map[string]FailedAttempt
	mutex             sync.RWMutex
	whitelistNetworks []*net.IPNet
	untrustedPatterns []string
	statistics        SecurityStats
	statsMutex        sync.RWMutex
	wrongCallStates   map[string]WrongCallStateEntry
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	Enabled                bool     `json:"enabled"`
	TrustedNetworks        []string `json:"trusted_networks"`
	UntrustedNetworks      []string `json:"untrusted_networks"`
	MaxFailedAttempts      int      `json:"max_failed_attempts"`
	FailedAttemptsWindow   string   `json:"failed_attempts_window"`
	AutoBlockEnabled       bool     `json:"auto_block_enabled"`
	BlockDuration          string   `json:"block_duration"`
	WhitelistEnabled       bool     `json:"whitelist_enabled"`
	WhitelistTTL           string   `json:"whitelist_ttl"`
	IPTablesChain          string   `json:"iptables_chain"`
	AutoWhitelistOnSuccess bool     `json:"auto_whitelist_on_success"`
	MaxWrongCallStates     int      `json:"max_wrong_call_states"`
	WrongCallStateWindow   string   `json:"wrong_call_state_window"`
}

// WhitelistEntry represents a whitelisted IP address
type WhitelistEntry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastSeen  time.Time `json:"last_seen"`
	UserID    string    `json:"user_id"`
	Domain    string    `json:"domain"`
	Permanent bool      `json:"permanent"`
}

// BlacklistEntry represents a blacklisted IP address
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
	FailCount int       `json:"fail_count"`
	Permanent bool      `json:"permanent"`
}

// FailedAttempt tracks failed registration attempts
type FailedAttempt struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	UserIDs      []string  `json:"user_ids"`
	Domains      []string  `json:"domains"`
}

// WrongCallStateEntry tracks wrong call state events
type WrongCallStateEntry struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	UserIDs      []string  `json:"user_ids"`
}

// SecurityStats tracks security-related statistics
type SecurityStats struct {
	TotalRegistrations     int       `json:"total_registrations"`
	FailedRegistrations    int       `json:"failed_registrations"`
	BlockedAttempts        int       `json:"blocked_attempts"`
	WrongCallStates        int       `json:"wrong_call_states"`
	LastRegistrationTime   time.Time `json:"last_registration_time"`
	LastFailedTime         time.Time `json:"last_failed_time"`
	LastWrongCallStateTime time.Time `json:"last_wrong_call_state_time"`
	ActiveWhitelistEntries int       `json:"active_whitelist_entries"`
	ActiveBlacklistEntries int       `json:"active_blacklist_entries"`
}

var (
	securityManager *SecurityManager
	secManagerOnce  sync.Once
)

// InitSecurityManager initializes the security manager
func InitSecurityManager() error {
	var err error
	secManagerOnce.Do(func() {
		logger := GetLogger()
		config := GetConfig()

		// Initialize the security configuration with defaults if not present
		secConfig := SecurityConfig{
			Enabled:                config.Security.Enabled,
			MaxFailedAttempts:      config.Security.MaxFailedAttempts,
			FailedAttemptsWindow:   config.Security.FailedAttemptsWindow,
			AutoBlockEnabled:       config.Security.AutoBlockEnabled,
			BlockDuration:          config.Security.BlockDuration,
			WhitelistEnabled:       config.Security.WhitelistEnabled,
			WhitelistTTL:           config.Security.WhitelistTTL,
			IPTablesChain:          config.Security.IPTablesChain,
			TrustedNetworks:        config.Security.TrustedNetworks,
			UntrustedNetworks:      config.Security.UntrustedNetworks,
			AutoWhitelistOnSuccess: config.Security.AutoWhitelistOnSuccess,
			MaxWrongCallStates:     config.Security.MaxWrongCallStates,
			WrongCallStateWindow:   config.Security.WrongCallStateWindow,
		}

		// Initialize logger with config
		logger.SetLogLevelFromString(config.Security.ESLLogLevel)

		// Parse trusted networks
		var trustedNetworks []*net.IPNet
		for _, networkStr := range secConfig.TrustedNetworks {
			_, network, err := net.ParseCIDR(networkStr)
			if err != nil {
				logger.Error("Error parsing trusted network %s: %v", networkStr, err)
				continue
			}
			trustedNetworks = append(trustedNetworks, network)
		}

		// Initialize the security manager
		securityManager = &SecurityManager{
			whitelist:         make(map[string]WhitelistEntry),
			blacklist:         make(map[string]BlacklistEntry),
			securityConfig:    secConfig,
			failedAttempts:    make(map[string]FailedAttempt),
			wrongCallStates:   make(map[string]WrongCallStateEntry),
			whitelistNetworks: trustedNetworks,
			untrustedPatterns: secConfig.UntrustedNetworks,
			statistics: SecurityStats{
				LastRegistrationTime:   time.Time{},
				LastFailedTime:         time.Time{},
				LastWrongCallStateTime: time.Time{},
			},
		}

		// Log initialization info
		logger.Info("Security manager initialized")
		logger.Info("Whitelist settings - Enabled: %t, TTL: %s, Auto-whitelist: %t",
			secConfig.WhitelistEnabled, secConfig.WhitelistTTL, secConfig.AutoWhitelistOnSuccess)
		logger.Info("Blacklist settings - Auto-block: %t, Max attempts: %d, Window: %s, Duration: %s",
			secConfig.AutoBlockEnabled, secConfig.MaxFailedAttempts, secConfig.FailedAttemptsWindow, secConfig.BlockDuration)

		// Log untrusted networks
		if len(secConfig.UntrustedNetworks) > 0 {
			logger.Info("Untrusted networks loaded - Count: %d", len(secConfig.UntrustedNetworks))
			for i, pattern := range secConfig.UntrustedNetworks {
				logger.Info("  Untrusted pattern #%d: %s", i+1, pattern)
			}
		} else {
			logger.Info("No untrusted networks configured")
		}

		// Ensure the iptables chain exists
		if secConfig.AutoBlockEnabled {
			err = ensureIPTablesChain(secConfig.IPTablesChain)
			if err != nil {
				logger.Error("Warning: Failed to set up iptables chain: %v", err)
			} else {
				logger.Info("Successfully configured iptables chain: %s", secConfig.IPTablesChain)
			}
		}

		// Start cleanup routine
		logger.Info("Starting periodic cleanup routine")
		go securityManager.startCleanupRoutine()
	})

	return err
}

// GetSecurityManager returns the security manager instance
func GetSecurityManager() *SecurityManager {
	if securityManager == nil {
		if err := InitSecurityManager(); err != nil {
			GetLogger().Error("Error initializing security manager: %v", err)
		}
	}
	return securityManager
}

// AddToWhitelist adds an IP address to the whitelist
func (sm *SecurityManager) AddToWhitelist(ipAddress, userId, domain string, permanent bool) error {
	logger := GetLogger()

	// Validate IP address
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	now := time.Now()
	whitelistTTL, err := time.ParseDuration(sm.securityConfig.WhitelistTTL)
	if err != nil {
		logger.Error("Error parsing whitelist TTL: %v, using default 24h", err)
		whitelistTTL = 24 * time.Hour
	}

	entry := WhitelistEntry{
		IP:        ipAddress,
		AddedAt:   now,
		ExpiresAt: now.Add(whitelistTTL),
		LastSeen:  now,
		UserID:    userId,
		Domain:    domain,
		Permanent: permanent,
	}

	// Add to whitelist
	sm.mutex.Lock()
	sm.whitelist[ipAddress] = entry
	count := len(sm.whitelist)
	sm.mutex.Unlock()

	// Update stats
	sm.statsMutex.Lock()
	sm.statistics.ActiveWhitelistEntries = count
	sm.statsMutex.Unlock()

	logger.Info("Added IP %s to whitelist for user %s@%s (expires: %s, permanent: %t)",
		ipAddress, userId, domain, entry.ExpiresAt.Format(time.RFC3339), permanent)

	// Remove from blacklist if present
	sm.RemoveFromBlacklist(ipAddress)

	// Cache the whitelist entry if caching is enabled
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("whitelist:%s", ipAddress)
		data, err := json.Marshal(entry)
		if err == nil {
			cache.CacheSecurityItem(key, data)
		}
	}

	return nil
}

// RemoveFromWhitelist removes an IP address from the whitelist
func (sm *SecurityManager) RemoveFromWhitelist(ipAddress string) error {
	logger := GetLogger()

	sm.mutex.Lock()
	entry, exists := sm.whitelist[ipAddress]
	delete(sm.whitelist, ipAddress)
	count := len(sm.whitelist)
	sm.mutex.Unlock()

	// Update stats
	sm.statsMutex.Lock()
	sm.statistics.ActiveWhitelistEntries = count
	sm.statsMutex.Unlock()

	if exists {
		logger.Info("Removed IP %s from whitelist (was for user %s@%s)", ipAddress, entry.UserID, entry.Domain)
	} else {
		logger.Info("Removed IP %s from whitelist", ipAddress)
	}

	// Remove from cache if caching is enabled
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("whitelist:%s", ipAddress)
		cache.securityCache.Delete(key)
	}

	return nil
}

// AddToBlacklist adds an IP address to the blacklist and blocks it using iptables
func (sm *SecurityManager) AddToBlacklist(ipAddress, reason string, permanent bool) error {
	logger := GetLogger()

	// Validate IP address
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	// Check if IP is whitelisted
	sm.mutex.RLock()
	_, isWhitelisted := sm.whitelist[ipAddress]
	sm.mutex.RUnlock()

	if isWhitelisted {
		logger.Error("Cannot blacklist a whitelisted IP: %s", ipAddress)
		return fmt.Errorf("cannot blacklist a whitelisted IP: %s", ipAddress)
	}

	// Check if IP is in a trusted network
	ip := net.ParseIP(ipAddress)
	for _, network := range sm.whitelistNetworks {
		if network.Contains(ip) {
			logger.Error("Cannot blacklist an IP in trusted network %s: %s", network, ipAddress)
			return fmt.Errorf("cannot blacklist an IP in trusted network %s: %s", network, ipAddress)
		}
	}

	now := time.Now()
	blockDuration, err := time.ParseDuration(sm.securityConfig.BlockDuration)
	if err != nil {
		logger.Error("Error parsing block duration: %v, using default 1h", err)
		blockDuration = time.Hour
	}

	// Get fail count if available
	failCount := 0
	sm.mutex.RLock()
	if attempt, exists := sm.failedAttempts[ipAddress]; exists {
		failCount = attempt.Count
	}
	sm.mutex.RUnlock()

	entry := BlacklistEntry{
		IP:        ipAddress,
		AddedAt:   now,
		ExpiresAt: now.Add(blockDuration),
		Reason:    reason,
		FailCount: failCount,
		Permanent: permanent,
	}

	// Add to blacklist
	sm.mutex.Lock()
	sm.blacklist[ipAddress] = entry
	delete(sm.failedAttempts, ipAddress)
	count := len(sm.blacklist)
	sm.mutex.Unlock()

	// Update stats
	sm.statsMutex.Lock()
	sm.statistics.ActiveBlacklistEntries = count
	sm.statistics.BlockedAttempts++
	sm.statsMutex.Unlock()

	// Block IP with iptables
	if sm.securityConfig.AutoBlockEnabled {
		err := blockIPWithIptables(ipAddress, sm.securityConfig.IPTablesChain)
		if err != nil {
			logger.Error("Failed to block IP %s with iptables: %v", ipAddress, err)
		} else {
			logger.Info("Blocked IP %s with iptables in chain %s", ipAddress, sm.securityConfig.IPTablesChain)
		}
	}

	logger.Info("Added IP %s to blacklist: %s (expires: %s, permanent: %t)",
		ipAddress, reason, entry.ExpiresAt.Format(time.RFC3339), permanent)

	// Cache the blacklist entry if caching is enabled
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("blacklist:%s", ipAddress)
		data, err := json.Marshal(entry)
		if err == nil {
			cache.CacheSecurityItem(key, data)
		}
	}

	return nil
}

// RemoveFromBlacklist removes an IP address from the blacklist and unblocks it using iptables
func (sm *SecurityManager) RemoveFromBlacklist(ipAddress string) error {
	logger := GetLogger()

	sm.mutex.Lock()
	_, wasBlacklisted := sm.blacklist[ipAddress]
	delete(sm.blacklist, ipAddress)
	count := len(sm.blacklist)
	sm.mutex.Unlock()

	// Update stats
	sm.statsMutex.Lock()
	sm.statistics.ActiveBlacklistEntries = count
	sm.statsMutex.Unlock()

	// Unblock IP with iptables if it was blacklisted
	if wasBlacklisted && sm.securityConfig.AutoBlockEnabled {
		err := unblockIPWithIptables(ipAddress, sm.securityConfig.IPTablesChain)
		if err != nil {
			logger.Error("Failed to unblock IP %s with iptables: %v", ipAddress, err)
		} else {
			logger.Info("Unblocked IP %s with iptables in chain %s", ipAddress, sm.securityConfig.IPTablesChain)
		}
	}

	logger.Info("Removed IP %s from blacklist", ipAddress)

	// Remove from cache if caching is enabled
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("blacklist:%s", ipAddress)
		cache.securityCache.Delete(key)
	}

	return nil
}

// IsIPWhitelisted checks if an IP address is whitelisted
func (sm *SecurityManager) IsIPWhitelisted(ipAddress string) bool {
	// Parse the IP
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Check trusted networks first
	for _, network := range sm.whitelistNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	// Check if caching is enabled and look for entry in cache first
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("whitelist:%s", ipAddress)
		data, found := cache.GetSecurityItem(key)
		if found {
			var entry WhitelistEntry
			if err := json.Unmarshal(data, &entry); err == nil {
				// Check if entry is expired
				if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
					// Remove expired entry from cache
					cache.securityCache.Delete(key)
					return false
				}
				return true
			}
		}
	}

	// Check explicit whitelist
	sm.mutex.RLock()
	entry, exists := sm.whitelist[ipAddress]
	sm.mutex.RUnlock()

	if !exists {
		return false
	}

	// Check if entry is expired
	if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// IsIPBlacklisted checks if an IP address is blacklisted
func (sm *SecurityManager) IsIPBlacklisted(ipAddress string) bool {
	// Check if caching is enabled and look for entry in cache first
	cache := GetCacheManager()
	if cache.enabled {
		key := fmt.Sprintf("blacklist:%s", ipAddress)
		data, found := cache.GetSecurityItem(key)
		if found {
			var entry BlacklistEntry
			if err := json.Unmarshal(data, &entry); err == nil {
				// Check if entry is expired
				if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
					// Remove expired entry from cache
					cache.securityCache.Delete(key)
					return false
				}
				return true
			}
		}
	}

	sm.mutex.RLock()
	entry, exists := sm.blacklist[ipAddress]
	sm.mutex.RUnlock()

	if !exists {
		return false
	}

	// Check if entry is expired
	if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// Check if a domain matches any untrusted pattern
func (sm *SecurityManager) IsUntrustedDomain(domain string) bool {
	logger := GetLogger()

	if domain == "" || len(sm.untrustedPatterns) == 0 {
		return false
	}

	for _, pattern := range sm.untrustedPatterns {
		// If the pattern is an exact match
		if pattern == domain {
			logger.Debug("pattern '%s' matched in untrusted networks", domain)
			return true
		}
	}
	return false
}

// AddUntrustedNetwork adds to untrusted networks list
func (sm *SecurityManager) AddUntrustedNetwork(pattern string) error {
	logger := GetLogger()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if pattern already exists
	for _, existing := range sm.untrustedPatterns {
		if existing == pattern {
			return fmt.Errorf("pattern '%s' already exists in untrusted networks", pattern)
		}
	}

	// Add to the list
	sm.untrustedPatterns = append(sm.untrustedPatterns, pattern)
	logger.Info("Added pattern '%s' to untrusted networks", pattern)
	return nil
}

// RemoveUntrustedNetwork removes from untrusted networks list
func (sm *SecurityManager) RemoveUntrustedNetwork(pattern string) error {
	logger := GetLogger()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for i, existing := range sm.untrustedPatterns {
		if existing == pattern {
			// Remove by replacing with last element and truncating
			sm.untrustedPatterns[i] = sm.untrustedPatterns[len(sm.untrustedPatterns)-1]
			sm.untrustedPatterns = sm.untrustedPatterns[:len(sm.untrustedPatterns)-1]
			logger.Info("Removed pattern '%s' from untrusted networks", pattern)
			return nil
		}
	}

	return fmt.Errorf("pattern '%s' not found in untrusted networks", pattern)
}

// GetUntrustedNetworks returns all untrusted network patterns
func (sm *SecurityManager) GetUntrustedNetworks() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Create a copy to avoid race conditions
	result := make([]string, len(sm.untrustedPatterns))
	copy(result, sm.untrustedPatterns)

	return result
}

// startCleanupRoutine periodically cleans up expired whitelist and blacklist entries
func (sm *SecurityManager) startCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		GetLogger().Info("Running scheduled cleanup of expired entries")
		sm.cleanupExpiredEntries()
	}
}

// cleanupExpiredEntries removes expired entries from whitelist and blacklist
func (sm *SecurityManager) cleanupExpiredEntries() {
	logger := GetLogger()
	now := time.Now()

	failedWindow, err := time.ParseDuration(sm.securityConfig.FailedAttemptsWindow)
	if err != nil {
		logger.Error("Error parsing failed attempts window: %v, using default 10m", err)
		failedWindow = 10 * time.Minute
	}

	// Parse wrong call state window
	wrongCallStateWindow, err := time.ParseDuration(sm.securityConfig.WrongCallStateWindow)
	if err != nil {
		logger.Error("Error parsing wrong call state window: %v, using default 10m", err)
		wrongCallStateWindow = 10 * time.Minute
	}

	// Clean up whitelist
	var whitelistToRemove []string
	sm.mutex.RLock()
	for ip, entry := range sm.whitelist {
		if !entry.Permanent && entry.ExpiresAt.Before(now) {
			whitelistToRemove = append(whitelistToRemove, ip)
		}
	}
	sm.mutex.RUnlock()

	for _, ip := range whitelistToRemove {
		logger.Debug("Cleanup: Removing expired whitelist entry for IP %s", ip)
		sm.RemoveFromWhitelist(ip)
	}

	// Clean up blacklist
	var blacklistToRemove []string
	sm.mutex.RLock()
	for ip, entry := range sm.blacklist {
		if !entry.Permanent && entry.ExpiresAt.Before(now) {
			blacklistToRemove = append(blacklistToRemove, ip)
		}
	}
	sm.mutex.RUnlock()

	for _, ip := range blacklistToRemove {
		logger.Debug("Cleanup: Removing expired blacklist entry for IP %s", ip)
		sm.RemoveFromBlacklist(ip)
	}

	// Clean up failed attempts
	var failedToRemove []string
	sm.mutex.RLock()
	for ip, attempt := range sm.failedAttempts {
		if attempt.LastAttempt.Add(failedWindow).Before(now) {
			failedToRemove = append(failedToRemove, ip)
		}
	}
	sm.mutex.RUnlock()

	if len(failedToRemove) > 0 {
		sm.mutex.Lock()
		for _, ip := range failedToRemove {
			logger.Debug("Cleanup: Removing stale failed attempts record for IP %s", ip)
			delete(sm.failedAttempts, ip)
		}
		sm.mutex.Unlock()
	}

	// Clean up wrong call states
	var wrongCallStatesToRemove []string
	sm.mutex.RLock()
	for ip, attempt := range sm.wrongCallStates {
		if attempt.LastAttempt.Add(wrongCallStateWindow).Before(now) {
			wrongCallStatesToRemove = append(wrongCallStatesToRemove, ip)
		}
	}
	sm.mutex.RUnlock()

	if len(wrongCallStatesToRemove) > 0 {
		sm.mutex.Lock()
		for _, ip := range wrongCallStatesToRemove {
			logger.Debug("Cleanup: Removing stale wrong call state record for IP %s", ip)
			delete(sm.wrongCallStates, ip)
		}
		sm.mutex.Unlock()
	}

	logger.Info("Cleanup: removed %d expired whitelist entries, %d expired blacklist entries, %d expired failed attempts, %d expired wrong call states",
		len(whitelistToRemove), len(blacklistToRemove), len(failedToRemove), len(wrongCallStatesToRemove))
}

// GetSecurityStats returns current security statistics
func (sm *SecurityManager) GetSecurityStats() SecurityStats {
	sm.statsMutex.RLock()
	stats := sm.statistics
	sm.statsMutex.RUnlock()
	return stats
}

// GetWhitelistedIPs returns all whitelisted IPs
func (sm *SecurityManager) GetWhitelistedIPs() map[string]WhitelistEntry {
	result := make(map[string]WhitelistEntry)

	sm.mutex.RLock()
	for ip, entry := range sm.whitelist {
		// Only include non-expired entries
		if entry.Permanent || entry.ExpiresAt.After(time.Now()) {
			result[ip] = entry
		}
	}
	sm.mutex.RUnlock()

	return result
}

// GetBlacklistedIPs returns all blacklisted IPs
func (sm *SecurityManager) GetBlacklistedIPs() map[string]BlacklistEntry {
	result := make(map[string]BlacklistEntry)

	sm.mutex.RLock()
	for ip, entry := range sm.blacklist {
		// Only include non-expired entries
		if entry.Permanent || entry.ExpiresAt.After(time.Now()) {
			result[ip] = entry
		}
	}
	sm.mutex.RUnlock()

	return result
}

// GetFailedAttempts returns all tracked failed attempts
func (sm *SecurityManager) GetFailedAttempts() map[string]FailedAttempt {
	result := make(map[string]FailedAttempt)

	sm.mutex.RLock()
	for ip, attempt := range sm.failedAttempts {
		result[ip] = attempt
	}
	sm.mutex.RUnlock()

	return result
}

// GetWrongCallStates returns all tracked wrong call state events
func (sm *SecurityManager) GetWrongCallStates() map[string]WrongCallStateEntry {
	result := make(map[string]WrongCallStateEntry)

	sm.mutex.RLock()
	for ip, attempt := range sm.wrongCallStates {
		result[ip] = attempt
	}
	sm.mutex.RUnlock()

	return result
}

// ensureIPTablesChain ensures that the iptables chain exists
func ensureIPTablesChain(chain string) error {
	logger := GetLogger()

	// Check if chain exists
	checkCmd := exec.Command("iptables", "-L", chain)
	err := checkCmd.Run()

	if err != nil {
		// Chain doesn't exist, create it
		logger.Info("Creating iptables chain %s", chain)
		createCmd := exec.Command("iptables", "-N", chain)
		if err := createCmd.Run(); err != nil {
			return fmt.Errorf("failed to create iptables chain %s: %v", chain, err)
		}

		// Add a jump from INPUT to our chain
		logger.Info("Adding jump from INPUT to chain %s", chain)
		linkCmd := exec.Command("iptables", "-A", "INPUT", "-j", chain)
		if err := linkCmd.Run(); err != nil {
			return fmt.Errorf("failed to link iptables chain %s to INPUT: %v", chain, err)
		}
	} else {
		logger.Info("Iptables chain %s already exists", chain)
	}

	return nil
}

// blockIPWithIptables blocks an IP address using iptables
func blockIPWithIptables(ip, chain string) error {
	logger := GetLogger()

	// First check if the rule already exists
	checkCmd := exec.Command("iptables", "-C", chain, "-s", ip, "-j", "REJECT", "--reject-with", "icmp-host-prohibited")
	if checkCmd.Run() == nil {
		logger.Info("IP %s is already blocked in chain %s", ip, chain)
		return nil
	}

	logger.Info("Adding iptables rule to block IP %s in chain %s", ip, chain)
	cmd := exec.Command("iptables", "-A", chain, "-s", ip, "-j", "REJECT", "--reject-with", "icmp-host-prohibited")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables error: %v, output: %s", err, string(output))
	}
	return nil
}

// unblockIPWithIptables unblocks an IP address using iptables
func unblockIPWithIptables(ip, chain string) error {
	logger := GetLogger()

	logger.Info("Removing iptables rule to unblock IP %s in chain %s", ip, chain)
	cmd := exec.Command("iptables", "-D", chain, "-s", ip, "-j", "REJECT", "--reject-with", "icmp-host-prohibited")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables error: %v, output: %s", err, string(output))
	}
	return nil
}

// getIPTablesRules gets the current iptables rules for the chain
func getIPTablesRules(chain string) ([]string, error) {
	logger := GetLogger()

	logger.Debug("Fetching iptables rules for chain %s", chain)
	cmd := exec.Command("iptables", "-S", chain)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error getting iptables rules: %v", err)
	}

	rules := strings.Split(string(output), "\n")
	var result []string

	for _, rule := range rules {
		if rule != "" {
			result = append(result, rule)
		}
	}

	logger.Debug("Found %d rules in iptables chain %s", len(result), chain)
	return result, nil
}

// UpdateRegistrationStats updates statistics for a successful registration
func (sm *SecurityManager) UpdateRegistrationStats(ipAddress, userId, domain string) {
	sm.statsMutex.Lock()
	defer sm.statsMutex.Unlock()

	sm.statistics.TotalRegistrations++
	sm.statistics.LastRegistrationTime = time.Now()
}

// ProcessWrongCallState processes a wrong call state event
func (sm *SecurityManager) ProcessWrongCallState(ipAddress, userId string) {
	logger := GetLogger()

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.WrongCallStates++
	sm.statistics.LastWrongCallStateTime = time.Now()
	sm.statsMutex.Unlock()

	// Check if IP is whitelisted
	sm.mutex.RLock()
	_, isWhitelisted := sm.whitelist[ipAddress]
	sm.mutex.RUnlock()

	if isWhitelisted {
		logger.Debug("IP %s is whitelisted, ignoring wrong call state", ipAddress)
		return
	}

	// Check if IP is in a trusted network
	ip := net.ParseIP(ipAddress)
	for _, network := range sm.whitelistNetworks {
		if network.Contains(ip) {
			logger.Debug("IP %s is in trusted network %s, ignoring wrong call state", ipAddress, network)
			return
		}
	}

	// Update wrong call state count
	sm.mutex.Lock()
	attempt, exists := sm.wrongCallStates[ipAddress]
	if !exists {
		attempt = WrongCallStateEntry{
			Count:        1,
			FirstAttempt: time.Now(),
			LastAttempt:  time.Now(),
			UserIDs:      []string{userId},
		}
		logger.Debug("First wrong call state from IP %s", ipAddress)
	} else {
		attempt.Count++
		attempt.LastAttempt = time.Now()
		logger.Debug("Incrementing wrong call states for IP %s to %d", ipAddress, attempt.Count)

		// Add userId to the list if not already present
		userExists := false
		for _, id := range attempt.UserIDs {
			if id == userId {
				userExists = true
				break
			}
		}
		if !userExists && userId != "unknown" {
			attempt.UserIDs = append(attempt.UserIDs, userId)
			logger.Debug("Added new user ID %s to wrong call states for IP %s", userId, ipAddress)
		}
	}
	sm.wrongCallStates[ipAddress] = attempt
	sm.mutex.Unlock()

	// Check if we should block this IP
	if sm.securityConfig.AutoBlockEnabled && attempt.Count >= sm.securityConfig.MaxWrongCallStates {
		reason := fmt.Sprintf("Exceeded max wrong call states (%d)", sm.securityConfig.MaxWrongCallStates)
		logger.Info("Threshold exceeded: Auto-blocking IP %s - %s", ipAddress, reason)
		sm.AddToBlacklist(ipAddress, reason, false)
	}
}

// ProcessFailedRegistration processes a failed registration event
func (sm *SecurityManager) ProcessFailedRegistration(ipAddress, userId, domain string) {
	logger := GetLogger()

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.FailedRegistrations++
	sm.statistics.LastFailedTime = time.Now()
	sm.statsMutex.Unlock()

	// Check if IP is whitelisted
	sm.mutex.RLock()
	_, isWhitelisted := sm.whitelist[ipAddress]
	sm.mutex.RUnlock()

	if isWhitelisted {
		logger.Debug("IP %s is whitelisted, ignoring failed registration", ipAddress)
		return
	}

	// Check if IP is in a trusted network
	ip := net.ParseIP(ipAddress)
	for _, network := range sm.whitelistNetworks {
		if network.Contains(ip) {
			logger.Debug("IP %s is in trusted network %s, ignoring failed registration", ipAddress, network)
			return
		}
	}

	// Update failed attempts count
	sm.mutex.Lock()
	attempt, exists := sm.failedAttempts[ipAddress]
	if !exists {
		attempt = FailedAttempt{
			Count:        1,
			FirstAttempt: time.Now(),
			LastAttempt:  time.Now(),
			UserIDs:      []string{userId},
			Domains:      []string{domain},
		}
		logger.Debug("First failed attempt from IP %s", ipAddress)
	} else {
		attempt.Count++
		attempt.LastAttempt = time.Now()
		logger.Debug("Incrementing failed attempts for IP %s to %d", ipAddress, attempt.Count)

		// Add userId to the list if not already present
		userExists := false
		for _, id := range attempt.UserIDs {
			if id == userId {
				userExists = true
				break
			}
		}
		if !userExists && userId != "unknown" {
			attempt.UserIDs = append(attempt.UserIDs, userId)
			logger.Debug("Added new user ID %s to failed attempts for IP %s", userId, ipAddress)
		}

		// Add domain to the list if not already present
		domainExists := false
		for _, dom := range attempt.Domains {
			if dom == domain {
				domainExists = true
				break
			}
		}
		if !domainExists && domain != "" {
			attempt.Domains = append(attempt.Domains, domain)
			logger.Debug("Added new domain %s to failed attempts for IP %s", domain, ipAddress)
		}
	}
	sm.failedAttempts[ipAddress] = attempt
	sm.mutex.Unlock()

	// Check if we should block this IP
	if sm.securityConfig.AutoBlockEnabled && attempt.Count >= sm.securityConfig.MaxFailedAttempts {
		reason := fmt.Sprintf("Exceeded max failed registrations (%d)", sm.securityConfig.MaxFailedAttempts)
		logger.Info("Threshold exceeded: Auto-blocking IP %s - %s", ipAddress, reason)
		sm.AddToBlacklist(ipAddress, reason, false)
	}

	// Check if domain matches any untrusted pattern
	if sm.IsUntrustedDomain(domain) {
		logger.Info("Failed registration from IP %s for domain %s blocked (untrusted domain)",
			ipAddress, domain)
		reason := fmt.Sprintf("Failed registration attempt from untrusted domain '%s'", domain)
		sm.AddToBlacklist(ipAddress, reason, false)
	}
}
