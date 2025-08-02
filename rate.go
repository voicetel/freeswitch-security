package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateManager handles rate limiting functionality
type RateManager struct {
	securityManager *SecurityManager
	callRates       map[string]RateCounter
	regRates        map[string]RateCounter
	rateMutex       sync.RWMutex
	rateLimitConfig RateLimitConfig

	// Add shutdown mechanism
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled            bool   `json:"enabled"`
	CallRateLimit      int    `json:"call_rate_limit"`
	CallRateInterval   string `json:"call_rate_interval"`
	RegistrationLimit  int    `json:"registration_limit"`
	RegistrationWindow string `json:"registration_window"`
	AutoBlockOnExceed  bool   `json:"auto_block_on_exceed"`
	BlockDuration      string `json:"block_duration"`
	WhitelistBypass    bool   `json:"whitelist_bypass"`
	CleanupInterval    string `json:"cleanup_interval"`
}

// RateCounter tracks request rates
type RateCounter struct {
	Count        int       `json:"count"`
	FirstRequest time.Time `json:"first_request"`
	LastRequest  time.Time `json:"last_request"`
	UserIDs      []string  `json:"user_ids"`
	Domains      []string  `json:"domains"`
}

// NewRateManager creates a new rate manager
func NewRateManager(securityManager *SecurityManager) *RateManager {
	logger := GetLogger()
	config := GetConfig()

	// Set default values
	rateConfig := RateLimitConfig{
		Enabled:            true,
		CallRateLimit:      20,
		CallRateInterval:   "1m",
		RegistrationLimit:  10,
		RegistrationWindow: "1m",
		AutoBlockOnExceed:  true,
		BlockDuration:      "15m",
		WhitelistBypass:    true,
		CleanupInterval:    "5m",
	}

	// Override with config if available
	if config.Security.RateLimit.Enabled {
		rateConfig.Enabled = config.Security.RateLimit.Enabled
		rateConfig.CallRateLimit = config.Security.RateLimit.CallRateLimit
		rateConfig.CallRateInterval = config.Security.RateLimit.CallRateInterval
		rateConfig.RegistrationLimit = config.Security.RateLimit.RegistrationLimit
		rateConfig.RegistrationWindow = config.Security.RateLimit.RegistrationWindow

		if config.Security.RateLimit.AutoBlockOnExceed {
			rateConfig.AutoBlockOnExceed = config.Security.RateLimit.AutoBlockOnExceed
		}

		rateConfig.BlockDuration = config.Security.RateLimit.BlockDuration

		if config.Security.RateLimit.WhitelistBypass {
			rateConfig.WhitelistBypass = config.Security.RateLimit.WhitelistBypass
		}

		rateConfig.CleanupInterval = config.Security.RateLimit.CleanupInterval
	}

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create rate manager
	rm := &RateManager{
		securityManager: securityManager,
		callRates:       make(map[string]RateCounter),
		regRates:        make(map[string]RateCounter),
		rateLimitConfig: rateConfig,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start cleanup routine
	if rateConfig.Enabled {
		rm.wg.Add(1)
		go rm.startRateLimitCleanupRoutine()
	}

	logger.Info("Rate limiting initialized - Enabled: %t, Call limit: %d per %s, Registration limit: %d per %s",
		rateConfig.Enabled,
		rateConfig.CallRateLimit,
		rateConfig.CallRateInterval,
		rateConfig.RegistrationLimit,
		rateConfig.RegistrationWindow)

	return rm
}

// Shutdown gracefully shuts down the rate manager
func (rm *RateManager) Shutdown() {
	logger := GetLogger()
	logger.Info("Shutting down rate manager...")

	// Cancel the context to signal shutdown
	rm.cancel()

	// Wait for all goroutines to finish
	rm.wg.Wait()

	logger.Info("Rate manager shutdown complete")
}

// CheckCallRate checks if an IP is exceeding the call rate limit
func (rm *RateManager) CheckCallRate(ipAddress, userId, domain string) bool {
	logger := GetLogger()

	if !rm.rateLimitConfig.Enabled {
		return true // Rate limiting disabled, always allowed
	}

	// Check if IP is whitelisted and if whitelist bypass is enabled
	if rm.rateLimitConfig.WhitelistBypass && rm.securityManager.IsIPWhitelisted(ipAddress) {
		logger.Debug("IP %s is whitelisted, bypassing call rate limit", ipAddress)
		return true
	}

	// Check if IP is already blacklisted
	if rm.securityManager.IsIPBlacklisted(ipAddress) {
		logger.Debug("IP %s is blacklisted, call not allowed", ipAddress)
		return false
	}

	callRateInterval, err := time.ParseDuration(rm.rateLimitConfig.CallRateInterval)
	if err != nil {
		logger.Error("Error parsing call rate interval: %v, using default 1m", err)
		callRateInterval = time.Minute
	}

	now := time.Now()

	rm.rateMutex.Lock()
	defer rm.rateMutex.Unlock()

	rate, exists := rm.callRates[ipAddress]
	if !exists {
		// First call from this IP
		rm.callRates[ipAddress] = RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      []string{userId},
			Domains:      []string{domain},
		}
		return true
	}

	// Check if we should reset the counter (if the interval has passed)
	if now.Sub(rate.FirstRequest) > callRateInterval {
		rm.callRates[ipAddress] = RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      []string{userId},
			Domains:      []string{domain},
		}
		return true
	}

	// Update counter
	rate.Count++
	rate.LastRequest = now

	// Add userId and domain if not already present
	if userId != "" {
		userExists := false
		for _, id := range rate.UserIDs {
			if id == userId {
				userExists = true
				break
			}
		}
		if !userExists {
			rate.UserIDs = append(rate.UserIDs, userId)
		}
	}

	if domain != "" {
		domainExists := false
		for _, dom := range rate.Domains {
			if dom == domain {
				domainExists = true
				break
			}
		}
		if !domainExists {
			rate.Domains = append(rate.Domains, domain)
		}
	}

	rm.callRates[ipAddress] = rate

	// Check if rate exceeds limit
	if rate.Count > rm.rateLimitConfig.CallRateLimit {
		logger.Info("Call rate limit exceeded for IP %s: %d calls in %s",
			ipAddress, rate.Count, callRateInterval)

		// Auto block if enabled
		if rm.rateLimitConfig.AutoBlockOnExceed {
			reason := fmt.Sprintf("Call rate limit exceeded (%d calls in %s)",
				rate.Count, callRateInterval)
			go func(ip, reason string) {
				if err := rm.securityManager.AddToBlacklist(ip, reason, false); err != nil {
					logger.Error("Failed to add IP %s to blacklist: %v", ip, err)
				}
			}(ipAddress, reason)
		}

		return false
	}

	return true
}

// CheckRegistrationRate checks if an IP is exceeding the registration rate limit
func (rm *RateManager) CheckRegistrationRate(ipAddress, userId, domain string) bool {
	logger := GetLogger()

	// Check if Rate limiting is enabled
	if !rm.rateLimitConfig.Enabled {
		logger.Debug("Rate limiting is disabled, bypassing registration rate limit for IP %s", ipAddress)
		return true
	}

	// Check if IP is whitelisted and if whitelist bypass is enabled
	if rm.rateLimitConfig.WhitelistBypass && rm.securityManager.IsIPWhitelisted(ipAddress) {
		logger.Info("IP %s is whitelisted, bypassing registration rate limit", ipAddress)
		return true
	}

	// Check if IP is already blacklisted
	if rm.securityManager.IsIPBlacklisted(ipAddress) {
		logger.Debug("IP %s is blacklisted, registration not allowed", ipAddress)
		return false
	}

	regWindow, err := time.ParseDuration(rm.rateLimitConfig.RegistrationWindow)
	if err != nil {
		logger.Error("Error parsing registration window: %v, using default 1m", err)
		regWindow = time.Minute
	}

	now := time.Now()

	rm.rateMutex.Lock()
	defer rm.rateMutex.Unlock()

	rate, exists := rm.regRates[ipAddress]
	if !exists {
		// First registration from this IP
		rm.regRates[ipAddress] = RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      []string{userId},
			Domains:      []string{domain},
		}
		return true
	}

	// Check if we should reset the counter (if the window has passed)
	if now.Sub(rate.FirstRequest) > regWindow {
		rm.regRates[ipAddress] = RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      []string{userId},
			Domains:      []string{domain},
		}
		return true
	}

	// Update counter
	rate.Count++
	rate.LastRequest = now

	// Add userId and domain if not already present
	if userId != "" {
		userExists := false
		for _, id := range rate.UserIDs {
			if id == userId {
				userExists = true
				break
			}
		}
		if !userExists {
			rate.UserIDs = append(rate.UserIDs, userId)
		}
	}

	if domain != "" {
		domainExists := false
		for _, dom := range rate.Domains {
			if dom == domain {
				domainExists = true
				break
			}
		}
		if !domainExists {
			rate.Domains = append(rate.Domains, domain)
		}
	}

	rm.regRates[ipAddress] = rate

	// Check if rate exceeds limit
	if rate.Count > rm.rateLimitConfig.RegistrationLimit {
		logger.Info("Registration rate limit exceeded for IP %s: %d registrations in %s",
			ipAddress, rate.Count, regWindow)

		// Auto block if enabled
		if rm.rateLimitConfig.AutoBlockOnExceed {
			reason := fmt.Sprintf("Registration rate limit exceeded (%d registrations in %s)",
				rate.Count, regWindow)
			go func() {
				if err := rm.securityManager.AddToBlacklist(ipAddress, reason, false); err != nil {
					logger := GetLogger()
					logger.Error("Failed to auto-block IP %s: %v", ipAddress, err)
				}
			}()
		}

		return false
	}

	return true
}

// GetCallRates returns the current call rates
func (rm *RateManager) GetCallRates() map[string]RateCounter {
	rm.rateMutex.RLock()
	defer rm.rateMutex.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]RateCounter)
	for ip, rate := range rm.callRates {
		result[ip] = rate
	}

	return result
}

// GetRegistrationRates returns the current registration rates
func (rm *RateManager) GetRegistrationRates() map[string]RateCounter {
	rm.rateMutex.RLock()
	defer rm.rateMutex.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]RateCounter)
	for ip, rate := range rm.regRates {
		result[ip] = rate
	}

	return result
}

// cleanupRateLimits cleans up expired rate counters
func (rm *RateManager) cleanupRateLimits() {
	logger := GetLogger()

	callRateInterval, err := time.ParseDuration(rm.rateLimitConfig.CallRateInterval)
	if err != nil {
		logger.Error("Error parsing call rate interval: %v, using default 1m", err)
		callRateInterval = time.Minute
	}

	regWindow, err := time.ParseDuration(rm.rateLimitConfig.RegistrationWindow)
	if err != nil {
		logger.Error("Error parsing registration window: %v, using default 1m", err)
		regWindow = time.Minute
	}

	now := time.Now()

	rm.rateMutex.Lock()
	defer rm.rateMutex.Unlock()

	// Clean up call rates
	var callRatesToRemove []string
	for ip, rate := range rm.callRates {
		if now.Sub(rate.FirstRequest) > callRateInterval {
			callRatesToRemove = append(callRatesToRemove, ip)
		}
	}

	for _, ip := range callRatesToRemove {
		delete(rm.callRates, ip)
	}

	// Clean up registration rates
	var regRatesToRemove []string
	for ip, rate := range rm.regRates {
		if now.Sub(rate.FirstRequest) > regWindow {
			regRatesToRemove = append(regRatesToRemove, ip)
		}
	}

	for _, ip := range regRatesToRemove {
		delete(rm.regRates, ip)
	}

	logger.Debug("Rate limit cleanup completed: removed %d call rates and %d registration rates",
		len(callRatesToRemove), len(regRatesToRemove))
}

// startRateLimitCleanupRoutine periodically cleans up expired rate limits
func (rm *RateManager) startRateLimitCleanupRoutine() {
	defer rm.wg.Done()

	logger := GetLogger()

	cleanupInterval, err := time.ParseDuration(rm.rateLimitConfig.CleanupInterval)
	if err != nil {
		logger.Error("Error parsing rate limit cleanup interval: %v, using default 5m", err)
		cleanupInterval = 5 * time.Minute
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			logger.Info("Rate limit cleanup routine shutting down")
			return
		case <-ticker.C:
			logger.Debug("Running rate limit cleanup routine")
			rm.cleanupRateLimits()
		}
	}
}
