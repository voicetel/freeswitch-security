package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateManager handles rate-limiting for calls and registrations.
type RateManager struct {
	securityManager *SecurityManager

	mu        sync.Mutex
	callRates map[string]*RateCounter
	regRates  map[string]*RateCounter

	cfg effectiveRateConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// RateLimitConfig holds rate-limiting configuration (JSON shape).
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

// defaultRateBlockDuration is the fallback block duration when the configured
// value is missing or fails to parse.
const defaultRateBlockDuration = 15 * time.Minute

// effectiveRateConfig is the validated/parsed shape used at runtime.
type effectiveRateConfig struct {
	Enabled           bool
	AutoBlockOnExceed bool
	WhitelistBypass   bool

	CallRateLimit     int
	CallRateInterval  time.Duration
	RegistrationLimit int
	RegWindow         time.Duration
	BlockDuration     time.Duration
	CleanupInterval   time.Duration
}

// RateCounter tracks request rates for a single IP.
type RateCounter struct {
	Count        int       `json:"count"`
	FirstRequest time.Time `json:"first_request"`
	LastRequest  time.Time `json:"last_request"`
	UserIDs      []string  `json:"user_ids"`
	Domains      []string  `json:"domains"`
}

// NewRateManager creates a new rate manager from the global config.
func NewRateManager(sm *SecurityManager) *RateManager {
	logger := GetLogger()
	cfg := GetConfig()
	rl := cfg.Security.RateLimit

	eff := effectiveRateConfig{
		Enabled:           rl.Enabled,
		AutoBlockOnExceed: rl.AutoBlockOnExceed,
		WhitelistBypass:   rl.WhitelistBypass,
		CallRateLimit:     rl.CallRateLimit,
		RegistrationLimit: rl.RegistrationLimit,
		CallRateInterval:  parseDurationOr(rl.CallRateInterval, time.Minute),
		RegWindow:         parseDurationOr(rl.RegistrationWindow, time.Minute),
		BlockDuration:     parseDurationOr(rl.BlockDuration, defaultRateBlockDuration),
		CleanupInterval:   parseDurationOr(rl.CleanupInterval, 5*time.Minute),
	}

	ctx, cancel := context.WithCancel(context.Background())
	rm := &RateManager{
		securityManager: sm,
		callRates:       make(map[string]*RateCounter),
		regRates:        make(map[string]*RateCounter),
		cfg:             eff,
		ctx:             ctx,
		cancel:          cancel,
	}

	if eff.Enabled {
		rm.wg.Add(1)
		go rm.cleanupLoop()
	}

	logger.Info("Rate limiting initialized — enabled=%t calls=%d/%s regs=%d/%s",
		eff.Enabled, eff.CallRateLimit, eff.CallRateInterval, eff.RegistrationLimit, eff.RegWindow)

	return rm
}

// Shutdown gracefully shuts down the rate manager.
func (rm *RateManager) Shutdown() {
	GetLogger().Info("Shutting down rate manager...")
	rm.cancel()
	rm.wg.Wait()
	GetLogger().Info("Rate manager shutdown complete")
}

// CheckCallRate reports whether the IP is permitted to place another call.
func (rm *RateManager) CheckCallRate(ip, userID, domain string) bool {
	return rm.checkRate(ip, userID, domain, true)
}

// CheckRegistrationRate reports whether the IP is permitted to register again.
func (rm *RateManager) CheckRegistrationRate(ip, userID, domain string) bool {
	return rm.checkRate(ip, userID, domain, false)
}

// checkRate is the shared implementation for call and registration rate checks.
// isCall switches between the call and registration counter buckets / limits.
func (rm *RateManager) checkRate(ip, userID, domain string, isCall bool) bool {
	logger := GetLogger()

	if !rm.cfg.Enabled {
		return true
	}

	// Combined exempt-status check: one RLock + (at most) one net.ParseIP for
	// both whitelist and blacklist. Halves the synchronization overhead of
	// calling IsIPWhitelisted then IsIPBlacklisted separately.
	whitelisted, blacklisted := rm.securityManager.ipListStatus(ip)
	if rm.cfg.WhitelistBypass && whitelisted {
		return true
	}

	if blacklisted {
		return false
	}

	var (
		bucket   map[string]*RateCounter
		window   time.Duration
		limit    int
		bucketID string
	)

	if isCall {
		bucket = rm.callRates
		window = rm.cfg.CallRateInterval
		limit = rm.cfg.CallRateLimit
		bucketID = "call"
	} else {
		bucket = rm.regRates
		window = rm.cfg.RegWindow
		limit = rm.cfg.RegistrationLimit
		bucketID = "registration"
	}

	now := time.Now()

	rm.mu.Lock()

	rc, ok := bucket[ip]
	if !ok || now.Sub(rc.FirstRequest) > window {
		bucket[ip] = &RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      appendUnique(nil, userID),
			Domains:      appendUnique(nil, domain),
		}
		rm.mu.Unlock()

		return true
	}

	rc.Count++
	rc.LastRequest = now
	rc.UserIDs = appendUnique(rc.UserIDs, userID)
	rc.Domains = appendUnique(rc.Domains, domain)
	exceeded := rc.Count > limit
	currentCount := rc.Count
	rm.mu.Unlock()

	if !exceeded {
		return true
	}

	logger.Info("%s rate limit exceeded for IP %s: %d in %s", bucketID, ip, currentCount, window)

	if rm.cfg.AutoBlockOnExceed {
		reason := fmt.Sprintf("%s rate limit exceeded (%d in %s)", bucketID, currentCount, window)
		rm.securityManager.AddToBlacklistAsync(ip, reason, false)
	}

	return false
}

// GetCallRates returns a snapshot of current per-IP call counters.
func (rm *RateManager) GetCallRates() map[string]RateCounter {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	out := make(map[string]RateCounter, len(rm.callRates))
	for ip, rc := range rm.callRates {
		out[ip] = *rc
	}

	return out
}

// GetRegistrationRates returns a snapshot of current per-IP registration counters.
func (rm *RateManager) GetRegistrationRates() map[string]RateCounter {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	out := make(map[string]RateCounter, len(rm.regRates))
	for ip, rc := range rm.regRates {
		out[ip] = *rc
	}

	return out
}

// CleanupNow runs a single cleanup pass synchronously. Exposed for tests.
// Returns (removedCalls, removedRegs).
func (rm *RateManager) CleanupNow() (int, int) {
	now := time.Now()

	rm.mu.Lock()
	defer rm.mu.Unlock()

	var removedCalls, removedRegs int

	for ip, rc := range rm.callRates {
		if now.Sub(rc.FirstRequest) > rm.cfg.CallRateInterval {
			delete(rm.callRates, ip)

			removedCalls++
		}
	}

	for ip, rc := range rm.regRates {
		if now.Sub(rc.FirstRequest) > rm.cfg.RegWindow {
			delete(rm.regRates, ip)

			removedRegs++
		}
	}

	return removedCalls, removedRegs
}

func (rm *RateManager) cleanupLoop() {
	defer rm.wg.Done()

	logger := GetLogger()

	ticker := time.NewTicker(rm.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			logger.Info("Rate cleanup routine shutting down")

			return
		case <-ticker.C:
			c, r := rm.CleanupNow()
			logger.Debug("Rate cleanup: removed %d call rates, %d registration rates", c, r)
		}
	}
}

// RateLimitConfigView returns a snapshot of the rate config used by routes.
func (rm *RateManager) RateLimitConfigView() map[string]interface{} {
	return map[string]interface{}{
		"enabled":              rm.cfg.Enabled,
		"call_rate_limit":      rm.cfg.CallRateLimit,
		"call_rate_interval":   rm.cfg.CallRateInterval.String(),
		"registration_limit":   rm.cfg.RegistrationLimit,
		"registration_window":  rm.cfg.RegWindow.String(),
		"auto_block_on_exceed": rm.cfg.AutoBlockOnExceed,
		"block_duration":       rm.cfg.BlockDuration.String(),
		"whitelist_bypass":     rm.cfg.WhitelistBypass,
		"cleanup_interval":     rm.cfg.CleanupInterval.String(),
	}
}
