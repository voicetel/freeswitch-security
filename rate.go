package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// rateShardCount is the number of counter shards. Power of two so the shard
// selector reduces to a mask. Sixteen shards removes essentially all of the
// mutex contention the profiler attributes to a single counter lock while
// keeping the per-manager footprint trivial.
const rateShardCount = 16

// rateShard holds one slice of the per-IP counters under its own lock.
type rateShard struct {
	mu        sync.Mutex
	callRates map[string]*RateCounter
	regRates  map[string]*RateCounter
}

// RateManager handles rate-limiting for calls and registrations.
//
// Counters are sharded by IP: the mutex profile showed the previous single
// lock serializing every CheckCallRate/CheckRegistrationRate caller.
type RateManager struct {
	securityManager *SecurityManager

	shards [rateShardCount]rateShard

	cfg effectiveRateConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// shardMixPrime spreads the two tail bytes across shards; any small odd
// prime works.
const shardMixPrime = 31

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

	rm := newRateManagerWithConfig(sm, eff)

	logger.Info("Rate limiting initialized — enabled=%t calls=%d/%s regs=%d/%s",
		eff.Enabled, eff.CallRateLimit, eff.CallRateInterval, eff.RegistrationLimit, eff.RegWindow)

	return rm
}

// newRateManagerWithConfig builds a rate manager from an already-validated
// config. The cleanup loop is started only when rate limiting is enabled.
func newRateManagerWithConfig(sm *SecurityManager, eff effectiveRateConfig) *RateManager {
	ctx, cancel := context.WithCancel(context.Background())
	rm := &RateManager{
		securityManager: sm,
		cfg:             eff,
		ctx:             ctx,
		cancel:          cancel,
	}

	for i := range rm.shards {
		rm.shards[i].callRates = make(map[string]*RateCounter)
		rm.shards[i].regRates = make(map[string]*RateCounter)
	}

	if eff.Enabled {
		rm.wg.Add(1)
		go rm.cleanupLoop()
	}

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

// GetCallRates returns a snapshot of current per-IP call counters.
func (rm *RateManager) GetCallRates() map[string]RateCounter {
	out := make(map[string]RateCounter)

	for i := range rm.shards {
		shard := &rm.shards[i]

		shard.mu.Lock()
		for ip, rc := range shard.callRates {
			out[ip] = *rc
		}
		shard.mu.Unlock()
	}

	return out
}

// GetRegistrationRates returns a snapshot of current per-IP registration counters.
func (rm *RateManager) GetRegistrationRates() map[string]RateCounter {
	out := make(map[string]RateCounter)

	for i := range rm.shards {
		shard := &rm.shards[i]

		shard.mu.Lock()
		for ip, rc := range shard.regRates {
			out[ip] = *rc
		}
		shard.mu.Unlock()
	}

	return out
}

// CleanupNow runs a single cleanup pass synchronously. Exposed for tests.
// Returns (removedCalls, removedRegs).
func (rm *RateManager) CleanupNow() (int, int) {
	now := time.Now()

	var removedCalls, removedRegs int

	for i := range rm.shards {
		shard := &rm.shards[i]

		shard.mu.Lock()

		for ip, rc := range shard.callRates {
			if now.Sub(rc.FirstRequest) > rm.cfg.CallRateInterval {
				delete(shard.callRates, ip)

				removedCalls++
			}
		}

		for ip, rc := range shard.regRates {
			if now.Sub(rc.FirstRequest) > rm.cfg.RegWindow {
				delete(shard.regRates, ip)

				removedRegs++
			}
		}

		shard.mu.Unlock()
	}

	return removedCalls, removedRegs
}

// RateLimitConfigView returns a snapshot of the rate config used by routes.
func (rm *RateManager) RateLimitConfigView() map[string]any {
	return map[string]any{
		keyEnabled:             rm.cfg.Enabled,
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

// shardFor picks the shard for an IP. The tail bytes are the highest-entropy
// part of dotted-quad addresses; a full hash is unnecessary for contention
// spreading and would tax the serial fast path.
func (rm *RateManager) shardFor(ip string) *rateShard {
	if ip == "" {
		return &rm.shards[0]
	}

	h := uint(ip[len(ip)-1])
	if len(ip) > 1 {
		h = h*shardMixPrime + uint(ip[len(ip)-2])
	}

	return &rm.shards[h%rateShardCount]
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
		window   time.Duration
		limit    int
		bucketID string
	)

	if isCall {
		window = rm.cfg.CallRateInterval
		limit = rm.cfg.CallRateLimit
		bucketID = "call"
	} else {
		window = rm.cfg.RegWindow
		limit = rm.cfg.RegistrationLimit
		bucketID = "registration"
	}

	now := time.Now()
	shard := rm.shardFor(ip)

	shard.mu.Lock()

	bucket := shard.callRates
	if !isCall {
		bucket = shard.regRates
	}

	rc, ok := bucket[ip]
	if !ok || now.Sub(rc.FirstRequest) > window {
		bucket[ip] = &RateCounter{
			Count:        1,
			FirstRequest: now,
			LastRequest:  now,
			UserIDs:      appendUnique(nil, userID),
			Domains:      appendUnique(nil, domain),
		}
		shard.mu.Unlock()

		return true
	}

	rc.Count++
	rc.LastRequest = now
	rc.UserIDs = appendUnique(rc.UserIDs, userID)
	rc.Domains = appendUnique(rc.Domains, domain)
	exceeded := rc.Count > limit
	currentCount := rc.Count
	shard.mu.Unlock()

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
