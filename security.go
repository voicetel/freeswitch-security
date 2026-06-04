package main

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Static channel buffer sizes. These were dynamic in earlier revisions; the
// resizing logic was inherently racy (it swapped sm.xxxQueue while other
// goroutines still held a reference to the old channel) so it has been
// removed in favor of generously sized fixed buffers.
const (
	blacklistQueueSize  = 4096
	whitelistQueueSize  = 4096
	failedQueueSize     = 16384
	wrongStateQueueSize = 16384

	defaultBatchSize     = 32
	defaultBatchInterval = 100 * time.Millisecond

	cleanupTickInterval = 10 * time.Minute

	// defaultWhitelistTTL is the fallback TTL for whitelist entries when the
	// configured value cannot be parsed.
	defaultWhitelistTTL = 24 * time.Hour

	// trackingBatchSize is the per-flush batch size for failed-attempt and
	// wrong-state queue draining.
	trackingBatchSize = 64
)

// SecurityManager handles all security-related functionality.
type SecurityManager struct {
	mu             sync.RWMutex
	whitelist      map[string]WhitelistEntry
	blacklist      map[string]BlacklistEntry
	failedAttempts map[string]FailedAttempt
	wrongStates    map[string]WrongCallStateEntry

	// Read-mostly. trustedNetworks is set at init and never mutated.
	trustedNetworks []*net.IPNet

	// untrustedPatterns is a constant-time lookup table of exact-match
	// patterns. Mutated under mu.
	untrustedPatterns map[string]struct{}

	cfg effectiveSecurityConfig

	// Async work queues. Each has a single dedicated drainer goroutine.
	blacklistQueue  chan BlacklistRequest
	whitelistQueue  chan WhitelistRequest
	failedQueue     chan FailedAttemptRequest
	wrongStateQueue chan WrongStateRequest

	// Registration counters are updated by every worker on every successful
	// registration; they are atomic so the hot path takes no lock. The
	// remaining stats fields are batch-updated under statsMu.
	totalRegistrations   atomic.Int64
	lastRegistrationUnix atomic.Int64

	statsMu sync.RWMutex
	stats   SecurityStats

	// Lifecycle.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
}

// SecurityConfig is the JSON-tagged configuration shape (kept for API stability).
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

// effectiveSecurityConfig is the validated, parsed config used at runtime.
type effectiveSecurityConfig struct {
	Enabled                bool
	AutoBlockEnabled       bool
	WhitelistEnabled       bool
	AutoWhitelistOnSuccess bool

	IPTablesChain string

	MaxFailedAttempts  int
	FailedWindow       time.Duration
	BlockDuration      time.Duration
	WhitelistTTL       time.Duration
	MaxWrongCallStates int
	WrongStateWindow   time.Duration
}

// WhitelistEntry represents a whitelisted IP address.
type WhitelistEntry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastSeen  time.Time `json:"last_seen"`
	UserID    string    `json:"user_id"`
	Domain    string    `json:"domain"`
	Permanent bool      `json:"permanent"`
}

// BlacklistEntry represents a blacklisted IP address.
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
	FailCount int       `json:"fail_count"`
	Permanent bool      `json:"permanent"`
}

// FailedAttempt tracks failed registration attempts.
type FailedAttempt struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	UserIDs      []string  `json:"user_ids"`
	Domains      []string  `json:"domains"`
}

// WrongCallStateEntry tracks wrong call state events.
type WrongCallStateEntry struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	UserIDs      []string  `json:"user_ids"`
}

// SecurityStats tracks security-related statistics.
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

// BlacklistRequest is a queued request to blacklist an IP.
type BlacklistRequest struct {
	IP        string
	Reason    string
	Permanent bool
	Response  chan error
}

type WhitelistRequest struct {
	IP        string
	UserID    string
	Domain    string
	Permanent bool
	Response  chan error
}

type FailedAttemptRequest struct {
	IP     string
	UserID string
	Domain string
}

type WrongStateRequest struct {
	IP     string
	UserID string
}

// BatchWhitelistRequest is used for batch whitelist operations.
type BatchWhitelistRequest struct {
	IP        string `binding:"required" json:"ip"`
	UserID    string `json:"user_id"`
	Domain    string `json:"domain"`
	Permanent bool   `json:"permanent"`
}

// BatchWhitelistResult is the result of a batch whitelist operation.
type BatchWhitelistResult struct {
	IP        string
	UserID    string
	Domain    string
	Permanent bool
	Error     error
}

// BatchBlacklistRequest is used for batch blacklist operations.
type BatchBlacklistRequest struct {
	IP        string `binding:"required" json:"ip"`
	Reason    string `json:"reason"`
	Permanent bool   `json:"permanent"`
}

// BatchBlacklistResult is the result of a batch blacklist operation.
type BatchBlacklistResult struct {
	IP        string
	Reason    string
	Permanent bool
	Error     error
}

var (
	securityManager *SecurityManager
	secManagerOnce  sync.Once
)

// parseDurationOr returns the parsed duration or fallback if parsing fails.
func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}

	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}

	return d
}

// InitSecurityManager initializes the security manager. iptables setup
// failures are logged but not returned because the manager remains usable in
// a degraded mode (without auto-blocking) when iptables is unavailable.
func InitSecurityManager() {
	secManagerOnce.Do(func() {
		logger := GetLogger()
		cfg := GetConfig()

		eff := effectiveSecurityConfig{
			Enabled:                cfg.Security.Enabled,
			AutoBlockEnabled:       cfg.Security.AutoBlockEnabled,
			WhitelistEnabled:       cfg.Security.WhitelistEnabled,
			AutoWhitelistOnSuccess: cfg.Security.AutoWhitelistOnSuccess,
			IPTablesChain:          cfg.Security.IPTablesChain,
			MaxFailedAttempts:      cfg.Security.MaxFailedAttempts,
			MaxWrongCallStates:     cfg.Security.MaxWrongCallStates,
			FailedWindow:           parseDurationOr(cfg.Security.FailedAttemptsWindow, 10*time.Minute),
			BlockDuration:          parseDurationOr(cfg.Security.BlockDuration, time.Hour),
			WhitelistTTL:           parseDurationOr(cfg.Security.WhitelistTTL, defaultWhitelistTTL),
			WrongStateWindow:       parseDurationOr(cfg.Security.WrongCallStateWindow, 10*time.Minute),
		}

		logger.SetLogLevelFromString(cfg.Security.ESLLogLevel)

		trusted := make([]*net.IPNet, 0, len(cfg.Security.TrustedNetworks))

		for _, s := range cfg.Security.TrustedNetworks {
			_, network, err := net.ParseCIDR(s)
			if err != nil {
				logger.Error("Error parsing trusted network %q: %v", s, err)

				continue
			}

			trusted = append(trusted, network)
		}

		untrusted := make(map[string]struct{}, len(cfg.Security.UntrustedNetworks))
		for _, p := range cfg.Security.UntrustedNetworks {
			untrusted[p] = struct{}{}
		}

		ctx, cancel := context.WithCancel(context.Background())
		securityManager = &SecurityManager{
			whitelist:         make(map[string]WhitelistEntry),
			blacklist:         make(map[string]BlacklistEntry),
			failedAttempts:    make(map[string]FailedAttempt),
			wrongStates:       make(map[string]WrongCallStateEntry),
			trustedNetworks:   trusted,
			untrustedPatterns: untrusted,
			cfg:               eff,
			blacklistQueue:    make(chan BlacklistRequest, blacklistQueueSize),
			whitelistQueue:    make(chan WhitelistRequest, whitelistQueueSize),
			failedQueue:       make(chan FailedAttemptRequest, failedQueueSize),
			wrongStateQueue:   make(chan WrongStateRequest, wrongStateQueueSize),
			ctx:               ctx,
			cancel:            cancel,
		}

		logger.Info("Security manager initialized")
		logger.Info("Whitelist - enabled: %t, ttl: %s, auto-on-success: %t",
			eff.WhitelistEnabled, eff.WhitelistTTL, eff.AutoWhitelistOnSuccess)
		logger.Info("Blacklist - auto-block: %t, max-attempts: %d, window: %s, duration: %s",
			eff.AutoBlockEnabled, eff.MaxFailedAttempts, eff.FailedWindow, eff.BlockDuration)

		if len(untrusted) > 0 {
			logger.Info("Untrusted patterns loaded: %d", len(untrusted))
		}

		if eff.AutoBlockEnabled {
			err := ensureIPTablesChain(eff.IPTablesChain)
			if err != nil {
				logger.Error("Warning: failed to set up iptables chain: %v", err)
			} else {
				logger.Info("Configured iptables chain: %s", eff.IPTablesChain)
			}
		}

		// Start workers.
		securityManager.wg.Add(5)
		go securityManager.processBlacklistQueue()
		go securityManager.processWhitelistQueue()
		go securityManager.processFailedAttemptQueue()
		go securityManager.processWrongStateQueue()
		go securityManager.startCleanupRoutine()
	})
}

// GetSecurityManager returns the security manager instance, initializing it
// on first call.
func GetSecurityManager() *SecurityManager {
	if securityManager == nil {
		InitSecurityManager()
	}

	return securityManager
}

// Shutdown gracefully shuts down the security manager.
func (sm *SecurityManager) Shutdown() {
	if !sm.closed.CompareAndSwap(false, true) {
		return
	}

	logger := GetLogger()
	logger.Info("Shutting down security manager...")

	sm.cancel()
	close(sm.blacklistQueue)
	close(sm.whitelistQueue)
	close(sm.failedQueue)
	close(sm.wrongStateQueue)
	sm.wg.Wait()

	logger.Info("Security manager shutdown complete")
}

// appendUnique appends value to the slice if non-empty, non-"unknown", and
// not already present.
func appendUnique(slice []string, value string) []string {
	if value == "" || value == unknownUser {
		return slice
	}

	if slices.Contains(slice, value) {
		return slice
	}

	return append(slice, value)
}

// AddToBlacklistAsync queues an IP for blacklisting without waiting.
func (sm *SecurityManager) AddToBlacklistAsync(ip, reason string, permanent bool) {
	select {
	case sm.blacklistQueue <- BlacklistRequest{IP: ip, Reason: reason, Permanent: permanent}:
	default:
		GetLogger().Error("Blacklist queue full, dropped async request for IP %s", ip)
	}
}

// AddToBlacklist queues a blacklist request and waits for the result.
func (sm *SecurityManager) AddToBlacklist(ip, reason string, permanent bool) error {
	resp := make(chan error, 1)
	select {
	case sm.blacklistQueue <- BlacklistRequest{IP: ip, Reason: reason, Permanent: permanent, Response: resp}:
	case <-time.After(time.Second):
		return fmt.Errorf("%w: blacklist enqueue", ErrTimeoutQueueing)
	}

	select {
	case err := <-resp:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%w: blacklist", ErrTimeoutWaiting)
	}
}

// AddToWhitelist queues a whitelist request and waits for the result.
func (sm *SecurityManager) AddToWhitelist(ip, userID, domain string, permanent bool) error {
	resp := make(chan error, 1)
	select {
	case sm.whitelistQueue <- WhitelistRequest{IP: ip, UserID: userID, Domain: domain, Permanent: permanent, Response: resp}:
	case <-time.After(time.Second):
		return fmt.Errorf("%w: whitelist enqueue", ErrTimeoutQueueing)
	}

	select {
	case err := <-resp:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%w: whitelist", ErrTimeoutWaiting)
	}
}

// AddToWhitelistAsync queues a whitelist request without waiting for the
// result. Used on the event hot path, where waiting for the batch ticker
// would stall a worker (measured: 100ms per successful registration).
func (sm *SecurityManager) AddToWhitelistAsync(ip, userID, domain string, permanent bool) {
	select {
	case sm.whitelistQueue <- WhitelistRequest{IP: ip, UserID: userID, Domain: domain, Permanent: permanent}:
	default:
		GetLogger().Error("Whitelist queue full, dropped async request for IP %s", ip)
	}
}

// RefreshWhitelistEntry extends the TTL of an existing whitelist entry and
// stamps LastSeen, in place and without the queue round-trip. It reports
// whether the entry existed; re-registrations take this fast path.
func (sm *SecurityManager) RefreshWhitelistEntry(ip string) bool {
	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry, ok := sm.whitelist[ip]
	if !ok {
		return false
	}

	entry.LastSeen = now
	if !entry.Permanent {
		entry.ExpiresAt = now.Add(sm.cfg.WhitelistTTL)
	}

	sm.whitelist[ip] = entry

	return true
}

// ProcessFailedRegistration enqueues a failed registration for tracking.
func (sm *SecurityManager) ProcessFailedRegistration(ip, userID, domain string) {
	select {
	case sm.failedQueue <- FailedAttemptRequest{IP: ip, UserID: userID, Domain: domain}:
	default:
		GetLogger().Error("Failed-attempt queue full, dropping event for IP %s", ip)
	}
}

// ProcessWrongCallState enqueues a wrong call state for tracking.
func (sm *SecurityManager) ProcessWrongCallState(ip, userID string) {
	select {
	case sm.wrongStateQueue <- WrongStateRequest{IP: ip, UserID: userID}:
	default:
		GetLogger().Error("Wrong-state queue full, dropping event for IP %s", ip)
	}
}

// RemoveFromWhitelist removes an IP address from the whitelist.
func (sm *SecurityManager) RemoveFromWhitelist(ip string) {
	logger := GetLogger()

	sm.mu.Lock()
	entry, existed := sm.whitelist[ip]
	delete(sm.whitelist, ip)
	count := len(sm.whitelist)
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveWhitelistEntries = count
	sm.statsMu.Unlock()

	if existed {
		logger.Info("Removed IP %s from whitelist (was for user %s@%s)", ip, entry.UserID, entry.Domain)
	} else {
		logger.Info("Removed IP %s from whitelist", ip)
	}
}

// RemoveFromBlacklist removes an IP address from the blacklist and unblocks it.
func (sm *SecurityManager) RemoveFromBlacklist(ip string) {
	logger := GetLogger()

	sm.mu.Lock()
	_, existed := sm.blacklist[ip]
	delete(sm.blacklist, ip)
	count := len(sm.blacklist)
	autoBlock := sm.cfg.AutoBlockEnabled
	chain := sm.cfg.IPTablesChain
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveBlacklistEntries = count
	sm.statsMu.Unlock()

	if existed && autoBlock {
		err := unblockIPWithIptables(ip, chain)
		if err != nil {
			logger.Error("Failed to unblock IP %s with iptables: %v", ip, err)
		} else {
			logger.Info("Unblocked IP %s with iptables in chain %s", ip, chain)
		}
	}

	logger.Info("Removed IP %s from blacklist", ip)
}

// IsIPWhitelisted reports whether the given IP is whitelisted (including via
// trusted networks). It is a hot path: callers may invoke it once per packet.
//
// The fast path checks the explicit whitelist map first to avoid the cost of
// net.ParseIP, which dominates the function under profiling. ParseIP is only
// called when the explicit whitelist misses AND there is at least one trusted
// network configured.
func (sm *SecurityManager) IsIPWhitelisted(ipStr string) bool {
	sm.mu.RLock()
	entry, mapHit := sm.whitelist[ipStr]
	trustedEmpty := len(sm.trustedNetworks) == 0
	sm.mu.RUnlock()

	if mapHit {
		if entry.Permanent || !entry.ExpiresAt.Before(time.Now()) {
			return true
		}
	}

	if trustedEmpty {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return sm.ipInTrustedNetwork(ip)
}

// IsIPBlacklisted reports whether the given IP is currently blacklisted.
func (sm *SecurityManager) IsIPBlacklisted(ipStr string) bool {
	sm.mu.RLock()
	entry, ok := sm.blacklist[ipStr]
	sm.mu.RUnlock()

	if !ok {
		return false
	}

	if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// IsUntrustedDomain reports whether the given domain matches any untrusted pattern.
func (sm *SecurityManager) IsUntrustedDomain(domain string) bool {
	if domain == "" {
		return false
	}

	sm.mu.RLock()
	_, ok := sm.untrustedPatterns[domain]
	sm.mu.RUnlock()

	return ok
}

// AddUntrustedNetwork adds to the untrusted-networks list.
func (sm *SecurityManager) AddUntrustedNetwork(pattern string) error {
	logger := GetLogger()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.untrustedPatterns[pattern]; exists {
		return fmt.Errorf("%w: %q", ErrUntrustedPatternExists, pattern)
	}

	sm.untrustedPatterns[pattern] = struct{}{}

	logger.Info("Added pattern %q to untrusted networks", pattern)

	return nil
}

// RemoveUntrustedNetwork removes from the untrusted-networks list.
func (sm *SecurityManager) RemoveUntrustedNetwork(pattern string) error {
	logger := GetLogger()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.untrustedPatterns[pattern]; !exists {
		return fmt.Errorf("%w: %q", ErrUntrustedPatternMissing, pattern)
	}

	delete(sm.untrustedPatterns, pattern)
	logger.Info("Removed pattern %q from untrusted networks", pattern)

	return nil
}

// GetUntrustedNetworks returns a snapshot of all untrusted-network patterns.
func (sm *SecurityManager) GetUntrustedNetworks() []string {
	sm.mu.RLock()

	out := make([]string, 0, len(sm.untrustedPatterns))
	for p := range sm.untrustedPatterns {
		out = append(out, p)
	}

	sm.mu.RUnlock()

	return out
}

// GetSecurityStats returns a snapshot of current security statistics.
func (sm *SecurityManager) GetSecurityStats() SecurityStats {
	sm.statsMu.RLock()
	stats := sm.stats
	sm.statsMu.RUnlock()

	stats.TotalRegistrations = int(sm.totalRegistrations.Load())
	if ns := sm.lastRegistrationUnix.Load(); ns != 0 {
		stats.LastRegistrationTime = time.Unix(0, ns)
	}

	return stats
}

// GetWhitelistedIPs returns a snapshot of the whitelist.
func (sm *SecurityManager) GetWhitelistedIPs() map[string]WhitelistEntry {
	now := time.Now()

	sm.mu.RLock()
	out := make(map[string]WhitelistEntry, len(sm.whitelist))

	for ip, e := range sm.whitelist {
		if e.Permanent || e.ExpiresAt.After(now) {
			out[ip] = e
		}
	}

	sm.mu.RUnlock()

	return out
}

// GetWhitelistEntry returns a single whitelist entry by IP.
func (sm *SecurityManager) GetWhitelistEntry(ip string) (WhitelistEntry, bool) {
	sm.mu.RLock()
	entry, ok := sm.whitelist[ip]
	sm.mu.RUnlock()

	if !ok {
		return WhitelistEntry{}, false
	}

	if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
		return WhitelistEntry{}, false
	}

	return entry, true
}

// GetBlacklistedIPs returns a snapshot of the blacklist.
func (sm *SecurityManager) GetBlacklistedIPs() map[string]BlacklistEntry {
	now := time.Now()

	sm.mu.RLock()
	out := make(map[string]BlacklistEntry, len(sm.blacklist))

	for ip, e := range sm.blacklist {
		if e.Permanent || e.ExpiresAt.After(now) {
			out[ip] = e
		}
	}

	sm.mu.RUnlock()

	return out
}

// GetBlacklistEntry returns a single blacklist entry by IP.
func (sm *SecurityManager) GetBlacklistEntry(ip string) (BlacklistEntry, bool) {
	sm.mu.RLock()
	entry, ok := sm.blacklist[ip]
	sm.mu.RUnlock()

	if !ok {
		return BlacklistEntry{}, false
	}

	if !entry.Permanent && entry.ExpiresAt.Before(time.Now()) {
		return BlacklistEntry{}, false
	}

	return entry, true
}

// GetFailedAttempts returns a snapshot of all tracked failed attempts.
func (sm *SecurityManager) GetFailedAttempts() map[string]FailedAttempt {
	sm.mu.RLock()

	out := make(map[string]FailedAttempt, len(sm.failedAttempts))
	maps.Copy(out, sm.failedAttempts)

	sm.mu.RUnlock()

	return out
}

// GetWrongCallStates returns a snapshot of all tracked wrong-state events.
func (sm *SecurityManager) GetWrongCallStates() map[string]WrongCallStateEntry {
	sm.mu.RLock()

	out := make(map[string]WrongCallStateEntry, len(sm.wrongStates))
	maps.Copy(out, sm.wrongStates)

	sm.mu.RUnlock()

	return out
}

// UpdateRegistrationStats updates statistics for a successful registration.
// The IP/userID/domain arguments are accepted for API stability but not stored.
// Lock-free: this runs once per successful registration on the worker hot path.
func (sm *SecurityManager) UpdateRegistrationStats(_, _, _ string) {
	sm.totalRegistrations.Add(1)
	sm.lastRegistrationUnix.Store(time.Now().UnixNano())
}

// AddToWhitelistBatch adds multiple IPs concurrently with a worker cap.
func (sm *SecurityManager) AddToWhitelistBatch(reqs []BatchWhitelistRequest) []BatchWhitelistResult {
	results := make([]BatchWhitelistResult, len(reqs))

	const maxWorkers = 10

	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup

	cfg := GetConfig()

	for i, req := range reqs {
		wg.Add(1)

		go func(idx int, request BatchWhitelistRequest) {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			domain := request.Domain
			if domain == "" {
				domain = cfg.FreeSWITCH.DefaultDomain
			}

			err := sm.AddToWhitelist(request.IP, request.UserID, domain, request.Permanent)
			results[idx] = BatchWhitelistResult{
				IP: request.IP, UserID: request.UserID, Domain: domain, Permanent: request.Permanent, Error: err,
			}
		}(i, req)
	}

	wg.Wait()

	return results
}

// AddToBlacklistBatch adds multiple IPs to the blacklist concurrently.
func (sm *SecurityManager) AddToBlacklistBatch(reqs []BatchBlacklistRequest) []BatchBlacklistResult {
	results := make([]BatchBlacklistResult, len(reqs))

	const maxWorkers = 10

	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup

	for i, req := range reqs {
		wg.Add(1)

		go func(idx int, request BatchBlacklistRequest) {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			err := sm.AddToBlacklist(request.IP, request.Reason, request.Permanent)
			results[idx] = BatchBlacklistResult{
				IP: request.IP, Reason: request.Reason, Permanent: request.Permanent, Error: err,
			}
		}(i, req)
	}

	wg.Wait()

	return results
}

// GetIPTablesInfo returns IPTables chain information.
func (sm *SecurityManager) GetIPTablesInfo() (map[string]any, error) {
	rules, err := getIPTablesRules(sm.cfg.IPTablesChain)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"chain": sm.cfg.IPTablesChain,
		"rules": rules,
	}, nil
}

// SecurityConfigView returns a read-only view of the in-effect config used
// by routes. Returns (enabled, autoBlockEnabled).
func (sm *SecurityManager) SecurityConfigView() (bool, bool) {
	return sm.cfg.Enabled, sm.cfg.AutoBlockEnabled
}

// processBlacklistQueue drains the blacklist queue.
func (sm *SecurityManager) processBlacklistQueue() {
	defer sm.wg.Done()

	ticker := time.NewTicker(defaultBatchInterval)
	defer ticker.Stop()

	batch := make([]BlacklistRequest, 0, defaultBatchSize)
	flush := func() {
		if len(batch) > 0 {
			sm.processBatchBlacklist(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case <-sm.ctx.Done():
			flush()

			return
		case req, ok := <-sm.blacklistQueue:
			if !ok {
				flush()

				return
			}

			batch = append(batch, req)
			if len(batch) >= defaultBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// processBatchBlacklist applies a batch of blacklist requests.
func (sm *SecurityManager) processBatchBlacklist(batch []BlacklistRequest) {
	logger := GetLogger()
	now := time.Now()
	blockDuration := sm.cfg.BlockDuration

	// IPs we successfully accepted into the blacklist; iptables work happens
	// outside the lock to avoid blocking other security operations on fork+exec.
	toBlock := make([]string, 0, len(batch))

	sm.mu.Lock()
	for _, req := range batch {
		ip := net.ParseIP(req.IP)
		if ip == nil {
			if req.Response != nil {
				req.Response <- fmt.Errorf("%w: %s", ErrInvalidIP, req.IP)
			}

			continue
		}

		if _, ok := sm.whitelist[req.IP]; ok {
			if req.Response != nil {
				req.Response <- fmt.Errorf("%w: %s", ErrIPWhitelisted, req.IP)
			}

			continue
		}

		if sm.ipInTrustedNetwork(ip) {
			if req.Response != nil {
				req.Response <- fmt.Errorf("%w: %s", ErrIPInTrustedNetwork, req.IP)
			}

			continue
		}

		entry := BlacklistEntry{
			IP:        req.IP,
			AddedAt:   now,
			ExpiresAt: now.Add(blockDuration),
			Reason:    req.Reason,
			Permanent: req.Permanent,
		}
		sm.blacklist[req.IP] = entry
		delete(sm.failedAttempts, req.IP)

		if sm.cfg.AutoBlockEnabled {
			toBlock = append(toBlock, req.IP)
		}

		logger.Info("Added IP %s to blacklist: %s", req.IP, req.Reason)

		if req.Response != nil {
			req.Response <- nil
		}
	}

	blacklistCount := len(sm.blacklist)
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveBlacklistEntries = blacklistCount
	sm.stats.BlockedAttempts += len(batch)
	sm.statsMu.Unlock()

	if len(toBlock) > 0 {
		sm.batchBlockIPs(toBlock)
	}
}

// ipInTrustedNetwork must be called with sm.mu held (or while trustedNetworks
// is otherwise known to be stable, which is always after init).
func (sm *SecurityManager) ipInTrustedNetwork(ip net.IP) bool {
	for _, n := range sm.trustedNetworks {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// processWhitelistQueue drains the whitelist queue.
func (sm *SecurityManager) processWhitelistQueue() {
	defer sm.wg.Done()

	ticker := time.NewTicker(defaultBatchInterval)
	defer ticker.Stop()

	batch := make([]WhitelistRequest, 0, defaultBatchSize)
	flush := func() {
		if len(batch) > 0 {
			sm.processBatchWhitelist(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case <-sm.ctx.Done():
			flush()

			return
		case req, ok := <-sm.whitelistQueue:
			if !ok {
				flush()

				return
			}

			batch = append(batch, req)
			if len(batch) >= defaultBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// processBatchWhitelist applies a batch of whitelist requests.
func (sm *SecurityManager) processBatchWhitelist(batch []WhitelistRequest) {
	logger := GetLogger()
	now := time.Now()
	ttl := sm.cfg.WhitelistTTL

	// IPs unblocked from iptables outside the lock.
	toUnblock := make([]string, 0)

	sm.mu.Lock()
	for _, req := range batch {
		if net.ParseIP(req.IP) == nil {
			if req.Response != nil {
				req.Response <- fmt.Errorf("%w: %s", ErrInvalidIP, req.IP)
			}

			continue
		}

		entry := WhitelistEntry{
			IP:        req.IP,
			AddedAt:   now,
			ExpiresAt: now.Add(ttl),
			LastSeen:  now,
			UserID:    req.UserID,
			Domain:    req.Domain,
			Permanent: req.Permanent,
		}
		sm.whitelist[req.IP] = entry

		if _, ok := sm.blacklist[req.IP]; ok {
			delete(sm.blacklist, req.IP)

			if sm.cfg.AutoBlockEnabled {
				toUnblock = append(toUnblock, req.IP)
			}
		}

		logger.Info("Added IP %s to whitelist for user %s@%s", req.IP, req.UserID, req.Domain)

		if req.Response != nil {
			req.Response <- nil
		}
	}

	whitelistCount := len(sm.whitelist)
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveWhitelistEntries = whitelistCount
	sm.statsMu.Unlock()

	chain := sm.cfg.IPTablesChain
	for _, ip := range toUnblock {
		err := unblockIPWithIptables(ip, chain)
		if err != nil {
			logger.Error("Failed to unblock IP %s: %v", ip, err)
		}
	}
}

// processFailedAttemptQueue drains the failed-attempt queue.
func (sm *SecurityManager) processFailedAttemptQueue() {
	defer sm.wg.Done()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]FailedAttemptRequest, 0, trackingBatchSize)
	flush := func() {
		if len(batch) > 0 {
			sm.processBatchFailedAttempts(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case <-sm.ctx.Done():
			flush()

			return
		case req, ok := <-sm.failedQueue:
			if !ok {
				flush()

				return
			}

			batch = append(batch, req)
			if len(batch) >= trackingBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// processBatchFailedAttempts handles a batch of failed registration attempts.
func (sm *SecurityManager) processBatchFailedAttempts(batch []FailedAttemptRequest) {
	now := time.Now()
	maxAttempts := sm.cfg.MaxFailedAttempts
	autoBlock := sm.cfg.AutoBlockEnabled

	var toBlacklist []BlacklistRequest

	sm.mu.Lock()
	for _, req := range batch {
		if _, whitelisted := sm.whitelist[req.IP]; whitelisted {
			continue
		}

		ip := net.ParseIP(req.IP)
		if ip == nil || sm.ipInTrustedNetwork(ip) {
			continue
		}

		attempt, ok := sm.failedAttempts[req.IP]
		if !ok {
			attempt = FailedAttempt{
				Count:        1,
				FirstAttempt: now,
				LastAttempt:  now,
				UserIDs:      appendUnique(nil, req.UserID),
				Domains:      appendUnique(nil, req.Domain),
			}
		} else {
			attempt.Count++
			attempt.LastAttempt = now
			attempt.UserIDs = appendUnique(attempt.UserIDs, req.UserID)
			attempt.Domains = appendUnique(attempt.Domains, req.Domain)
		}

		sm.failedAttempts[req.IP] = attempt

		if autoBlock && attempt.Count >= maxAttempts {
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:     req.IP,
				Reason: fmt.Sprintf("Exceeded max failed registrations (%d)", maxAttempts),
			})
		}

		if _, untrusted := sm.untrustedPatterns[req.Domain]; untrusted && req.Domain != "" {
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:     req.IP,
				Reason: fmt.Sprintf("Failed registration from untrusted domain %q", req.Domain),
			})
		}
	}
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.FailedRegistrations += len(batch)
	sm.stats.LastFailedTime = now
	sm.statsMu.Unlock()

	sm.enqueueBlacklist(toBlacklist)
}

// processWrongStateQueue drains the wrong-state queue.
func (sm *SecurityManager) processWrongStateQueue() {
	defer sm.wg.Done()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]WrongStateRequest, 0, trackingBatchSize)
	flush := func() {
		if len(batch) > 0 {
			sm.processBatchWrongStates(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case <-sm.ctx.Done():
			flush()

			return
		case req, ok := <-sm.wrongStateQueue:
			if !ok {
				flush()

				return
			}

			batch = append(batch, req)
			if len(batch) >= trackingBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// processBatchWrongStates handles a batch of wrong-call-state events.
func (sm *SecurityManager) processBatchWrongStates(batch []WrongStateRequest) {
	now := time.Now()
	maxStates := sm.cfg.MaxWrongCallStates
	autoBlock := sm.cfg.AutoBlockEnabled

	var toBlacklist []BlacklistRequest

	sm.mu.Lock()
	for _, req := range batch {
		if _, whitelisted := sm.whitelist[req.IP]; whitelisted {
			continue
		}

		ip := net.ParseIP(req.IP)
		if ip == nil || sm.ipInTrustedNetwork(ip) {
			continue
		}

		attempt, ok := sm.wrongStates[req.IP]
		if !ok {
			attempt = WrongCallStateEntry{
				Count:        1,
				FirstAttempt: now,
				LastAttempt:  now,
				UserIDs:      appendUnique(nil, req.UserID),
			}
		} else {
			attempt.Count++
			attempt.LastAttempt = now
			attempt.UserIDs = appendUnique(attempt.UserIDs, req.UserID)
		}

		sm.wrongStates[req.IP] = attempt

		if autoBlock && attempt.Count >= maxStates {
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:     req.IP,
				Reason: fmt.Sprintf("Exceeded max wrong call states (%d)", maxStates),
			})
		}
	}
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.WrongCallStates += len(batch)
	sm.stats.LastWrongCallStateTime = now
	sm.statsMu.Unlock()

	sm.enqueueBlacklist(toBlacklist)
}

// enqueueBlacklist sends requests to the blacklist queue. If the queue is
// saturated, the request is logged and dropped — better than blocking the
// caller and risking deadlock with the same goroutine that drains the queue.
func (sm *SecurityManager) enqueueBlacklist(reqs []BlacklistRequest) {
	if len(reqs) == 0 {
		return
	}

	logger := GetLogger()

	for _, req := range reqs {
		select {
		case sm.blacklistQueue <- req:
			logger.Info("Queued IP %s for blacklisting: %s", req.IP, req.Reason)
		default:
			logger.Error("Blacklist queue full, dropped request for IP %s", req.IP)
		}
	}
}

// ipListStatus reports both whitelist and blacklist status. It is structured
// to do the minimum work for each case:
//
//   - explicit whitelist hit: 1 map lookup, no ParseIP, no blacklist lookup
//   - trusted-network hit: 1 map lookup + 1 ParseIP, no blacklist lookup
//   - blacklist hit / miss: 2 map lookups + 1 ParseIP if trusted nets configured
//
// The fast paths are equivalent to the public IsIPWhitelisted; the slow path
// avoids the second RLock that calling IsIPWhitelisted then IsIPBlacklisted
// would incur.
func (sm *SecurityManager) ipListStatus(ipStr string) (bool, bool) {
	// time.Now() stays lazy inside the hit branches: hoisting it would add a
	// clock read to the map-miss path, which never needs one (measured +57%
	// on the miss benchmark when hoisted).
	sm.mu.RLock()

	wlEntry, wlHit := sm.whitelist[ipStr]
	if wlHit && (wlEntry.Permanent || !wlEntry.ExpiresAt.Before(time.Now())) {
		sm.mu.RUnlock()

		return true, false
	}

	blEntry, blHit := sm.blacklist[ipStr]
	trustedEmpty := len(sm.trustedNetworks) == 0
	sm.mu.RUnlock()

	if blHit && (blEntry.Permanent || !blEntry.ExpiresAt.Before(time.Now())) {
		return false, true
	}

	if trustedEmpty {
		return false, false
	}

	ip := net.ParseIP(ipStr)
	if ip != nil && sm.ipInTrustedNetwork(ip) {
		return true, false
	}

	return false, false
}

// startCleanupRoutine periodically removes expired/stale entries.
func (sm *SecurityManager) startCleanupRoutine() {
	defer sm.wg.Done()

	ticker := time.NewTicker(cleanupTickInterval)
	defer ticker.Stop()

	logger := GetLogger()
	logger.Info("Starting periodic cleanup routine")

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Cleanup routine shutting down")

			return
		case <-ticker.C:
			sm.cleanupExpiredEntries()
		}
	}
}

// cleanupExpiredEntries removes expired whitelist/blacklist entries and
// stale failed-attempt / wrong-state records in a single locked pass.
func (sm *SecurityManager) cleanupExpiredEntries() {
	logger := GetLogger()
	now := time.Now()
	failedWindow := sm.cfg.FailedWindow
	wrongWindow := sm.cfg.WrongStateWindow
	autoBlock := sm.cfg.AutoBlockEnabled
	chain := sm.cfg.IPTablesChain

	var (
		whitelistRemoved []string
		blacklistRemoved []string
		failedRemoved    int
		wrongRemoved     int
	)

	sm.mu.Lock()
	for ip, e := range sm.whitelist {
		if !e.Permanent && e.ExpiresAt.Before(now) {
			delete(sm.whitelist, ip)
			whitelistRemoved = append(whitelistRemoved, ip)
		}
	}

	for ip, e := range sm.blacklist {
		if !e.Permanent && e.ExpiresAt.Before(now) {
			delete(sm.blacklist, ip)
			blacklistRemoved = append(blacklistRemoved, ip)
		}
	}

	for ip, a := range sm.failedAttempts {
		if a.LastAttempt.Add(failedWindow).Before(now) {
			delete(sm.failedAttempts, ip)

			failedRemoved++
		}
	}

	for ip, a := range sm.wrongStates {
		if a.LastAttempt.Add(wrongWindow).Before(now) {
			delete(sm.wrongStates, ip)

			wrongRemoved++
		}
	}

	whitelistCount := len(sm.whitelist)
	blacklistCount := len(sm.blacklist)
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveWhitelistEntries = whitelistCount
	sm.stats.ActiveBlacklistEntries = blacklistCount
	sm.statsMu.Unlock()

	// Unblock removed blacklist entries from iptables (outside lock).
	if autoBlock {
		for _, ip := range blacklistRemoved {
			err := unblockIPWithIptables(ip, chain)
			if err != nil {
				logger.Error("Failed to unblock expired IP %s: %v", ip, err)
			}
		}
	}

	logger.Info("Cleanup: removed %d whitelist, %d blacklist, %d failed, %d wrong-state",
		len(whitelistRemoved), len(blacklistRemoved), failedRemoved, wrongRemoved)
}

// ----------------------------------------------------------------------
// iptables helpers
// ----------------------------------------------------------------------

// execCommand is the process-spawning seam for the iptables helpers. Tests
// replace it so unit tests never invoke the real iptables binary (which would
// mutate host firewall state or fail unpredictably without privileges).
var execCommand = exec.Command

// runIptablesWithRetry executes the given iptables argv with retry on
// xtables-lock contention. It returns the combined output and the final error.
func runIptablesWithRetry(args ...string) ([]byte, error) {
	const maxRetries = 3

	var lastOut []byte

	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		cmd := execCommand("iptables", args...)

		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, nil
		}

		lastOut, lastErr = out, err

		if strings.Contains(string(out), "xtables lock") && attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)

			continue
		}

		break
	}

	return lastOut, lastErr
}

// ensureIPTablesChain ensures that the iptables chain exists.
func ensureIPTablesChain(chain string) error {
	logger := GetLogger()

	if execCommand("iptables", "-L", chain).Run() == nil {
		logger.Info("Iptables chain %s already exists", chain)

		return nil
	}

	logger.Info("Creating iptables chain %s", chain)

	out, err := runIptablesWithRetry("-N", chain)
	if err != nil && !strings.Contains(string(out), "Chain already exists") {
		return fmt.Errorf("creating iptables chain %s: %w: %s", chain, err, out)
	}

	logger.Info("Adding jump from INPUT to chain %s", chain)

	out, err = runIptablesWithRetry("-A", "INPUT", "-j", chain)
	if err != nil {
		return fmt.Errorf("linking iptables chain %s: %w: %s", chain, err, out)
	}

	return nil
}

// blockIPWithIptables installs a DROP rule for the given IP in the chain.
func blockIPWithIptables(ip, chain string) error {
	logger := GetLogger()
	if execCommand("iptables", "-C", chain, "-s", ip, "-j", "DROP").Run() == nil {
		logger.Info("IP %s is already blocked in chain %s", ip, chain)

		return nil
	}

	out, err := runIptablesWithRetry("-A", chain, "-s", ip, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("iptables block %s: %w: %s", ip, err, out)
	}

	logger.Info("Blocked IP %s in chain %s", ip, chain)

	return nil
}

// unblockIPWithIptables removes a DROP rule for the given IP.
func unblockIPWithIptables(ip, chain string) error {
	logger := GetLogger()
	// iptables -C exits non-zero when the rule does not exist. That's not
	// an error for us — there's nothing to unblock.
	ruleExists := execCommand("iptables", "-C", chain, "-s", ip, "-j", "DROP").Run() == nil
	if !ruleExists {
		logger.Debug("IP %s is not blocked in chain %s", ip, chain)

		return nil
	}

	out, err := runIptablesWithRetry("-D", chain, "-s", ip, "-j", "DROP")
	if err != nil {
		// "Bad rule" / "does a matching rule exist" → already gone, treat as success.
		os := string(out)
		if strings.Contains(os, "Bad rule") || strings.Contains(os, "does a matching rule exist") {
			return nil
		}

		return fmt.Errorf("iptables unblock %s: %w: %s", ip, err, out)
	}

	logger.Info("Unblocked IP %s in chain %s", ip, chain)

	return nil
}

// batchBlockIPs installs DROP rules for many IPs. Each IP is blocked via a
// direct exec of iptables; the original "batch via sh -c" implementation was
// removed because it required shell quoting (gosec G204) for marginal savings.
func (sm *SecurityManager) batchBlockIPs(ips []string) {
	if len(ips) == 0 {
		return
	}

	logger := GetLogger()

	chain := sm.cfg.IPTablesChain
	for _, ip := range ips {
		err := blockIPWithIptables(ip, chain)
		if err != nil {
			logger.Error("Failed to block IP %s: %v", ip, err)
		}
	}
}

// getIPTablesRules returns the current rules for the given chain.
func getIPTablesRules(chain string) ([]string, error) {
	out, err := runIptablesWithRetry("-S", chain)
	if err != nil {
		return nil, fmt.Errorf("listing iptables rules: %w: %s", err, out)
	}

	lines := strings.Split(string(out), "\n")
	rules := make([]string, 0, len(lines))

	for _, l := range lines {
		if l != "" {
			rules = append(rules, l)
		}
	}

	return rules, nil
}
