package main

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
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
	trustedNetworks []netip.Prefix

	// untrustedPatterns is a constant-time lookup table of exact-match
	// patterns. Mutated under mu.
	untrustedPatterns map[string]struct{}

	cfg effectiveSecurityConfig

	// ipset is the firewall backend: a kernel ipset referenced by one
	// iptables match-set DROP rule. Membership changes are O(1) and per-IP
	// bans expire in-kernel via the entry timeout.
	ipset *IPSetManager

	// reporter forwards every firewall block to the central chanDaemon
	// repository (D39). nil when reporting is disabled (or in dry-run); when
	// non-nil, each successful ipset block is reported best-effort.
	reporter *ChanDaemonReporter

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

// effectiveSecurityConfig is the validated, parsed config used at runtime.
type effectiveSecurityConfig struct {
	Enabled                bool
	AutoBlockEnabled       bool
	WhitelistEnabled       bool
	AutoWhitelistOnSuccess bool

	IPTablesChain string
	IPSetName     string
	DryRun        bool

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
	AddedAt   time.Time `json:"addedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	LastSeen  time.Time `json:"lastSeen"`
	UserID    string    `json:"userId"`
	Domain    string    `json:"domain"`
	Permanent bool      `json:"permanent"`
}

// BlacklistEntry represents a blacklisted IP address.
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"addedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Reason    string    `json:"reason"`
	FailCount int       `json:"failCount"`
	Permanent bool      `json:"permanent"`
}

// FailedAttempt tracks failed registration attempts.
type FailedAttempt struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"firstAttempt"`
	LastAttempt  time.Time `json:"lastAttempt"`
	UserIDs      []string  `json:"userIds"`
	Domains      []string  `json:"domains"`
}

// WrongCallStateEntry tracks wrong call state events.
type WrongCallStateEntry struct {
	Count        int       `json:"count"`
	FirstAttempt time.Time `json:"firstAttempt"`
	LastAttempt  time.Time `json:"lastAttempt"`
	UserIDs      []string  `json:"userIds"`
}

// SecurityStats tracks security-related statistics.
type SecurityStats struct {
	TotalRegistrations     int       `json:"totalRegistrations"`
	FailedRegistrations    int       `json:"failedRegistrations"`
	BlockedAttempts        int       `json:"blockedAttempts"`
	WrongCallStates        int       `json:"wrongCallStates"`
	LastRegistrationTime   time.Time `json:"lastRegistrationTime"`
	LastFailedTime         time.Time `json:"lastFailedTime"`
	LastWrongCallStateTime time.Time `json:"lastWrongCallStateTime"`
	ActiveWhitelistEntries int       `json:"activeWhitelistEntries"`
	ActiveBlacklistEntries int       `json:"activeBlacklistEntries"`
	// chanDaemon (D39) reporting counters; both 0 when reporting is disabled.
	ReportsSent   uint64 `json:"reportsSent"`
	ReportsFailed uint64 `json:"reportsFailed"`
}

// BlacklistRequest is a queued request to blacklist an IP. FromUser is the
// best-effort SIP From-user associated with the block; it is forwarded to
// chanDaemon for account attribution and is "" for manual/API blocks.
type BlacklistRequest struct {
	IP        string
	Reason    string
	FromUser  string
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
	UserID    string `json:"userId"`
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
			IPSetName:              cfg.Security.IPSetName,
			DryRun:                 cfg.Security.DryRun,
			MaxFailedAttempts:      cfg.Security.MaxFailedAttempts,
			MaxWrongCallStates:     cfg.Security.MaxWrongCallStates,
			FailedWindow:           parseDurationOr(cfg.Security.FailedAttemptsWindow, 10*time.Minute),
			BlockDuration:          parseDurationOr(cfg.Security.BlockDuration, time.Hour),
			WhitelistTTL:           parseDurationOr(cfg.Security.WhitelistTTL, defaultWhitelistTTL),
			WrongStateWindow:       parseDurationOr(cfg.Security.WrongCallStateWindow, 10*time.Minute),
		}

		logger.SetLogLevelFromString(cfg.Security.ESLLogLevel)

		trusted := make([]netip.Prefix, 0, len(cfg.Security.TrustedNetworks))

		for _, s := range cfg.Security.TrustedNetworks {
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				logger.Error("Error parsing trusted network %q: %v", s, err)

				continue
			}

			trusted = append(trusted, prefix.Masked())
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
			ipset:             NewIPSetManager(eff.IPTablesChain, eff.IPSetName, eff.BlockDuration, eff.DryRun, logger),
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
			err := securityManager.ipset.EnsureSetup()
			if err != nil {
				logger.Error("Warning: failed to set up ipset firewall: %v", err)
			} else {
				logger.Info("Configured ipset %q in chain %s", eff.IPSetName, eff.IPTablesChain)

				// Flush bans from a previous run and remove any legacy per-IP
				// "Auto-blocked" iptables rules left by pre-ipset versions.
				removed, cerr := securityManager.ipset.CleanupAutoBlocked()
				if cerr != nil {
					logger.Error("Warning: ipset cleanup failed: %v", cerr)
				} else if removed > 0 {
					logger.Info("Cleared %d stale ban entr(ies) on startup", removed)
				}
			}
		}

		securityManager.initChanDaemonReporter(cfg, logger)

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

	// Drain any in-flight chanDaemon reports queued by the workers above.
	if sm.reporter != nil {
		sm.reporter.Wait()
	}

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
	sm.mu.Unlock()

	sm.statsMu.Lock()
	sm.stats.ActiveBlacklistEntries = count
	sm.statsMu.Unlock()

	if existed && autoBlock {
		err := sm.ipset.UnblockIP(ip)
		if err != nil {
			logger.Error("Failed to unblock IP %s: %v", ip, err)
		} else {
			logger.Info("Unblocked IP %s from ipset", ip)
		}
	}

	logger.Info("Removed IP %s from blacklist", ip)
}

// IsIPWhitelisted reports whether the given IP is whitelisted (including via
// trusted networks). It is a hot path: callers may invoke it once per packet.
//
// The fast path checks the explicit whitelist map first to avoid the cost of
// parsing the address, which dominates the function under profiling. The parse
// happens only when the explicit whitelist misses AND there is at least one
// trusted network configured.
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

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	return sm.ipInTrustedNetwork(addr)
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

// CheckUntrustedCall decides whether an inbound INVITE (CHANNEL_CREATE) from the
// given source IP and From-domain should be filtered. Trusted networks and
// whitelisted IPs are always allowed (checked first); otherwise, if the domain
// matches an untrusted pattern, the source IP is queued for blacklisting (ipset
// + chanDaemon report, like the failed-registration path) and the function
// returns true so the caller can tear the call down. fromUser is the SIP
// From-user, forwarded for chanDaemon account attribution.
func (sm *SecurityManager) CheckUntrustedCall(ip, fromUser, domain string) bool {
	// Trusted networks and whitelisted IPs win — never filtered.
	if sm.IsIPWhitelisted(ip) {
		return false
	}

	if !sm.IsUntrustedDomain(domain) {
		return false
	}

	sm.enqueueBlacklist([]BlacklistRequest{{
		IP:       ip,
		Reason:   fmt.Sprintf("Call from untrusted domain %q", domain),
		FromUser: reportableUser(fromUser),
	}})

	return true
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

	if sm.reporter != nil {
		stats.ReportsSent, stats.ReportsFailed = sm.reporter.Stats()
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

// GetIPTablesInfo returns the firewall (ipset) state: the IPs currently
// banned in the set and the chain holding the match-set DROP rule.
func (sm *SecurityManager) GetIPTablesInfo() (map[string]any, error) {
	blocked, err := sm.ipset.ListBlockedIPs()
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"chain":      sm.cfg.IPTablesChain,
		"ipset":      sm.cfg.IPSetName,
		"blockedIps": blocked,
		"count":      len(blocked),
	}, nil
}

// SecurityConfigView returns a read-only view of the in-effect config used
// by routes. Returns (enabled, autoBlockEnabled).
func (sm *SecurityManager) SecurityConfigView() (bool, bool) {
	return sm.cfg.Enabled, sm.cfg.AutoBlockEnabled
}

// initChanDaemonReporter builds the chanDaemon (D39) reporter when reporting is
// enabled. Reporting is tied to actually enforcing bans: it is skipped unless
// auto-block is on (otherwise we would report bans we did not enact) and is
// suppressed in dry-run (which must produce no external side effects). A failure
// to parse the timeout falls back to 5s.
func (sm *SecurityManager) initChanDaemonReporter(cfg *AppConfig, logger *Logger) {
	cd := cfg.Security.ChanDaemon

	if !cd.Enabled || cd.ReportURL == "" || !sm.cfg.AutoBlockEnabled || sm.cfg.DryRun {
		return
	}

	timeout := parseDurationOr(cd.ReportTimeout, 5*time.Second)
	sm.reporter = NewChanDaemonReporter(cd.ReportURL, cd.BlockerURL, cd.ServiceName, timeout)

	logger.Info("chanDaemon ban reporting enabled: %s (self %q, service %q)",
		cd.ReportURL, cd.BlockerURL, cd.ServiceName)

	if cd.BlockerURL == "" {
		logger.Info("chanDaemon blocker_url is empty: bans are reported, but chanDaemon cannot push unbans back to this node")
	}
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

	// IPs we successfully accepted into the blacklist; firewall work happens
	// outside the lock to avoid blocking other security operations on fork+exec.
	toBlock := make([]blockTarget, 0, len(batch))

	sm.mu.Lock()
	for _, req := range batch {
		addr, err := netip.ParseAddr(req.IP)
		if err != nil {
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

		if sm.ipInTrustedNetwork(addr) {
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
			toBlock = append(toBlock, blockTarget{ip: req.IP, reason: req.Reason, fromUser: req.FromUser, permanent: req.Permanent})
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
func (sm *SecurityManager) ipInTrustedNetwork(addr netip.Addr) bool {
	for _, prefix := range sm.trustedNetworks {
		if prefix.Contains(addr) {
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
		_, parseErr := netip.ParseAddr(req.IP)
		if parseErr != nil {
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

	for _, ip := range toUnblock {
		err := sm.ipset.UnblockIP(ip)
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

		addr, err := netip.ParseAddr(req.IP)
		if err != nil || sm.ipInTrustedNetwork(addr) {
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
				IP:       req.IP,
				Reason:   fmt.Sprintf("Exceeded max failed registrations (%d)", maxAttempts),
				FromUser: reportableUser(req.UserID),
			})
		}

		if _, untrusted := sm.untrustedPatterns[req.Domain]; untrusted && req.Domain != "" {
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:       req.IP,
				Reason:   fmt.Sprintf("Failed registration from untrusted domain %q", req.Domain),
				FromUser: reportableUser(req.UserID),
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

		addr, err := netip.ParseAddr(req.IP)
		if err != nil || sm.ipInTrustedNetwork(addr) {
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
				IP:       req.IP,
				Reason:   fmt.Sprintf("Exceeded max wrong call states (%d)", maxStates),
				FromUser: reportableUser(req.UserID),
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

	addr, err := netip.ParseAddr(ipStr)
	if err == nil && sm.ipInTrustedNetwork(addr) {
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

	// Remove expired blacklist entries from the ipset (outside lock). The
	// kernel also expires entries on its own via their timeout; this is a
	// belt-and-suspenders cleanup for entries the in-memory map dropped.
	if autoBlock {
		for _, ip := range blacklistRemoved {
			err := sm.ipset.UnblockIP(ip)
			if err != nil {
				logger.Error("Failed to unblock expired IP %s: %v", ip, err)
			}
		}
	}

	logger.Info("Cleanup: removed %d whitelist, %d blacklist, %d failed, %d wrong-state",
		len(whitelistRemoved), len(blacklistRemoved), failedRemoved, wrongRemoved)
}

// ----------------------------------------------------------------------
// firewall (ipset) helpers
// ----------------------------------------------------------------------

// blockTarget is one accepted blacklist entry awaiting a kernel ipset add.
// fromUser carries the best-effort SIP From-user through to the chanDaemon
// report (it never reaches the kernel ipset itself).
type blockTarget struct {
	ip        string
	reason    string
	fromUser  string
	permanent bool
}

// batchBlockIPs adds many IPs to the ipset. Permanent bans use a zero timeout
// (no in-kernel expiry); the rest use the configured block duration. Failures
// are logged and do not stop the batch.
func (sm *SecurityManager) batchBlockIPs(targets []blockTarget) {
	if len(targets) == 0 {
		return
	}

	logger := GetLogger()

	for _, tgt := range targets {
		ttl := sm.cfg.BlockDuration
		if tgt.permanent {
			ttl = 0
		}

		err := sm.ipset.BlockIP(tgt.ip, tgt.reason, ttl)
		if err != nil {
			logger.Error("Failed to block IP %s: %v", tgt.ip, err)

			continue
		}

		// Mirror the enacted ban to chanDaemon (best-effort, async). A
		// permanent ban (ttl 0) lets chanDaemon apply its sticky floor.
		if sm.reporter != nil {
			sm.reporter.Report(tgt.ip, tgt.fromUser, tgt.reason, ttl)
		}
	}
}
