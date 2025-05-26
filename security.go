package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
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

	// Channel-based operations
	blacklistQueue  chan BlacklistRequest
	whitelistQueue  chan WhitelistRequest
	failedQueue     chan FailedAttemptRequest
	wrongStateQueue chan WrongStateRequest

	// Batch processing
	batchSize     int
	batchInterval time.Duration

	// Dynamic channel sizing
	channelResizers map[string]*DynamicChannelManager
	channelMutex    sync.RWMutex

	// Shutdown mechanism
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// DynamicChannelManager manages dynamic sizing for a specific channel
type DynamicChannelManager struct {
	name           string
	baseSize       int
	currentSize    int
	maxSize        int
	minSize        int
	lastResize     time.Time
	resizeInterval time.Duration
	highLoadCount  int
	lowLoadCount   int
	totalProcessed int64
	totalDropped   int64
	mutex          sync.RWMutex
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

// Request types for channel operations
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

var (
	securityManager *SecurityManager
	secManagerOnce  sync.Once
)

// NewDynamicChannelManager creates a new dynamic channel manager
func NewDynamicChannelManager(name string, baseSize, minSize, maxSize int) *DynamicChannelManager {
	return &DynamicChannelManager{
		name:           name,
		baseSize:       baseSize,
		currentSize:    baseSize,
		minSize:        minSize,
		maxSize:        maxSize,
		lastResize:     time.Now(),
		resizeInterval: 30 * time.Second,
	}
}

// ShouldResize determines if a channel should be resized based on current load
func (dcm *DynamicChannelManager) ShouldResize(currentLength, currentCapacity int) (bool, int) {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	// Don't resize too frequently
	if time.Since(dcm.lastResize) < dcm.resizeInterval {
		return false, dcm.currentSize
	}

	utilization := float64(currentLength) / float64(currentCapacity)

	// High load: > 80% utilization
	if utilization > 0.8 {
		dcm.highLoadCount++
		dcm.lowLoadCount = 0

		if dcm.highLoadCount >= 3 {
			newSize := dcm.currentSize * 2
			if newSize > dcm.maxSize {
				newSize = dcm.maxSize
			}
			if newSize != dcm.currentSize {
				dcm.currentSize = newSize
				dcm.lastResize = time.Now()
				dcm.highLoadCount = 0
				return true, newSize
			}
		}
	} else if utilization < 0.2 { // Low load: < 20% utilization
		dcm.lowLoadCount++
		dcm.highLoadCount = 0

		if dcm.lowLoadCount >= 5 {
			newSize := dcm.currentSize / 2
			if newSize < dcm.minSize {
				newSize = dcm.minSize
			}
			if newSize != dcm.currentSize {
				dcm.currentSize = newSize
				dcm.lastResize = time.Now()
				dcm.lowLoadCount = 0
				return true, newSize
			}
		}
	} else {
		// Normal load, reset counters
		dcm.highLoadCount = 0
		dcm.lowLoadCount = 0
	}

	return false, dcm.currentSize
}

// UpdateStats updates the channel statistics
func (dcm *DynamicChannelManager) UpdateStats(processed, dropped int64) {
	atomic.AddInt64(&dcm.totalProcessed, processed)
	atomic.AddInt64(&dcm.totalDropped, dropped)
}

// GetStats returns channel statistics
func (dcm *DynamicChannelManager) GetStats() map[string]interface{} {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	return map[string]interface{}{
		"name":            dcm.name,
		"current_size":    dcm.currentSize,
		"base_size":       dcm.baseSize,
		"min_size":        dcm.minSize,
		"max_size":        dcm.maxSize,
		"high_load_count": dcm.highLoadCount,
		"low_load_count":  dcm.lowLoadCount,
		"last_resize":     dcm.lastResize.Format(time.RFC3339),
		"total_processed": atomic.LoadInt64(&dcm.totalProcessed),
		"total_dropped":   atomic.LoadInt64(&dcm.totalDropped),
	}
}

// InitSecurityManager initializes the security manager
func InitSecurityManager() error {
	var err error
	secManagerOnce.Do(func() {
		logger := GetLogger()
		config := GetConfig()

		// Initialize the security configuration
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

		// Create context for shutdown
		ctx, cancel := context.WithCancel(context.Background())

		// Initialize channel resizers
		channelResizers := make(map[string]*DynamicChannelManager)
		channelResizers["blacklist"] = NewDynamicChannelManager("blacklist", 1000, 500, 5000)
		channelResizers["whitelist"] = NewDynamicChannelManager("whitelist", 1000, 500, 5000)
		channelResizers["failed"] = NewDynamicChannelManager("failed", 5000, 1000, 20000)
		channelResizers["wrongstate"] = NewDynamicChannelManager("wrongstate", 5000, 1000, 20000)

		// Initialize the security manager with dynamic channel sizes
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
			// Channel initialization with dynamic sizes
			blacklistQueue:  make(chan BlacklistRequest, channelResizers["blacklist"].currentSize),
			whitelistQueue:  make(chan WhitelistRequest, channelResizers["whitelist"].currentSize),
			failedQueue:     make(chan FailedAttemptRequest, channelResizers["failed"].currentSize),
			wrongStateQueue: make(chan WrongStateRequest, channelResizers["wrongstate"].currentSize),
			batchSize:       10,
			batchInterval:   100 * time.Millisecond,
			channelResizers: channelResizers,
			ctx:             ctx,
			cancel:          cancel,
		}

		logger.Info("Security manager initialized with dynamic channel sizing")
		logger.Info("Initial channel sizes - Blacklist: %d, Whitelist: %d, Failed: %d, WrongState: %d",
			channelResizers["blacklist"].currentSize,
			channelResizers["whitelist"].currentSize,
			channelResizers["failed"].currentSize,
			channelResizers["wrongstate"].currentSize)
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

		// Start worker goroutines
		securityManager.wg.Add(4)
		go securityManager.processBlacklistQueue()
		go securityManager.processWhitelistQueue()
		go securityManager.processFailedAttemptQueue()
		go securityManager.processWrongStateQueue()

		// Start channel monitor
		securityManager.wg.Add(1)
		go securityManager.monitorChannelSizes()

		// Start cleanup routine
		logger.Info("Starting periodic cleanup routine")
		securityManager.wg.Add(1)
		go securityManager.startCleanupRoutine()
	})

	return err
}

// monitorChannelSizes monitors and adjusts channel sizes based on load
func (sm *SecurityManager) monitorChannelSizes() {
	defer sm.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Channel size monitor shutting down")
			return

		case <-ticker.C:
			// Check each channel and resize if needed
			sm.checkAndResizeChannel("blacklist", sm.blacklistQueue)
			sm.checkAndResizeChannel("whitelist", sm.whitelistQueue)
			sm.checkAndResizeChannel("failed", sm.failedQueue)
			sm.checkAndResizeChannel("wrongstate", sm.wrongStateQueue)
		}
	}
}

// checkAndResizeChannel checks a specific channel and resizes if needed
func (sm *SecurityManager) checkAndResizeChannel(name string, currentChannel interface{}) {
	logger := GetLogger()

	sm.channelMutex.RLock()
	resizer, exists := sm.channelResizers[name]
	sm.channelMutex.RUnlock()

	if !exists {
		return
	}

	var length, capacity int
	var needsResize bool
	var newSize int

	// Get channel metrics based on type
	switch ch := currentChannel.(type) {
	case chan BlacklistRequest:
		length = len(ch)
		capacity = cap(ch)
		needsResize, newSize = resizer.ShouldResize(length, capacity)
		if needsResize {
			sm.resizeBlacklistChannel(newSize)
		}
	case chan WhitelistRequest:
		length = len(ch)
		capacity = cap(ch)
		needsResize, newSize = resizer.ShouldResize(length, capacity)
		if needsResize {
			sm.resizeWhitelistChannel(newSize)
		}
	case chan FailedAttemptRequest:
		length = len(ch)
		capacity = cap(ch)
		needsResize, newSize = resizer.ShouldResize(length, capacity)
		if needsResize {
			sm.resizeFailedChannel(newSize)
		}
	case chan WrongStateRequest:
		length = len(ch)
		capacity = cap(ch)
		needsResize, newSize = resizer.ShouldResize(length, capacity)
		if needsResize {
			sm.resizeWrongStateChannel(newSize)
		}
	}

	if needsResize {
		logger.Info("Resized %s channel from %d to %d (was %d/%d full)",
			name, capacity, newSize, length, capacity)
	}
}

// Channel resize methods
func (sm *SecurityManager) resizeBlacklistChannel(newSize int) {
	newChan := make(chan BlacklistRequest, newSize)
	oldChan := sm.blacklistQueue
	sm.blacklistQueue = newChan

	// Transfer existing items
	go func() {
		for req := range oldChan {
			select {
			case newChan <- req:
			default:
				// New channel full, send error response
				if req.Response != nil {
					req.Response <- fmt.Errorf("channel resize: queue full")
				}
				sm.channelResizers["blacklist"].UpdateStats(0, 1)
			}
		}
	}()
}

func (sm *SecurityManager) resizeWhitelistChannel(newSize int) {
	newChan := make(chan WhitelistRequest, newSize)
	oldChan := sm.whitelistQueue
	sm.whitelistQueue = newChan

	go func() {
		for req := range oldChan {
			select {
			case newChan <- req:
			default:
				if req.Response != nil {
					req.Response <- fmt.Errorf("channel resize: queue full")
				}
				sm.channelResizers["whitelist"].UpdateStats(0, 1)
			}
		}
	}()
}

func (sm *SecurityManager) resizeFailedChannel(newSize int) {
	newChan := make(chan FailedAttemptRequest, newSize)
	oldChan := sm.failedQueue
	sm.failedQueue = newChan

	go func() {
		for req := range oldChan {
			select {
			case newChan <- req:
			default:
				sm.channelResizers["failed"].UpdateStats(0, 1)
			}
		}
	}()
}

func (sm *SecurityManager) resizeWrongStateChannel(newSize int) {
	newChan := make(chan WrongStateRequest, newSize)
	oldChan := sm.wrongStateQueue
	sm.wrongStateQueue = newChan

	go func() {
		for req := range oldChan {
			select {
			case newChan <- req:
			default:
				sm.channelResizers["wrongstate"].UpdateStats(0, 1)
			}
		}
	}()
}

// Shutdown gracefully shuts down the security manager
func (sm *SecurityManager) Shutdown() {
	logger := GetLogger()
	logger.Info("Shutting down security manager...")

	// Cancel the context to signal shutdown
	sm.cancel()

	// Close all channels
	close(sm.blacklistQueue)
	close(sm.whitelistQueue)
	close(sm.failedQueue)
	close(sm.wrongStateQueue)

	// Wait for all goroutines to finish
	sm.wg.Wait()

	logger.Info("Security manager shutdown complete")
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

// processBlacklistQueue processes blacklist requests in batches
func (sm *SecurityManager) processBlacklistQueue() {
	defer sm.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(sm.batchInterval)
	defer ticker.Stop()

	batch := make([]BlacklistRequest, 0, sm.batchSize)

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Blacklist queue processor shutting down")
			return

		case req, ok := <-sm.blacklistQueue:
			if !ok {
				// Channel closed
				return
			}
			batch = append(batch, req)

			// Process batch if it's full
			if len(batch) >= sm.batchSize {
				sm.processBatchBlacklist(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Process any pending items
			if len(batch) > 0 {
				sm.processBatchBlacklist(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchBlacklist processes a batch of blacklist requests
func (sm *SecurityManager) processBatchBlacklist(batch []BlacklistRequest) {
	logger := GetLogger()

	// Update channel statistics
	sm.channelResizers["blacklist"].UpdateStats(int64(len(batch)), 0)

	// Batch iptables commands
	var iptablesCommands []string

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for _, req := range batch {
		// Validate IP
		if net.ParseIP(req.IP) == nil {
			if req.Response != nil {
				req.Response <- fmt.Errorf("invalid IP address: %s", req.IP)
			}
			continue
		}

		// Check if whitelisted
		if _, isWhitelisted := sm.whitelist[req.IP]; isWhitelisted {
			if req.Response != nil {
				req.Response <- fmt.Errorf("cannot blacklist whitelisted IP: %s", req.IP)
			}
			continue
		}

		// Check if IP is in a trusted network
		ip := net.ParseIP(req.IP)
		inTrustedNetwork := false
		for _, network := range sm.whitelistNetworks {
			if network.Contains(ip) {
				inTrustedNetwork = true
				break
			}
		}
		if inTrustedNetwork {
			if req.Response != nil {
				req.Response <- fmt.Errorf("cannot blacklist IP in trusted network: %s", req.IP)
			}
			continue
		}

		// Add to blacklist
		now := time.Now()
		blockDuration, _ := time.ParseDuration(sm.securityConfig.BlockDuration)
		if blockDuration == 0 {
			blockDuration = time.Hour
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

		// Queue iptables command
		if sm.securityConfig.AutoBlockEnabled {
			iptablesCommands = append(iptablesCommands, req.IP)
		}

		logger.Info("Added IP %s to blacklist: %s", req.IP, req.Reason)

		// Cache the entry
		cache := GetCacheManager()
		if cache.enabled {
			key := fmt.Sprintf("blacklist:%s", req.IP)
			data, err := json.Marshal(entry)
			if err == nil {
				cache.CacheSecurityItemAsync(key, data)
			}
		}

		if req.Response != nil {
			req.Response <- nil
		}
	}

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.ActiveBlacklistEntries = len(sm.blacklist)
	sm.statistics.BlockedAttempts += len(batch)
	sm.statsMutex.Unlock()

	// Execute batch iptables commands
	if len(iptablesCommands) > 0 && sm.securityConfig.AutoBlockEnabled {
		sm.batchBlockIPs(iptablesCommands)
	}
}

// batchBlockIPs blocks multiple IPs using iptables in a single operation
func (sm *SecurityManager) batchBlockIPs(ips []string) {
	logger := GetLogger()

	// Create a script for batch processing
	var commands []string
	for _, ip := range ips {
		// Check if already blocked
		checkCmd := fmt.Sprintf("iptables -C %s -s %s -j DROP 2>/dev/null || iptables -A %s -s %s -j DROP",
			sm.securityConfig.IPTablesChain, ip, sm.securityConfig.IPTablesChain, ip)
		commands = append(commands, checkCmd)
	}

	// Execute all commands in one shell invocation
	script := strings.Join(commands, " && ")
	cmd := exec.Command("sh", "-c", script)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Batch iptables error: %v, output: %s", err, string(output))
	} else {
		logger.Info("Successfully blocked %d IPs in batch", len(ips))
	}
}

// processWhitelistQueue processes whitelist requests
func (sm *SecurityManager) processWhitelistQueue() {
	defer sm.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(sm.batchInterval)
	defer ticker.Stop()

	batch := make([]WhitelistRequest, 0, sm.batchSize)

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Whitelist queue processor shutting down")
			return

		case req, ok := <-sm.whitelistQueue:
			if !ok {
				return
			}
			batch = append(batch, req)

			if len(batch) >= sm.batchSize {
				sm.processBatchWhitelist(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sm.processBatchWhitelist(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchWhitelist processes a batch of whitelist requests
func (sm *SecurityManager) processBatchWhitelist(batch []WhitelistRequest) {
	logger := GetLogger()

	// Update channel statistics
	sm.channelResizers["whitelist"].UpdateStats(int64(len(batch)), 0)

	whitelistTTL, _ := time.ParseDuration(sm.securityConfig.WhitelistTTL)
	if whitelistTTL == 0 {
		whitelistTTL = 24 * time.Hour
	}
	now := time.Now()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for _, req := range batch {
		// Validate IP
		if net.ParseIP(req.IP) == nil {
			if req.Response != nil {
				req.Response <- fmt.Errorf("invalid IP address: %s", req.IP)
			}
			continue
		}

		entry := WhitelistEntry{
			IP:        req.IP,
			AddedAt:   now,
			ExpiresAt: now.Add(whitelistTTL),
			LastSeen:  now,
			UserID:    req.UserID,
			Domain:    req.Domain,
			Permanent: req.Permanent,
		}

		sm.whitelist[req.IP] = entry

		// Remove from blacklist if present
		if _, exists := sm.blacklist[req.IP]; exists {
			delete(sm.blacklist, req.IP)
			// Unblock from iptables
			if sm.securityConfig.AutoBlockEnabled {
				go unblockIPWithIptables(req.IP, sm.securityConfig.IPTablesChain)
			}
		}

		logger.Info("Added IP %s to whitelist for user %s@%s", req.IP, req.UserID, req.Domain)

		// Cache the entry
		cache := GetCacheManager()
		if cache.enabled {
			key := fmt.Sprintf("whitelist:%s", req.IP)
			data, err := json.Marshal(entry)
			if err == nil {
				cache.CacheSecurityItemAsync(key, data)
			}
		}

		if req.Response != nil {
			req.Response <- nil
		}
	}

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.ActiveWhitelistEntries = len(sm.whitelist)
	sm.statsMutex.Unlock()
}

// processFailedAttemptQueue processes failed attempt tracking
func (sm *SecurityManager) processFailedAttemptQueue() {
	defer sm.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]FailedAttemptRequest, 0, 50)

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Failed attempt queue processor shutting down")
			return

		case req, ok := <-sm.failedQueue:
			if !ok {
				return
			}
			batch = append(batch, req)

			if len(batch) >= 50 {
				sm.processBatchFailedAttempts(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sm.processBatchFailedAttempts(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchFailedAttempts processes a batch of failed attempts
func (sm *SecurityManager) processBatchFailedAttempts(batch []FailedAttemptRequest) {
	logger := GetLogger()

	// Update channel statistics
	sm.channelResizers["failed"].UpdateStats(int64(len(batch)), 0)

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Track IPs that need to be blacklisted
	var toBlacklist []BlacklistRequest

	for _, req := range batch {
		// Check if whitelisted
		if _, isWhitelisted := sm.whitelist[req.IP]; isWhitelisted {
			continue
		}

		// Check if IP is in a trusted network
		ip := net.ParseIP(req.IP)
		inTrustedNetwork := false
		for _, network := range sm.whitelistNetworks {
			if network.Contains(ip) {
				inTrustedNetwork = true
				break
			}
		}
		if inTrustedNetwork {
			continue
		}

		// Update failed attempts
		attempt, exists := sm.failedAttempts[req.IP]
		if !exists {
			attempt = FailedAttempt{
				Count:        1,
				FirstAttempt: time.Now(),
				LastAttempt:  time.Now(),
				UserIDs:      []string{req.UserID},
				Domains:      []string{req.Domain},
			}
		} else {
			attempt.Count++
			attempt.LastAttempt = time.Now()

			// Add unique user IDs and domains
			if req.UserID != "" && req.UserID != "unknown" {
				found := false
				for _, id := range attempt.UserIDs {
					if id == req.UserID {
						found = true
						break
					}
				}
				if !found {
					attempt.UserIDs = append(attempt.UserIDs, req.UserID)
				}
			}

			if req.Domain != "" {
				found := false
				for _, dom := range attempt.Domains {
					if dom == req.Domain {
						found = true
						break
					}
				}
				if !found {
					attempt.Domains = append(attempt.Domains, req.Domain)
				}
			}
		}

		sm.failedAttempts[req.IP] = attempt

		// Check if should be blacklisted
		if sm.securityConfig.AutoBlockEnabled && attempt.Count >= sm.securityConfig.MaxFailedAttempts {
			reason := fmt.Sprintf("Exceeded max failed registrations (%d)", sm.securityConfig.MaxFailedAttempts)
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:        req.IP,
				Reason:    reason,
				Permanent: false,
			})
		}

		// Check untrusted domain
		if sm.IsUntrustedDomain(req.Domain) {
			reason := fmt.Sprintf("Failed registration attempt from untrusted domain '%s'", req.Domain)
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:        req.IP,
				Reason:    reason,
				Permanent: false,
			})
		}
	}

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.FailedRegistrations += len(batch)
	sm.statistics.LastFailedTime = time.Now()
	sm.statsMutex.Unlock()

	// Queue blacklist requests
	for _, req := range toBlacklist {
		select {
		case sm.blacklistQueue <- req:
			logger.Info("Queued IP %s for blacklisting: %s", req.IP, req.Reason)
		default:
			// Queue is full, log error
			logger.Error("Blacklist queue full, could not queue IP %s", req.IP)
			sm.channelResizers["blacklist"].UpdateStats(0, 1)
		}
	}
}

// processWrongStateQueue processes wrong call state events
func (sm *SecurityManager) processWrongStateQueue() {
	defer sm.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]WrongStateRequest, 0, 50)

	for {
		select {
		case <-sm.ctx.Done():
			logger.Info("Wrong state queue processor shutting down")
			return

		case req, ok := <-sm.wrongStateQueue:
			if !ok {
				return
			}
			batch = append(batch, req)

			if len(batch) >= 50 {
				sm.processBatchWrongStates(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sm.processBatchWrongStates(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchWrongStates processes a batch of wrong call states
func (sm *SecurityManager) processBatchWrongStates(batch []WrongStateRequest) {
	logger := GetLogger()

	// Update channel statistics
	sm.channelResizers["wrongstate"].UpdateStats(int64(len(batch)), 0)

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	var toBlacklist []BlacklistRequest

	for _, req := range batch {
		// Check if whitelisted
		if _, isWhitelisted := sm.whitelist[req.IP]; isWhitelisted {
			continue
		}

		// Check if IP is in a trusted network
		ip := net.ParseIP(req.IP)
		inTrustedNetwork := false
		for _, network := range sm.whitelistNetworks {
			if network.Contains(ip) {
				inTrustedNetwork = true
				break
			}
		}
		if inTrustedNetwork {
			continue
		}

		// Update wrong call state count
		attempt, exists := sm.wrongCallStates[req.IP]
		if !exists {
			attempt = WrongCallStateEntry{
				Count:        1,
				FirstAttempt: time.Now(),
				LastAttempt:  time.Now(),
				UserIDs:      []string{req.UserID},
			}
		} else {
			attempt.Count++
			attempt.LastAttempt = time.Now()

			// Add unique user ID
			if req.UserID != "" && req.UserID != "unknown" {
				found := false
				for _, id := range attempt.UserIDs {
					if id == req.UserID {
						found = true
						break
					}
				}
				if !found {
					attempt.UserIDs = append(attempt.UserIDs, req.UserID)
				}
			}
		}

		sm.wrongCallStates[req.IP] = attempt

		// Check if should be blacklisted
		if sm.securityConfig.AutoBlockEnabled && attempt.Count >= sm.securityConfig.MaxWrongCallStates {
			reason := fmt.Sprintf("Exceeded max wrong call states (%d)", sm.securityConfig.MaxWrongCallStates)
			toBlacklist = append(toBlacklist, BlacklistRequest{
				IP:        req.IP,
				Reason:    reason,
				Permanent: false,
			})
		}
	}

	// Update statistics
	sm.statsMutex.Lock()
	sm.statistics.WrongCallStates += len(batch)
	sm.statistics.LastWrongCallStateTime = time.Now()
	sm.statsMutex.Unlock()

	// Queue blacklist requests
	for _, req := range toBlacklist {
		select {
		case sm.blacklistQueue <- req:
			logger.Info("Queued IP %s for blacklisting: %s", req.IP, req.Reason)
		default:
			logger.Error("Blacklist queue full, could not queue IP %s", req.IP)
			sm.channelResizers["blacklist"].UpdateStats(0, 1)
		}
	}
}

// AddToBlacklistAsync adds an IP to the blacklist asynchronously
func (sm *SecurityManager) AddToBlacklistAsync(ipAddress, reason string, permanent bool) {
	select {
	case sm.blacklistQueue <- BlacklistRequest{
		IP:        ipAddress,
		Reason:    reason,
		Permanent: permanent,
		Response:  nil, // Fire and forget
	}:
		// Queued successfully
	case <-time.After(100 * time.Millisecond):
		// Queue is full, fall back to synchronous
		sm.AddToBlacklist(ipAddress, reason, permanent)
	}
}

// ProcessFailedRegistration processes a failed registration event asynchronously
func (sm *SecurityManager) ProcessFailedRegistration(ipAddress, userId, domain string) {
	select {
	case sm.failedQueue <- FailedAttemptRequest{
		IP:     ipAddress,
		UserID: userId,
		Domain: domain,
	}:
		// Queued successfully
	case <-time.After(10 * time.Millisecond):
		// Queue is full, drop the event
		logger := GetLogger()
		logger.Error("Failed attempt queue full, dropping event for IP %s", ipAddress)
		sm.channelResizers["failed"].UpdateStats(0, 1)
	}
}

// ProcessWrongCallState processes a wrong call state event asynchronously
func (sm *SecurityManager) ProcessWrongCallState(ipAddress, userId string) {
	select {
	case sm.wrongStateQueue <- WrongStateRequest{
		IP:     ipAddress,
		UserID: userId,
	}:
		// Queued successfully
	case <-time.After(10 * time.Millisecond):
		// Queue is full, drop the event
		logger := GetLogger()
		logger.Error("Wrong state queue full, dropping event for IP %s", ipAddress)
		sm.channelResizers["wrongstate"].UpdateStats(0, 1)
	}
}

// Keep the original synchronous methods for compatibility
func (sm *SecurityManager) AddToBlacklist(ipAddress, reason string, permanent bool) error {
	respChan := make(chan error, 1)

	select {
	case sm.blacklistQueue <- BlacklistRequest{
		IP:        ipAddress,
		Reason:    reason,
		Permanent: permanent,
		Response:  respChan,
	}:
		return <-respChan
	case <-time.After(1 * time.Second):
		return fmt.Errorf("timeout queueing blacklist request")
	}
}

func (sm *SecurityManager) AddToWhitelist(ipAddress, userId, domain string, permanent bool) error {
	respChan := make(chan error, 1)

	select {
	case sm.whitelistQueue <- WhitelistRequest{
		IP:        ipAddress,
		UserID:    userId,
		Domain:    domain,
		Permanent: permanent,
		Response:  respChan,
	}:
		return <-respChan
	case <-time.After(1 * time.Second):
		return fmt.Errorf("timeout queueing whitelist request")
	}
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
		cache.DeleteSecurityItemAsync(key)
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
		cache.DeleteSecurityItemAsync(key)
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
					cache.DeleteSecurityItemAsync(key)
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
					cache.DeleteSecurityItemAsync(key)
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
	defer sm.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			GetLogger().Info("Cleanup routine shutting down")
			return
		case <-ticker.C:
			GetLogger().Info("Running scheduled cleanup of expired entries")
			sm.cleanupExpiredEntries()
		}
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

// GetChannelStats returns dynamic channel statistics
func (sm *SecurityManager) GetChannelStats() map[string]interface{} {
	sm.channelMutex.RLock()
	defer sm.channelMutex.RUnlock()

	stats := make(map[string]interface{})
	for name, resizer := range sm.channelResizers {
		stats[name] = resizer.GetStats()
	}

	// Add current queue lengths
	stats["current_queue_lengths"] = map[string]int{
		"blacklist":  len(sm.blacklistQueue),
		"whitelist":  len(sm.whitelistQueue),
		"failed":     len(sm.failedQueue),
		"wrongstate": len(sm.wrongStateQueue),
	}

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

// UpdateRegistrationStats updates statistics for a successful registration
func (sm *SecurityManager) UpdateRegistrationStats(ipAddress, userId, domain string) {
	sm.statsMutex.Lock()
	defer sm.statsMutex.Unlock()

	sm.statistics.TotalRegistrations++
	sm.statistics.LastRegistrationTime = time.Now()
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
	checkCmd := exec.Command("iptables", "-C", chain, "-s", ip, "-j", "DROP")
	if checkCmd.Run() == nil {
		logger.Info("IP %s is already blocked in chain %s", ip, chain)
		return nil
	}

	logger.Info("Adding iptables rule to block IP %s in chain %s", ip, chain)
	cmd := exec.Command("iptables", "-A", chain, "-s", ip, "-j", "DROP")
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
	cmd := exec.Command("iptables", "-D", chain, "-s", ip, "-j", "DROP")
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
