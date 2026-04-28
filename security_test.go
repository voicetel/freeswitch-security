package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestSecurityManager builds an isolated SecurityManager for tests. It
// bypasses the package-level singleton and disables AutoBlock so tests never
// invoke iptables on the host.
func newTestSecurityManager(tb testing.TB) *SecurityManager {
	tb.Helper()
	// Suppress noisy log output during tests; raise via -v if needed.
	GetLogger().SetLogLevel(LogLevelError)

	trusted := make([]*net.IPNet, 0, 1)
	if _, n, err := net.ParseCIDR("10.0.0.0/8"); err == nil {
		trusted = append(trusted, n)
	}

	ctx, cancel := context.WithCancel(tb.Context())
	sm := &SecurityManager{
		whitelist:       make(map[string]WhitelistEntry),
		blacklist:       make(map[string]BlacklistEntry),
		failedAttempts:  make(map[string]FailedAttempt),
		wrongStates:     make(map[string]WrongCallStateEntry),
		trustedNetworks: trusted,
		untrustedPatterns: map[string]struct{}{
			"evil.example": {},
		},
		cfg: effectiveSecurityConfig{
			Enabled:                true,
			AutoBlockEnabled:       false,
			WhitelistEnabled:       true,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          "TEST",
			MaxFailedAttempts:      3,
			FailedWindow:           10 * time.Minute,
			BlockDuration:          time.Hour,
			WhitelistTTL:           24 * time.Hour,
			MaxWrongCallStates:     3,
			WrongStateWindow:       10 * time.Minute,
		},
		blacklistQueue:  make(chan BlacklistRequest, blacklistQueueSize),
		whitelistQueue:  make(chan WhitelistRequest, whitelistQueueSize),
		failedQueue:     make(chan FailedAttemptRequest, failedQueueSize),
		wrongStateQueue: make(chan WrongStateRequest, wrongStateQueueSize),
		ctx:             ctx,
		cancel:          cancel,
	}

	sm.wg.Add(5)
	go sm.processBlacklistQueue()
	go sm.processWhitelistQueue()
	go sm.processFailedAttemptQueue()
	go sm.processWrongStateQueue()
	go sm.startCleanupRoutine()

	tb.Cleanup(func() { sm.Shutdown() })

	return sm
}

func TestParseDurationOr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in       string
		fallback time.Duration
		want     time.Duration
	}{
		{"5s", time.Hour, 5 * time.Second},
		{"", time.Hour, time.Hour},
		{"bogus", time.Minute, time.Minute},
		{"-1s", time.Minute, time.Minute},
		{"0s", time.Minute, time.Minute},
	}
	for _, c := range cases {
		if got := parseDurationOr(c.in, c.fallback); got != c.want {
			t.Errorf("parseDurationOr(%q, %v) = %v, want %v", c.in, c.fallback, got, c.want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		add  string
		want []string
	}{
		{"empty add to nil", nil, "alice", []string{"alice"}},
		{"skip empty", []string{"alice"}, "", []string{"alice"}},
		{"skip unknown", []string{"alice"}, "unknown", []string{"alice"}},
		{"dedupe", []string{"alice"}, "alice", []string{"alice"}},
		{"append distinct", []string{"alice"}, "bob", []string{"alice", "bob"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := appendUnique(tc.in, tc.add)
			if !sliceEqual(got, tc.want) {
				t.Errorf("appendUnique(%v, %q) = %v, want %v", tc.in, tc.add, got, tc.want)
			}
		})
	}
}

func sliceEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

func TestIsIPWhitelisted_TrustedNetwork(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if !sm.IsIPWhitelisted("10.1.2.3") {
		t.Error("IP in trusted network 10.0.0.0/8 should be whitelisted")
	}

	if sm.IsIPWhitelisted("8.8.8.8") {
		t.Error("IP outside trusted network should not be whitelisted")
	}

	if sm.IsIPWhitelisted("not-an-ip") {
		t.Error("invalid IP must not be whitelisted")
	}
}

func TestAddToWhitelist_RoundTrip(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToWhitelist("203.0.113.7", "alice", "example.com", false); err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if !sm.IsIPWhitelisted("203.0.113.7") {
		t.Error("expected IP to be whitelisted after AddToWhitelist")
	}

	entry, ok := sm.GetWhitelistEntry("203.0.113.7")
	if !ok {
		t.Fatal("GetWhitelistEntry returned not-found")
	}

	if entry.UserID != "alice" || entry.Domain != "example.com" {
		t.Errorf("unexpected entry: %+v", entry)
	}

	sm.RemoveFromWhitelist("203.0.113.7")

	if sm.IsIPWhitelisted("203.0.113.7") {
		t.Error("expected IP to no longer be whitelisted")
	}
}

func TestAddToWhitelist_InvalidIP(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	if err := sm.AddToWhitelist("not-an-ip", "u", "d", false); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestAddToBlacklist_RejectsTrustedIP(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	if err := sm.AddToBlacklist("10.1.2.3", "test", false); err == nil {
		t.Error("expected error blacklisting IP in trusted network")
	}

	if sm.IsIPBlacklisted("10.1.2.3") {
		t.Error("trusted IP must not be blacklisted")
	}
}

func TestAddToBlacklist_RejectsWhitelistedIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToWhitelist("203.0.113.10", "u", "d", false); err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if err := sm.AddToBlacklist("203.0.113.10", "test", false); err == nil {
		t.Error("expected error blacklisting whitelisted IP")
	}
}

func TestBlacklistEntry_Expiry(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// Inject expired blacklist entry directly to avoid waiting.
	sm.mu.Lock()
	sm.blacklist["203.0.113.20"] = BlacklistEntry{
		IP:        "203.0.113.20",
		AddedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.mu.Unlock()

	if sm.IsIPBlacklisted("203.0.113.20") {
		t.Error("expired blacklist entry must read as not-blacklisted")
	}

	if _, ok := sm.GetBlacklistEntry("203.0.113.20"); ok {
		t.Error("GetBlacklistEntry must skip expired entries")
	}
}

func TestProcessFailedRegistration_AutoBlacklists(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// Force AutoBlock so the failed-attempt processor will queue blacklist requests.
	sm.cfg.AutoBlockEnabled = true

	const ip = "203.0.113.30"
	for i := range sm.cfg.MaxFailedAttempts {
		sm.ProcessFailedRegistration(ip, fmt.Sprintf("u%d", i), "example.com")
	}

	// Wait until the IP is blacklisted (queues + batch worker have batched delays).
	if !waitFor(func() bool { return sm.IsIPBlacklisted(ip) }) {
		t.Errorf("expected %s to be blacklisted after %d failed attempts", ip, sm.cfg.MaxFailedAttempts)
	}
}

func TestProcessFailedRegistration_TrustedIPNotBlacklisted(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true

	for range 10 {
		sm.ProcessFailedRegistration("10.1.2.3", "u", "example.com")
	}

	// Drain time
	time.Sleep(300 * time.Millisecond)

	if sm.IsIPBlacklisted("10.1.2.3") {
		t.Error("trusted IP must not be blacklisted via failed attempts")
	}
}

func TestProcessWrongCallState_AutoBlacklists(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true

	const ip = "203.0.113.40"
	for i := range sm.cfg.MaxWrongCallStates {
		sm.ProcessWrongCallState(ip, fmt.Sprintf("u%d", i))
	}

	if !waitFor(func() bool { return sm.IsIPBlacklisted(ip) }) {
		t.Errorf("expected %s to be blacklisted after %d wrong call states", ip, sm.cfg.MaxWrongCallStates)
	}
}

func TestUntrustedPatterns(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if !sm.IsUntrustedDomain("evil.example") {
		t.Error("expected evil.example to match untrusted pattern set up by helper")
	}

	if sm.IsUntrustedDomain("ok.example") {
		t.Error("ok.example must not be marked untrusted")
	}

	if sm.IsUntrustedDomain("") {
		t.Error("empty domain must not be marked untrusted")
	}

	if err := sm.AddUntrustedNetwork("new.example"); err != nil {
		t.Fatalf("AddUntrustedNetwork: %v", err)
	}

	if !sm.IsUntrustedDomain("new.example") {
		t.Error("expected new.example to be flagged after add")
	}

	if err := sm.AddUntrustedNetwork("new.example"); err == nil {
		t.Error("expected duplicate-add error")
	}

	if err := sm.RemoveUntrustedNetwork("new.example"); err != nil {
		t.Fatalf("RemoveUntrustedNetwork: %v", err)
	}

	if sm.IsUntrustedDomain("new.example") {
		t.Error("expected new.example to be cleared after remove")
	}

	if err := sm.RemoveUntrustedNetwork("does-not-exist"); err == nil {
		t.Error("expected remove-missing error")
	}
}

// TestUntrustedPatterns_Concurrent verifies that reads and writes against the
// untrusted-patterns map are race-free. Run with -race to validate.
func TestUntrustedPatterns_Concurrent(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		i := 0
		for ctx.Err() == nil {
			pattern := fmt.Sprintf("dom%d.example", i%10)
			_ = sm.AddUntrustedNetwork(pattern)
			_ = sm.RemoveUntrustedNetwork(pattern)
			i++
		}
	}()
	go func() {
		defer wg.Done()

		for ctx.Err() == nil {
			_ = sm.IsUntrustedDomain("dom0.example")
		}
	}()
	wg.Wait()
}

func TestCleanupExpiredEntries(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	now := time.Now()

	sm.mu.Lock()
	sm.whitelist["203.0.113.50"] = WhitelistEntry{
		IP: "203.0.113.50", ExpiresAt: now.Add(-time.Hour),
	}
	sm.whitelist["203.0.113.51"] = WhitelistEntry{
		IP: "203.0.113.51", ExpiresAt: now.Add(time.Hour),
	}
	sm.blacklist["203.0.113.52"] = BlacklistEntry{
		IP: "203.0.113.52", ExpiresAt: now.Add(-time.Hour),
	}
	sm.blacklist["203.0.113.53"] = BlacklistEntry{
		IP: "203.0.113.53", ExpiresAt: now.Add(time.Hour),
	}
	sm.failedAttempts["203.0.113.54"] = FailedAttempt{
		LastAttempt: now.Add(-time.Hour),
	}
	sm.failedAttempts["203.0.113.55"] = FailedAttempt{
		LastAttempt: now,
	}
	sm.wrongStates["203.0.113.56"] = WrongCallStateEntry{
		LastAttempt: now.Add(-time.Hour),
	}
	sm.wrongStates["203.0.113.57"] = WrongCallStateEntry{
		LastAttempt: now,
	}
	sm.mu.Unlock()

	sm.cleanupExpiredEntries()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if _, ok := sm.whitelist["203.0.113.50"]; ok {
		t.Error("expired whitelist entry not cleaned")
	}

	if _, ok := sm.whitelist["203.0.113.51"]; !ok {
		t.Error("active whitelist entry was incorrectly cleaned")
	}

	if _, ok := sm.blacklist["203.0.113.52"]; ok {
		t.Error("expired blacklist entry not cleaned")
	}

	if _, ok := sm.blacklist["203.0.113.53"]; !ok {
		t.Error("active blacklist entry was incorrectly cleaned")
	}

	if _, ok := sm.failedAttempts["203.0.113.54"]; ok {
		t.Error("stale failed-attempt entry not cleaned")
	}

	if _, ok := sm.wrongStates["203.0.113.56"]; ok {
		t.Error("stale wrong-state entry not cleaned")
	}
}

func TestPermanentEntriesNeverExpire(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.mu.Lock()
	sm.whitelist["203.0.113.60"] = WhitelistEntry{
		IP:        "203.0.113.60",
		Permanent: true,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.blacklist["203.0.113.61"] = BlacklistEntry{
		IP:        "203.0.113.61",
		Permanent: true,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.mu.Unlock()

	if !sm.IsIPWhitelisted("203.0.113.60") {
		t.Error("permanent whitelisted IP must not expire")
	}

	if !sm.IsIPBlacklisted("203.0.113.61") {
		t.Error("permanent blacklisted IP must not expire")
	}
}

func TestBatchWhitelist(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	reqs := []BatchWhitelistRequest{
		{IP: "203.0.113.70", UserID: "a", Domain: "x.example"},
		{IP: "203.0.113.71", UserID: "b", Domain: "y.example"},
		{IP: "not-an-ip", UserID: "c", Domain: "z.example"},
	}

	results := sm.AddToWhitelistBatch(reqs)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results[0].Error != nil || results[1].Error != nil {
		t.Errorf("expected first two to succeed: %+v", results)
	}

	if results[2].Error == nil {
		t.Error("expected third (invalid IP) to fail")
	}
}

func TestBatchBlacklist(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	reqs := []BatchBlacklistRequest{
		{IP: "203.0.113.80", Reason: "test1"},
		{IP: "203.0.113.81", Reason: "test2"},
		{IP: "10.1.2.3", Reason: "trusted"},  // should be rejected (trusted net)
		{IP: "not-an-ip", Reason: "invalid"}, // should be rejected (invalid IP)
	}

	results := sm.AddToBlacklistBatch(reqs)
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	if results[0].Error != nil || results[1].Error != nil {
		t.Errorf("expected first two to succeed: %+v", results[:2])
	}

	if results[2].Error == nil {
		t.Error("expected trusted-network IP to be rejected")
	}

	if results[3].Error == nil {
		t.Error("expected invalid IP to be rejected")
	}
}

func TestGetBlacklistEntry(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToBlacklist("203.0.113.90", "spam", false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	entry, ok := sm.GetBlacklistEntry("203.0.113.90")
	if !ok {
		t.Fatal("GetBlacklistEntry returned not-found for known IP")
	}

	if entry.Reason != "spam" {
		t.Errorf("got Reason=%q, want %q", entry.Reason, "spam")
	}

	if _, ok := sm.GetBlacklistEntry("198.51.100.1"); ok {
		t.Error("GetBlacklistEntry should miss for unknown IP")
	}

	// Inject an expired entry — getter should report not-found.
	sm.mu.Lock()
	sm.blacklist["203.0.113.91"] = BlacklistEntry{
		IP:        "203.0.113.91",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.mu.Unlock()

	if _, ok := sm.GetBlacklistEntry("203.0.113.91"); ok {
		t.Error("GetBlacklistEntry should skip expired entry")
	}
}

func TestSnapshotGetters(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToWhitelist("203.0.113.95", "u", "d", false); err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if err := sm.AddToBlacklist("203.0.113.96", "test", false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	sm.ProcessFailedRegistration("203.0.113.97", "u", "d")
	sm.ProcessWrongCallState("203.0.113.98", "u")

	if !waitFor(func() bool {
		return len(sm.GetFailedAttempts()) > 0 && len(sm.GetWrongCallStates()) > 0
	}) {
		t.Fatal("expected failed/wrong-state records to be drained")
	}

	if got := sm.GetWhitelistedIPs(); len(got) == 0 {
		t.Error("GetWhitelistedIPs returned empty")
	}

	if got := sm.GetBlacklistedIPs(); len(got) == 0 {
		t.Error("GetBlacklistedIPs returned empty")
	}

	if got := sm.GetFailedAttempts(); len(got) == 0 {
		t.Error("GetFailedAttempts returned empty")
	}

	if got := sm.GetWrongCallStates(); len(got) == 0 {
		t.Error("GetWrongCallStates returned empty")
	}
}

func TestIPInTrustedNetwork_MultipleCIDRs(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.trustedNetworks = sm.trustedNetworks[:0]

	cidrs := []string{"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"}
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}

		sm.trustedNetworks = append(sm.trustedNetworks, n)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.20.30.40", true},
		{"192.168.99.99", true},
		{"172.16.1.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := sm.ipInTrustedNetwork(ip); got != c.want {
			t.Errorf("ipInTrustedNetwork(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSecurityConfigView(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true

	enabled, autoBlock := sm.SecurityConfigView()
	if !enabled || !autoBlock {
		t.Errorf("got enabled=%v autoBlock=%v, want both true", enabled, autoBlock)
	}
}

func TestCommandAllowed(t *testing.T) {
	t.Parallel()

	allowed := []string{"status", "uptime", "version"}
	cases := []struct {
		cmd  string
		want bool
	}{
		{"status", true},
		{"status all", true},
		{"status\targ", true},
		{"statusand_evil", false},
		{"status_evil", false},
		{"version", true},
		{"versions", false},
		{"reload mod_sofia", false},
		{"", false},
	}

	for _, c := range cases {
		if got := commandAllowed(c.cmd, allowed); got != c.want {
			t.Errorf("commandAllowed(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// waitForTimeout is the polling timeout used by waitFor across tests.
const waitForTimeout = 2 * time.Second

// waitFor polls cond until it returns true or waitForTimeout elapses.
// 10 ms granularity is enough for the test cases that wait on async workers.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(waitForTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(10 * time.Millisecond)
	}

	return cond()
}

// ----- Benchmarks -----

func BenchmarkIsIPWhitelisted_TrustedHit(b *testing.B) {
	sm := newTestSecurityManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsIPWhitelisted("10.1.2.3")
	}
}

func BenchmarkIsIPWhitelisted_MapHit(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.99", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsIPWhitelisted("203.0.113.99")
	}
}

func BenchmarkIsIPWhitelisted_Miss(b *testing.B) {
	sm := newTestSecurityManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsIPWhitelisted("198.51.100.42")
	}
}

func BenchmarkIsIPBlacklisted_Miss(b *testing.B) {
	sm := newTestSecurityManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsIPBlacklisted("198.51.100.42")
	}
}

func BenchmarkIsIPBlacklisted_Hit(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToBlacklist("203.0.113.100", "test", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsIPBlacklisted("203.0.113.100")
	}
}

func BenchmarkIsUntrustedDomain_Miss(b *testing.B) {
	sm := newTestSecurityManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsUntrustedDomain("good.example")
	}
}

func BenchmarkIsUntrustedDomain_Hit(b *testing.B) {
	sm := newTestSecurityManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.IsUntrustedDomain("evil.example")
	}
}

func BenchmarkAppendUnique_Hit(b *testing.B) {
	slice := []string{"alice", "bob", "carol", "dave", "eve"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = appendUnique(slice, "carol")
	}
}

func BenchmarkAppendUnique_New(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = appendUnique(nil, "alice")
	}
}

func BenchmarkCommandAllowed(b *testing.B) {
	allowed := []string{"status", "uptime", "version", "reload"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = commandAllowed("status all", allowed)
	}
}

// BenchmarkIPListStatus exercises the rate-limiter's combined exempt-status
// fast path. Complements the per-method IsIP{White,Black}listed benchmarks.
func BenchmarkIPListStatus_NewIP(b *testing.B) {
	sm := newTestSecurityManager(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = sm.ipListStatus("198.51.100.42")
	}
}

// BenchmarkIsIPWhitelisted_TrustedHit_ManyNets measures the cost when the
// trusted-network list is realistic (multiple CIDRs across IP classes), as
// opposed to the single-CIDR test helper. The current implementation linear-
// scans, so this should grow ~linearly until the user's IP matches.
func BenchmarkIsIPWhitelisted_TrustedHit_ManyNets(b *testing.B) {
	sm := newTestSecurityManager(b)
	// Override the trusted networks with a more realistic set.
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
	}

	sm.trustedNetworks = sm.trustedNetworks[:0]

	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			b.Fatal(err)
		}

		sm.trustedNetworks = append(sm.trustedNetworks, n)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		// Worst case: matches the last entry (169.254.x.x).
		_ = sm.IsIPWhitelisted("169.254.1.1")
	}
}

// ----- Parallel benchmarks: surface RWMutex contention behavior. -----

func BenchmarkIsIPWhitelisted_MapHit_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.99", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sm.IsIPWhitelisted("203.0.113.99")
		}
	})
}

func BenchmarkIsIPBlacklisted_Hit_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToBlacklist("203.0.113.100", "test", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sm.IsIPBlacklisted("203.0.113.100")
		}
	})
}

func BenchmarkIPListStatus_Whitelisted_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.99", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = sm.ipListStatus("203.0.113.99")
		}
	})
}

func BenchmarkIPListStatus_NewIP_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = sm.ipListStatus("198.51.100.42")
		}
	})
}

// ----- Async-queue write hot paths -----
//
// The intent of these benchmarks is to measure the cost of the producer-side
// channel send when the queue is not full. Without an active drainer, a
// b.N-iteration loop fills the queue in microseconds and every subsequent
// send hits the "default:" branch and logs an error — that's not the path we
// care about. We therefore replace the queue with a freshly-drained channel
// for each benchmark, with a private goroutine consuming as fast as possible.

// silenceLogs sends log.Printf output to io.Discard for the duration of the
// benchmark, since the queue-full error path can otherwise dominate timing.
func silenceLogs(b *testing.B) {
	b.Helper()

	old := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(old) })
}

// drainFailedQueue consumes from sm.failedQueue as quickly as possible and
// returns a stop function to end the goroutine.
func drainFailedQueue(sm *SecurityManager) func() {
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-sm.failedQueue:
			}
		}
	}()

	return func() { close(stop) }
}

func drainWrongStateQueue(sm *SecurityManager) func() {
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-sm.wrongStateQueue:
			}
		}
	}()

	return func() { close(stop) }
}

func drainBlacklistQueue(sm *SecurityManager) func() {
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-sm.blacklistQueue:
			}
		}
	}()

	return func() { close(stop) }
}

// newDrainedSecurityManager builds a SecurityManager whose async queues are
// consumed by private goroutines (instead of the production batch workers),
// so producer-side benchmarks measure the channel-send cost rather than the
// queue-full error path.
func newDrainedSecurityManager(tb testing.TB) *SecurityManager {
	tb.Helper()

	sm := &SecurityManager{
		whitelist:         make(map[string]WhitelistEntry),
		blacklist:         make(map[string]BlacklistEntry),
		failedAttempts:    make(map[string]FailedAttempt),
		wrongStates:       make(map[string]WrongCallStateEntry),
		untrustedPatterns: map[string]struct{}{},
		cfg: effectiveSecurityConfig{
			Enabled:                true,
			AutoBlockEnabled:       false,
			WhitelistEnabled:       true,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          "TEST",
			MaxFailedAttempts:      3,
			FailedWindow:           10 * time.Minute,
			BlockDuration:          time.Hour,
			WhitelistTTL:           24 * time.Hour,
			MaxWrongCallStates:     3,
			WrongStateWindow:       10 * time.Minute,
		},
		blacklistQueue:  make(chan BlacklistRequest, 1024),
		whitelistQueue:  make(chan WhitelistRequest, 1024),
		failedQueue:     make(chan FailedAttemptRequest, 1024),
		wrongStateQueue: make(chan WrongStateRequest, 1024),
	}
	sm.ctx, sm.cancel = context.WithCancel(tb.Context())

	stopFailed := drainFailedQueue(sm)
	stopWrong := drainWrongStateQueue(sm)
	stopBlack := drainBlacklistQueue(sm)

	tb.Cleanup(func() {
		sm.cancel()
		stopFailed()
		stopWrong()
		stopBlack()
	})

	return sm
}

func BenchmarkProcessFailedRegistration(b *testing.B) {
	silenceLogs(b)

	sm := newDrainedSecurityManager(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sm.ProcessFailedRegistration("203.0.113.200", "u", "d")
	}
}

func BenchmarkProcessWrongCallState(b *testing.B) {
	silenceLogs(b)

	sm := newDrainedSecurityManager(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sm.ProcessWrongCallState("203.0.113.201", "u")
	}
}

func BenchmarkAddToBlacklistAsync(b *testing.B) {
	silenceLogs(b)

	sm := newDrainedSecurityManager(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sm.AddToBlacklistAsync("203.0.113.202", "test", false)
	}
}

// ----- Snapshot getters (used by stats endpoints) -----

func BenchmarkGetWhitelistedIPs_1k(b *testing.B) {
	sm := newTestSecurityManager(b)

	for i := range 1000 {
		ip := fmt.Sprintf("203.0.%d.%d", i/256, i%256)
		if err := sm.AddToWhitelist(ip, "u", "d", false); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.GetWhitelistedIPs()
	}
}

func BenchmarkIPListStatus_Whitelisted(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.99", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = sm.ipListStatus("203.0.113.99")
	}
}

func BenchmarkIPListStatus_Blacklisted(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToBlacklist("203.0.113.100", "test", false); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = sm.ipListStatus("203.0.113.100")
	}
}

func TestIPListStatus(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToWhitelist("203.0.113.50", "u", "d", false); err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if err := sm.AddToBlacklist("203.0.113.51", "test", false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	cases := []struct {
		ip                               string
		wantWhitelisted, wantBlacklisted bool
	}{
		{"203.0.113.50", true, false},   // whitelisted
		{"203.0.113.51", false, true},   // blacklisted
		{"10.1.2.3", true, false},       // trusted network
		{"198.51.100.99", false, false}, // unknown
		{"not-an-ip", false, false},     // invalid
	}
	for _, c := range cases {
		wl, bl := sm.ipListStatus(c.ip)
		if wl != c.wantWhitelisted || bl != c.wantBlacklisted {
			t.Errorf("ipListStatus(%q) = (%v, %v), want (%v, %v)",
				c.ip, wl, bl, c.wantWhitelisted, c.wantBlacklisted)
		}
	}
}
