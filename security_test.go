package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Network fixtures shared across the security tests.
const (
	testTrustedCIDR     = "10.0.0.0/8"
	testPrivateCIDR     = "192.168.0.0/16"
	testLoopbackIP      = "127.0.0.1"
	testUntrustedDomain = "evil.example"
	testSampleIP        = "10.1.2.3"
	testChain           = "TEST"
)

// newTestSecurityManager builds an isolated SecurityManager for tests. It
// bypasses the package-level singleton and disables AutoBlock so tests never
// invoke iptables on the host.
func newTestSecurityManager(tb testing.TB) *SecurityManager {
	tb.Helper()
	// Suppress noisy log output during tests; raise via -v if needed.
	GetLogger().SetLogLevel(LogLevelError)

	trusted := make([]netip.Prefix, 0, 1)

	prefix, err := netip.ParsePrefix(testTrustedCIDR)
	if err == nil {
		trusted = append(trusted, prefix.Masked())
	}

	ctx, cancel := context.WithCancel(tb.Context())
	sm := &SecurityManager{
		whitelist:       make(map[string]WhitelistEntry),
		blacklist:       make(map[string]BlacklistEntry),
		failedAttempts:  make(map[string]FailedAttempt),
		wrongStates:     make(map[string]WrongCallStateEntry),
		trustedNetworks: trusted,
		untrustedPatterns: map[string]struct{}{
			testUntrustedDomain: {},
		},
		ipset: newTestIPSet(),
		cfg: effectiveSecurityConfig{
			Enabled:                true,
			AutoBlockEnabled:       false,
			WhitelistEnabled:       true,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          testChain,
			IPSetName:              testIPSetName,
			DryRun:                 false,
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
		{testBogusValue, time.Minute, time.Minute},
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
		{"empty add to nil", nil, testUserAlice, []string{testUserAlice}},
		{"skip empty", []string{testUserAlice}, "", []string{testUserAlice}},
		{"skip unknown", []string{testUserAlice}, "unknown", []string{testUserAlice}},
		{"dedupe", []string{testUserAlice}, testUserAlice, []string{testUserAlice}},
		{"append distinct", []string{testUserAlice}, testUserBob, []string{testUserAlice, testUserBob}},
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

func containsCall(calls []string, substr string) bool {
	for _, c := range calls {
		if strings.Contains(c, substr) {
			return true
		}
	}

	return false
}

func argsContain(args []string, want string) bool {
	return slices.Contains(args, want)
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

	if !sm.IsIPWhitelisted(testSampleIP) {
		t.Error("IP in trusted network 10.0.0.0/8 should be whitelisted")
	}

	if sm.IsIPWhitelisted("8.8.8.8") {
		t.Error("IP outside trusted network should not be whitelisted")
	}

	if sm.IsIPWhitelisted(testInvalidIP) {
		t.Error("invalid IP must not be whitelisted")
	}
}

func TestAddToWhitelist_RoundTrip(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	err := sm.AddToWhitelist("203.0.113.7", testUserAlice, "example.com", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if !sm.IsIPWhitelisted("203.0.113.7") {
		t.Error("expected IP to be whitelisted after AddToWhitelist")
	}

	entry, ok := sm.GetWhitelistEntry("203.0.113.7")
	if !ok {
		t.Fatal("GetWhitelistEntry returned not-found")
	}

	if entry.UserID != testUserAlice || entry.Domain != "example.com" {
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

	err := sm.AddToWhitelist(testInvalidIP, "u", "d", false)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestAddToBlacklist_RejectsTrustedIP(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	err := sm.AddToBlacklist(testSampleIP, "test", false)
	if err == nil {
		t.Error("expected error blacklisting IP in trusted network")
	}

	if sm.IsIPBlacklisted(testSampleIP) {
		t.Error("trusted IP must not be blacklisted")
	}
}

func TestAddToBlacklist_RejectsWhitelistedIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	err := sm.AddToWhitelist(testIPSample, "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	err = sm.AddToBlacklist(testIPSample, "test", false)
	if err == nil {
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
		sm.ProcessFailedRegistration(testSampleIP, "u", "example.com")
	}

	// Drain time
	time.Sleep(300 * time.Millisecond)

	if sm.IsIPBlacklisted(testSampleIP) {
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

	err := sm.AddUntrustedNetwork("new.example")
	if err != nil {
		t.Fatalf("AddUntrustedNetwork: %v", err)
	}

	if !sm.IsUntrustedDomain("new.example") {
		t.Error("expected new.example to be flagged after add")
	}

	err = sm.AddUntrustedNetwork("new.example")
	if err == nil {
		t.Error("expected duplicate-add error")
	}

	err = sm.RemoveUntrustedNetwork("new.example")
	if err != nil {
		t.Fatalf("RemoveUntrustedNetwork: %v", err)
	}

	if sm.IsUntrustedDomain("new.example") {
		t.Error("expected new.example to be cleared after remove")
	}

	err = sm.RemoveUntrustedNetwork("does-not-exist")
	if err == nil {
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
	sm.whitelist[testIPWhitelisted] = WhitelistEntry{
		IP: testIPWhitelisted, ExpiresAt: now.Add(-time.Hour),
	}
	sm.whitelist[testIPBlacklisted] = WhitelistEntry{
		IP: testIPBlacklisted, ExpiresAt: now.Add(time.Hour),
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

	if _, ok := sm.whitelist[testIPWhitelisted]; ok {
		t.Error("expired whitelist entry not cleaned")
	}

	if _, ok := sm.whitelist[testIPBlacklisted]; !ok {
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
		{IP: testInvalidIP, UserID: "c", Domain: "z.example"},
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
		{IP: testSampleIP, Reason: "trusted"},  // should be rejected (trusted net)
		{IP: testInvalidIP, Reason: "invalid"}, // should be rejected (invalid IP)
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

	err := sm.AddToBlacklist("203.0.113.90", "spam", false)
	if err != nil {
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

	err := sm.AddToWhitelist("203.0.113.95", "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	err = sm.AddToBlacklist("203.0.113.96", "test", false)
	if err != nil {
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

	cidrs := []string{"127.0.0.0/8", testTrustedCIDR, testPrivateCIDR}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatal(err)
		}

		sm.trustedNetworks = append(sm.trustedNetworks, prefix.Masked())
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{testLoopbackIP, true},
		{"10.20.30.40", true},
		{"192.168.99.99", true},
		{"172.16.1.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.ip)
		if got := sm.ipInTrustedNetwork(addr); got != c.want {
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

	allowed := []string{testCmdStatus, testCmdUptime, testCmdVersion}
	cases := []struct {
		cmd  string
		want bool
	}{
		{testCmdStatus, true},
		{"status all", true},
		{"status\targ", true},
		{"statusand_evil", false},
		{"status_evil", false},
		{testCmdVersion, true},
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
		_ = sm.IsIPWhitelisted(testSampleIP)
	}
}

func BenchmarkIsIPWhitelisted_MapHit(b *testing.B) {
	sm := newTestSecurityManager(b)

	err := sm.AddToWhitelist("203.0.113.99", "u", "d", false)
	if err != nil {
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

	err := sm.AddToBlacklist("203.0.113.100", "test", false)
	if err != nil {
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
	slice := []string{testUserAlice, testUserBob, testUserCarol, testUserDave, "eve"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkStrings = appendUnique(slice, testUserCarol)
	}
}

func BenchmarkAppendUnique_New(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkStrings = appendUnique(nil, testUserAlice)
	}
}

func BenchmarkCommandAllowed(b *testing.B) {
	allowed := []string{testCmdStatus, testCmdUptime, testCmdVersion, "reload"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkBool = commandAllowed("status all", allowed)
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
		testTrustedCIDR,
		"172.16.0.0/12",
		testPrivateCIDR,
		"100.64.0.0/10",
		"169.254.0.0/16",
	}

	sm.trustedNetworks = sm.trustedNetworks[:0]

	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			b.Fatal(err)
		}

		sm.trustedNetworks = append(sm.trustedNetworks, prefix.Masked())
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

	err := sm.AddToWhitelist("203.0.113.99", "u", "d", false)
	if err != nil {
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

	err := sm.AddToBlacklist("203.0.113.100", "test", false)
	if err != nil {
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

	err := sm.AddToWhitelist("203.0.113.99", "u", "d", false)
	if err != nil {
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
		ipset:             newTestIPSet(),
		cfg: effectiveSecurityConfig{
			Enabled:                true,
			AutoBlockEnabled:       false,
			WhitelistEnabled:       true,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          testChain,
			IPSetName:              testIPSetName,
			DryRun:                 false,
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

	// Inject entries directly: the production AddToWhitelist round-trip waits
	// on the 100ms batch ticker, which would turn this setup into ~100s per
	// -count sample. The benchmark measures the snapshot getter, not the add.
	now := time.Now()

	sm.mu.Lock()
	for i := range 1000 {
		ip := fmt.Sprintf("203.0.%d.%d", i/256, i%256)
		sm.whitelist[ip] = WhitelistEntry{
			IP: ip, AddedAt: now, ExpiresAt: now.Add(time.Hour), UserID: "u", Domain: "d",
		}
	}
	sm.mu.Unlock()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = sm.GetWhitelistedIPs()
	}
}

func BenchmarkIPListStatus_Whitelisted(b *testing.B) {
	sm := newTestSecurityManager(b)

	err := sm.AddToWhitelist("203.0.113.99", "u", "d", false)
	if err != nil {
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

	err := sm.AddToBlacklist("203.0.113.100", "test", false)
	if err != nil {
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

	err := sm.AddToWhitelist(testIPWhitelisted, "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	err = sm.AddToBlacklist(testIPBlacklisted, "test", false)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	cases := []struct {
		ip                               string
		wantWhitelisted, wantBlacklisted bool
	}{
		{testIPWhitelisted, true, false}, // whitelisted
		{testIPBlacklisted, false, true}, // blacklisted
		{testSampleIP, true, false},      // trusted network
		{"198.51.100.99", false, false},  // unknown
		{testInvalidIP, false, false},    // invalid
	}
	for _, c := range cases {
		wl, bl := sm.ipListStatus(c.ip)
		if wl != c.wantWhitelisted || bl != c.wantBlacklisted {
			t.Errorf("ipListStatus(%q) = (%v, %v), want (%v, %v)",
				c.ip, wl, bl, c.wantWhitelisted, c.wantBlacklisted)
		}
	}
}

// ----- Stats and async enqueue paths -----

func TestGetSecurityStats(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.UpdateRegistrationStats("203.0.113.110", "u", "d")
	sm.UpdateRegistrationStats("203.0.113.111", "u", "d")

	stats := sm.GetSecurityStats()
	if stats.TotalRegistrations != 2 {
		t.Errorf("TotalRegistrations = %d, want 2", stats.TotalRegistrations)
	}

	if stats.LastRegistrationTime.IsZero() {
		t.Error("LastRegistrationTime not set")
	}
}

func TestAddToBlacklistAsync(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.AddToBlacklistAsync("203.0.113.112", "async test", false)

	if !waitFor(func() bool { return sm.IsIPBlacklisted("203.0.113.112") }) {
		t.Error("expected async blacklist request to be applied")
	}
}

// newSaturatedSecurityManager returns a manager whose queues are unbuffered
// with no drainers, so every non-blocking enqueue takes the queue-full branch.
func newSaturatedSecurityManager() *SecurityManager {
	return &SecurityManager{
		blacklistQueue:  make(chan BlacklistRequest),
		whitelistQueue:  make(chan WhitelistRequest),
		failedQueue:     make(chan FailedAttemptRequest),
		wrongStateQueue: make(chan WrongStateRequest),
	}
}

func TestQueueFullDropsAreNonBlocking(t *testing.T) {
	t.Parallel()

	sm := newSaturatedSecurityManager()

	done := make(chan struct{})

	go func() {
		defer close(done)

		sm.AddToBlacklistAsync("203.0.113.113", "drop me", false)
		sm.ProcessFailedRegistration("203.0.113.113", "u", "d")
		sm.ProcessWrongCallState("203.0.113.113", "u")
		sm.enqueueBlacklist([]BlacklistRequest{{IP: "203.0.113.113", Reason: "drop"}})
	}()

	select {
	case <-done:
	case <-time.After(waitForTimeout):
		t.Fatal("queue-full paths must never block the caller")
	}
}

// TestAddTimeouts covers the enqueue- and response-timeout branches of
// AddToBlacklist and AddToWhitelist. All four slow paths run concurrently so
// the test costs one response-timeout (~5s) of wall clock, in parallel with
// the rest of the suite.
func TestAddTimeouts(t *testing.T) {
	t.Parallel()

	// Unbuffered queues, no drainers: enqueue times out.
	saturated := newSaturatedSecurityManager()

	// Buffered queues, no drainers: enqueue succeeds, response never comes.
	unanswered := &SecurityManager{
		blacklistQueue:  make(chan BlacklistRequest, 1),
		whitelistQueue:  make(chan WhitelistRequest, 1),
		failedQueue:     make(chan FailedAttemptRequest, 1),
		wrongStateQueue: make(chan WrongStateRequest, 1),
	}

	var wg sync.WaitGroup

	check := func(name string, wantErr error, fn func() error) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			err := fn()
			if !errors.Is(err, wantErr) {
				t.Errorf("%s: err = %v, want %v", name, err, wantErr)
			}
		}()
	}

	check("blacklist enqueue", ErrTimeoutQueueing, func() error {
		return saturated.AddToBlacklist("203.0.113.114", "t", false)
	})
	check("whitelist enqueue", ErrTimeoutQueueing, func() error {
		return saturated.AddToWhitelist("203.0.113.114", "u", "d", false)
	})
	check("blacklist response", ErrTimeoutWaiting, func() error {
		return unanswered.AddToBlacklist("203.0.113.115", "t", false)
	})
	check("whitelist response", ErrTimeoutWaiting, func() error {
		return unanswered.AddToWhitelist("203.0.113.115", "u", "d", false)
	})

	wg.Wait()
}

func TestGetWhitelistEntry_Expired(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.mu.Lock()
	sm.whitelist["203.0.113.116"] = WhitelistEntry{
		IP:        "203.0.113.116",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.mu.Unlock()

	if _, ok := sm.GetWhitelistEntry("203.0.113.116"); ok {
		t.Error("expired whitelist entry must read as not-found")
	}
}

// TestWhitelistUnblocksBlacklistedIP covers the blacklist-eviction path of
// processBatchWhitelist: whitelisting a blacklisted IP removes the blacklist
// entry and unblocks it from the ipset when auto-block is on.
func TestWhitelistUnblocksBlacklistedIP(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		calls []string
	)

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true
	// A single fully guarded runner: recordingRunner is not safe for the
	// concurrent batch workers (it appends to its slice without a lock).
	sm.ipset.run = func(name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()

		calls = append(calls, name+" "+strings.Join(args, " "))

		return nil, nil
	}

	const ip = "203.0.113.117"

	err := sm.AddToBlacklist(ip, "bad", false)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	err = sm.AddToWhitelist(ip, "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if sm.IsIPBlacklisted(ip) {
		t.Error("whitelisting must evict the blacklist entry")
	}

	// The ipset unblock runs after the whitelist response is delivered;
	// poll instead of asserting immediately.
	if !waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()

		return containsCall(calls, "ipset del "+testIPSetName+" "+ip)
	}) {
		t.Error("expected ipset del for the evicted blacklist entry")
	}
}

func TestRemoveFromBlacklist_UnblocksViaIPSet(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true
	// One runner, installed before any queue op (so the channel send/recv
	// synchronizes it with the workers): the del for .119 fails, everything
	// else succeeds. Reassigning run mid-test would race the batch workers.
	sm.ipset.run = func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "del" && argsContain(args, "203.0.113.119") {
			return []byte(fakeOutResourceBusy), errFakeIPSet
		}

		return nil, nil
	}

	err := sm.AddToBlacklist("203.0.113.118", "t", false)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	sm.RemoveFromBlacklist("203.0.113.118") // unblock success branch

	if sm.IsIPBlacklisted("203.0.113.118") {
		t.Error("IP must be removed from blacklist")
	}

	// Error branch: the ipset del fails for a real reason; removal still proceeds.
	err = sm.AddToBlacklist("203.0.113.119", "t", false)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	sm.RemoveFromBlacklist("203.0.113.119")

	if sm.IsIPBlacklisted("203.0.113.119") {
		t.Error("IP must be removed from blacklist even when unblock fails")
	}
}

func TestCommandAllowed_EmptyPrefixSkipped(t *testing.T) {
	t.Parallel()

	if commandAllowed("anything", []string{"", testCmdStatus}) {
		t.Error("empty allowlist entries must not match")
	}

	if !commandAllowed(testCmdStatus, []string{"", testCmdStatus}) {
		t.Error("entries after an empty one must still match")
	}
}

func TestSecurityManagerShutdown_Idempotent(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.Shutdown()
	sm.Shutdown() // CAS guard: second call returns immediately
}

// TestBatchSizeFlush floods the async queues faster than the 50–100ms flush
// tickers so the size-triggered flush branches execute.
func TestBatchSizeFlush(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// Blacklist queue (batch size 32).
	for i := range 200 {
		sm.AddToBlacklistAsync(fmt.Sprintf("203.0.%d.%d", 120+i/250, i%250), "flood", false)
	}

	// Whitelist queue (batch size 32) — direct async sends.
	for i := range 200 {
		select {
		case sm.whitelistQueue <- WhitelistRequest{IP: fmt.Sprintf("198.51.%d.%d", 100+i/250, i%250)}:
		default:
		}
	}

	// Failed-attempt and wrong-state queues (batch size 64).
	for i := range 200 {
		sm.ProcessFailedRegistration(fmt.Sprintf("192.0.2.%d", i%250), "u", "d")
		sm.ProcessWrongCallState(fmt.Sprintf("192.0.2.%d", i%250), "u")
	}

	if !waitFor(func() bool {
		return len(sm.GetBlacklistedIPs()) > 100 &&
			len(sm.GetWhitelistedIPs()) > 100 &&
			len(sm.GetFailedAttempts()) > 0 &&
			len(sm.GetWrongCallStates()) > 0
	}) {
		t.Error("flooded queues were not drained into state maps")
	}
}

func TestWhitelistUnblockError(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true
	// Every ipset command fails; eviction must still proceed (error logged).
	sm.ipset.run = func(_ string, _ ...string) ([]byte, error) {
		return []byte(fakeOutResourceBusy), errFakeIPSet
	}

	const ip = "203.0.113.230"

	err := sm.AddToBlacklist(ip, "bad", false)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	err = sm.AddToWhitelist(ip, "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	// Eviction succeeds even when the ipset unblock fails (logged).
	if sm.IsIPBlacklisted(ip) {
		t.Error("blacklist entry must be evicted despite unblock failure")
	}
}

func TestProcessFailedRegistration_WhitelistedSkipped(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	const ip = "203.0.113.231"

	err := sm.AddToWhitelist(ip, "u", "d", false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	sm.ProcessFailedRegistration(ip, "u", "d")
	sm.ProcessWrongCallState(ip, "u")

	time.Sleep(200 * time.Millisecond) // allow batches to flush

	if _, ok := sm.GetFailedAttempts()[ip]; ok {
		t.Error("whitelisted IP must not accumulate failed attempts")
	}

	if _, ok := sm.GetWrongCallStates()[ip]; ok {
		t.Error("whitelisted IP must not accumulate wrong-state records")
	}
}

func TestProcessWrongCallState_InvalidIPSkipped(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.ProcessWrongCallState(testInvalidIP, "u")

	time.Sleep(200 * time.Millisecond)

	if len(sm.GetWrongCallStates()) != 0 {
		t.Error("invalid IP must not be tracked")
	}
}

func TestProcessFailedRegistration_UntrustedDomainBlacklists(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// evil.example is in the helper's untrusted set; one failure from an
	// untrusted domain queues a blacklist request regardless of counters.
	const ip = "203.0.113.232"

	sm.ProcessFailedRegistration(ip, "u", "evil.example")

	if !waitFor(func() bool { return sm.IsIPBlacklisted(ip) }) {
		t.Error("failed registration from untrusted domain must blacklist the IP")
	}
}

func TestRemoveFromWhitelist_Unknown(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.RemoveFromWhitelist("198.51.100.250") // not present: must log-and-return
}

func TestIsIPWhitelisted_ExpiredAndNoTrustedNets(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// Expired non-permanent entry falls through to the trusted-network check.
	sm.mu.Lock()
	sm.whitelist["203.0.113.233"] = WhitelistEntry{
		IP:        "203.0.113.233",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.trustedNetworks = nil
	sm.mu.Unlock()

	if sm.IsIPWhitelisted("203.0.113.233") {
		t.Error("expired entry with no trusted networks must not be whitelisted")
	}

	if sm.IsIPWhitelisted("203.0.113.234") {
		t.Error("unknown IP with no trusted networks must not be whitelisted")
	}
}

func TestCleanupUnblocksExpiredBlacklist(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true
	// The ipset del fails; cleanup must log and proceed (covers the error arm).
	sm.ipset.run = func(_ string, _ ...string) ([]byte, error) {
		return []byte(fakeOutResourceBusy), errFakeIPSet
	}

	sm.mu.Lock()
	sm.blacklist["203.0.113.235"] = BlacklistEntry{
		IP:        "203.0.113.235",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	sm.mu.Unlock()

	sm.cleanupExpiredEntries()

	if sm.IsIPBlacklisted("203.0.113.235") {
		t.Error("expired blacklist entry must be cleaned")
	}
}

// TestQueueDrainersExitOnClose covers the queue-closed (!ok) flush-and-return
// branches of all four drainer goroutines.
func TestQueueDrainersExitOnClose(t *testing.T) {
	t.Parallel()

	sm := &SecurityManager{
		whitelist:         make(map[string]WhitelistEntry),
		blacklist:         make(map[string]BlacklistEntry),
		failedAttempts:    make(map[string]FailedAttempt),
		wrongStates:       make(map[string]WrongCallStateEntry),
		untrustedPatterns: map[string]struct{}{},
		blacklistQueue:    make(chan BlacklistRequest, 4),
		whitelistQueue:    make(chan WhitelistRequest, 4),
		failedQueue:       make(chan FailedAttemptRequest, 4),
		wrongStateQueue:   make(chan WrongStateRequest, 4),
	}
	sm.ctx, sm.cancel = context.WithCancel(t.Context())

	sm.wg.Add(4)
	go sm.processBlacklistQueue()
	go sm.processWhitelistQueue()
	go sm.processFailedAttemptQueue()
	go sm.processWrongStateQueue()

	// Leave one pending item in each queue so the closing flush has work.
	const drainIP = "203.0.113.236"

	sm.blacklistQueue <- BlacklistRequest{IP: drainIP, Reason: "t"}

	sm.whitelistQueue <- WhitelistRequest{IP: drainIP}

	sm.failedQueue <- FailedAttemptRequest{IP: drainIP}

	sm.wrongStateQueue <- WrongStateRequest{IP: drainIP}

	close(sm.blacklistQueue)
	close(sm.whitelistQueue)
	close(sm.failedQueue)
	close(sm.wrongStateQueue)

	sm.wg.Wait() // drainers must exit via the !ok branch
}

func TestAddToWhitelistAsync(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	sm.AddToWhitelistAsync("203.0.113.240", "u", "d", false)

	if !waitFor(func() bool { return sm.IsIPWhitelisted("203.0.113.240") }) {
		t.Error("expected async whitelist request to be applied")
	}
}

func TestRefreshWhitelistEntry(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	// Missing entry: no refresh.
	if sm.RefreshWhitelistEntry("203.0.113.241") {
		t.Error("refresh must report false for an unknown IP")
	}

	// Existing entry: TTL extended, LastSeen stamped.
	stale := time.Now().Add(-time.Hour)

	sm.mu.Lock()
	sm.whitelist["203.0.113.241"] = WhitelistEntry{
		IP: "203.0.113.241", ExpiresAt: time.Now().Add(time.Minute), LastSeen: stale,
	}
	sm.whitelist["203.0.113.242"] = WhitelistEntry{
		IP: "203.0.113.242", Permanent: true, ExpiresAt: stale, LastSeen: stale,
	}
	sm.mu.Unlock()

	if !sm.RefreshWhitelistEntry("203.0.113.241") {
		t.Fatal("refresh must report true for an existing IP")
	}

	entry, ok := sm.GetWhitelistEntry("203.0.113.241")
	if !ok {
		t.Fatal("entry vanished after refresh")
	}

	if entry.ExpiresAt.Before(time.Now().Add(sm.cfg.WhitelistTTL - time.Minute)) {
		t.Errorf("ExpiresAt not extended by TTL: %v", entry.ExpiresAt)
	}

	if !entry.LastSeen.After(stale) {
		t.Error("LastSeen not stamped")
	}

	// Permanent entry: LastSeen stamped, ExpiresAt untouched.
	if !sm.RefreshWhitelistEntry("203.0.113.242") {
		t.Fatal("refresh must report true for a permanent entry")
	}

	permanent, ok := sm.GetWhitelistEntry("203.0.113.242")
	if !ok {
		t.Fatal("permanent entry vanished after refresh")
	}

	if !permanent.ExpiresAt.Equal(stale) {
		t.Errorf("permanent ExpiresAt must not change: %v", permanent.ExpiresAt)
	}

	if !permanent.LastSeen.After(stale) {
		t.Error("permanent LastSeen not stamped")
	}
}

// TestBatchBlockIPs_PermanentAndError covers the ipset block path used by
// auto-blocking: a permanent ban is added with a zero (no-expiry) timeout, and
// a failing ipset add is logged without stopping the batch.
func TestBatchBlockIPs_PermanentAndError(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		calls []string
	)

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true
	// A single fully guarded runner installed before any queue op: the add for
	// .251 fails, everything else succeeds. recordingRunner is not safe under
	// the concurrent batch workers.
	sm.ipset.run = func(name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()

		calls = append(calls, name+" "+strings.Join(args, " "))

		if len(args) > 0 && args[0] == "add" && argsContain(args, "203.0.113.251") {
			return []byte(fakeOutPermissionDenied), errFakeIPSet
		}

		return nil, nil
	}

	// Permanent ban → ipset add with "timeout 0".
	permErr := sm.AddToBlacklist("203.0.113.250", "perma", true)
	if permErr != nil {
		t.Fatalf("AddToBlacklist permanent: %v", permErr)
	}

	if !waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()

		return containsCall(calls, "ipset add "+testIPSetName+" 203.0.113.250 timeout 0")
	}) {
		t.Error("expected permanent ban to add with timeout 0")
	}

	// Failing ipset add must be logged, not fatal: the batch keeps going.
	finErr := sm.AddToBlacklist("203.0.113.251", "boom", false)
	if finErr != nil {
		t.Fatalf("AddToBlacklist finite: %v", finErr)
	}

	if !waitFor(func() bool { return sm.IsIPBlacklisted("203.0.113.251") }) {
		t.Error("blacklist bookkeeping must succeed even when the ipset add fails")
	}
}
