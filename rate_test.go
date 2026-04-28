package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestRateManager builds a rate manager with a configurable, isolated
// effectiveRateConfig. It does not start the cleanup loop unless Enabled is
// true; if started, it is torn down via t.Cleanup.
func newTestRateManager(tb testing.TB, sm *SecurityManager, eff effectiveRateConfig) *RateManager {
	tb.Helper()

	ctx, cancel := context.WithCancel(tb.Context())
	rm := &RateManager{
		securityManager: sm,
		callRates:       make(map[string]*RateCounter),
		regRates:        make(map[string]*RateCounter),
		cfg:             eff,
		ctx:             ctx,
		cancel:          cancel,
	}
	tb.Cleanup(rm.Shutdown)

	return rm
}

func defaultTestRateConfig() effectiveRateConfig {
	return effectiveRateConfig{
		Enabled:           true,
		AutoBlockOnExceed: false,
		WhitelistBypass:   true,
		CallRateLimit:     5,
		CallRateInterval:  time.Minute,
		RegistrationLimit: 3,
		RegWindow:         time.Minute,
		BlockDuration:     time.Minute,
		CleanupInterval:   time.Minute,
	}
}

func TestRateManager_Disabled(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	cfg := defaultTestRateConfig()
	cfg.Enabled = false
	rm := newTestRateManager(t, sm, cfg)

	for range 100 {
		if !rm.CheckCallRate("203.0.113.1", "u", "d") {
			t.Fatal("disabled rate limiter must always permit")
		}
	}
}

func TestRateManager_BlocksAtLimit(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	const ip = "203.0.113.2"

	limit := rm.cfg.CallRateLimit
	for i := range limit {
		if !rm.CheckCallRate(ip, "u", "d") {
			t.Fatalf("call %d/%d: expected allowed", i+1, limit)
		}
	}

	if rm.CheckCallRate(ip, "u", "d") {
		t.Errorf("call after limit (%d) should be denied", limit)
	}
}

func TestRateManager_WhitelistBypass(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	if err := sm.AddToWhitelist("203.0.113.3", "u", "d", false); err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	for range 50 {
		if !rm.CheckCallRate("203.0.113.3", "u", "d") {
			t.Fatal("whitelisted IP must bypass rate limit")
		}
	}
}

func TestRateManager_BlacklistedDenied(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	if err := sm.AddToBlacklist("203.0.113.4", "test", false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	if rm.CheckCallRate("203.0.113.4", "u", "d") {
		t.Error("blacklisted IP must always be denied")
	}
}

func TestRateManager_RegistrationIndependentBucket(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	const ip = "203.0.113.5"
	// Use up call quota
	for range rm.cfg.CallRateLimit {
		_ = rm.CheckCallRate(ip, "u", "d")
	}
	// Registration bucket should still permit
	for i := range rm.cfg.RegistrationLimit {
		if !rm.CheckRegistrationRate(ip, "u", "d") {
			t.Errorf("registration %d/%d: expected allowed", i+1, rm.cfg.RegistrationLimit)
		}
	}
}

func TestRateManager_WindowReset(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	cfg := defaultTestRateConfig()
	cfg.CallRateInterval = 50 * time.Millisecond
	rm := newTestRateManager(t, sm, cfg)

	const ip = "203.0.113.6"
	for range cfg.CallRateLimit {
		_ = rm.CheckCallRate(ip, "u", "d")
	}

	if rm.CheckCallRate(ip, "u", "d") {
		t.Fatal("expected limit to be hit before window reset")
	}

	time.Sleep(70 * time.Millisecond)

	if !rm.CheckCallRate(ip, "u", "d") {
		t.Error("expected window reset to allow new call")
	}
}

func TestRateManager_CleanupNow(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	cfg := defaultTestRateConfig()
	cfg.CallRateInterval = 10 * time.Millisecond
	cfg.RegWindow = 10 * time.Millisecond
	rm := newTestRateManager(t, sm, cfg)

	_ = rm.CheckCallRate("203.0.113.7", "u", "d")
	_ = rm.CheckRegistrationRate("203.0.113.7", "u", "d")

	time.Sleep(20 * time.Millisecond)

	c, r := rm.CleanupNow()
	if c == 0 || r == 0 {
		t.Errorf("expected cleanup to remove entries, got calls=%d regs=%d", c, r)
	}
}

func TestRateManager_ConcurrentCalls(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	cfg := defaultTestRateConfig()
	cfg.CallRateLimit = 1000
	rm := newTestRateManager(t, sm, cfg)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 10 {
				_ = rm.CheckCallRate("203.0.113.8", "u", "d")
			}
		}()
	}

	wg.Wait()
}

// ----- Benchmarks -----

func BenchmarkCheckCallRate_NewIP(b *testing.B) {
	sm := newTestSecurityManager(b)
	cfg := defaultTestRateConfig()
	cfg.CallRateLimit = 1 << 30
	rm := newTestRateManager(b, sm, cfg)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = rm.CheckCallRate("203.0.113.99", "u", "d")
	}
}

func BenchmarkCheckCallRate_Whitelisted(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.50", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	rm := newTestRateManager(b, sm, defaultTestRateConfig())

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = rm.CheckCallRate("203.0.113.50", "u", "d")
	}
}

func BenchmarkCheckCallRate_TrustedNet(b *testing.B) {
	sm := newTestSecurityManager(b)
	rm := newTestRateManager(b, sm, defaultTestRateConfig())

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = rm.CheckCallRate("10.1.2.3", "u", "d")
	}
}

// CheckRegistrationRate mirrors CheckCallRate but writes to the regRates
// bucket. Same code path, separate counters; benched here for completeness.
func BenchmarkCheckRegistrationRate_NewIP(b *testing.B) {
	sm := newTestSecurityManager(b)
	cfg := defaultTestRateConfig()
	cfg.RegistrationLimit = 1 << 30
	rm := newTestRateManager(b, sm, cfg)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = rm.CheckRegistrationRate("203.0.113.99", "u", "d")
	}
}

func BenchmarkCheckRegistrationRate_Whitelisted(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.50", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	rm := newTestRateManager(b, sm, defaultTestRateConfig())
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = rm.CheckRegistrationRate("203.0.113.50", "u", "d")
	}
}

// ----- Parallel rate-limit benchmarks: surface mutex contention. -----

// BenchmarkCheckCallRate_NewIP_Parallel measures contention on rm.mu when many
// goroutines concurrently increment the SAME counter (worst-case write storm).
func BenchmarkCheckCallRate_NewIP_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	cfg := defaultTestRateConfig()
	cfg.CallRateLimit = 1 << 30
	rm := newTestRateManager(b, sm, cfg)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rm.CheckCallRate("203.0.113.99", "u", "d")
		}
	})
}

// BenchmarkCheckCallRate_Whitelisted_Parallel measures the read-only
// (whitelisted) hot path, which only touches the security manager's RLock.
// Reveals RWMutex reader-counter atomic contention.
func BenchmarkCheckCallRate_Whitelisted_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	if err := sm.AddToWhitelist("203.0.113.50", "u", "d", false); err != nil {
		b.Fatal(err)
	}

	rm := newTestRateManager(b, sm, defaultTestRateConfig())
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rm.CheckCallRate("203.0.113.50", "u", "d")
		}
	})
}

// BenchmarkCheckCallRate_DistinctIPs_Parallel measures realistic load — each
// goroutine works on a distinct IP, so map writes don't all serialize on the
// same counter. This is closer to production traffic with many sources.
func BenchmarkCheckCallRate_DistinctIPs_Parallel(b *testing.B) {
	sm := newTestSecurityManager(b)
	cfg := defaultTestRateConfig()
	cfg.CallRateLimit = 1 << 30
	rm := newTestRateManager(b, sm, cfg)

	var counter int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine claims a private IP range derived from a global counter.
		// Within a goroutine, the IP cycles through 256 values to avoid hitting
		// the rate limiter's window check on the same IP repeatedly.
		base := atomic.AddInt64(&counter, 1)

		i := 0
		for pb.Next() {
			ip := fmt.Sprintf("203.0.%d.%d", base&0xff, i&0xff)
			_ = rm.CheckCallRate(ip, "u", "d")
			i++
		}
	})
}
