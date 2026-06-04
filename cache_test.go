package main

import (
	"context"
	"testing"
	"time"
)

// newTestCacheManager builds an isolated, enabled cache for tests, with its
// expiry janitor running and torn down via t.Cleanup.
func newTestCacheManager(tb testing.TB) *CacheManager {
	tb.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cm := &CacheManager{
		enabled:     true,
		securityTTL: time.Minute,
		items:       make(map[string]cacheItem),
		cancel:      cancel,
	}

	cm.wg.Add(1)
	go cm.janitor(ctx, time.Minute)

	tb.Cleanup(cm.Shutdown)

	return cm
}

func TestCacheManager_Disabled(t *testing.T) {
	t.Parallel()

	cm := &CacheManager{enabled: false}
	cm.CacheSecurityItem("key", []byte("value")) // must not panic

	if data, ok := cm.GetSecurityItem("key"); ok || data != nil {
		t.Errorf("disabled cache must always miss")
	}

	cm.DeleteSecurityItem("key")

	cm.ClearSecurityCache() // disabled: no-op, must not panic
}

func TestCacheManager_RoundTrip(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.CacheSecurityItem("key", []byte("value"))

	got, ok := cm.GetSecurityItem("key")
	if !ok {
		t.Fatal("expected hit on cached item")
	}

	if string(got) != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}

	cm.DeleteSecurityItem("key")

	if _, ok := cm.GetSecurityItem("key"); ok {
		t.Error("expected miss after delete")
	}
}

func TestCacheManager_Miss(t *testing.T) {
	t.Parallel()

	cm := newTestCacheManager(t)
	if _, ok := cm.GetSecurityItem("nonexistent"); ok {
		t.Error("expected miss")
	}
}

func TestCacheManager_Expiry(t *testing.T) {
	t.Parallel()

	cm := newTestCacheManager(t)
	cm.securityTTL = 20 * time.Millisecond

	cm.CacheSecurityItem("k", []byte("v"))

	if _, ok := cm.GetSecurityItem("k"); !ok {
		t.Fatal("expected hit before expiry")
	}

	time.Sleep(40 * time.Millisecond)

	if _, ok := cm.GetSecurityItem("k"); ok {
		t.Error("expected miss after TTL elapsed")
	}
}

func TestCacheManager_ReturnsCopy(t *testing.T) {
	t.Parallel()

	cm := newTestCacheManager(t)
	cm.CacheSecurityItem("k", []byte("value"))

	got, ok := cm.GetSecurityItem("k")
	if !ok {
		t.Fatal("expected hit")
	}

	got[0] = 'X' // mutating the returned slice must not affect the stored entry

	again, _ := cm.GetSecurityItem("k")
	if string(again) != "value" {
		t.Errorf("stored value was mutated through the returned slice: %q", again)
	}
}

func TestCacheManager_Stats(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)
	cm.CacheSecurityItem("k", []byte("v"))
	_, _ = cm.GetSecurityItem("k")
	cm.DeleteSecurityItem("k")

	if got := cm.stats.Writes.Load(); got != 1 {
		t.Errorf("Writes = %d, want 1", got)
	}

	if got := cm.stats.Reads.Load(); got != 1 {
		t.Errorf("Reads = %d, want 1", got)
	}

	if got := cm.stats.Deletes.Load(); got != 1 {
		t.Errorf("Deletes = %d, want 1", got)
	}
}

func TestCacheManager_PurgeExpired(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	// Inject one already-expired and one live entry, then purge directly.
	cm.mu.Lock()
	cm.items["stale"] = cacheItem{data: []byte("x"), expires: time.Now().Add(-time.Hour)}
	cm.items["fresh"] = cacheItem{data: []byte("y"), expires: time.Now().Add(time.Hour)}
	cm.mu.Unlock()

	cm.purgeExpired()

	cm.mu.RLock()
	_, staleOK := cm.items["stale"]
	_, freshOK := cm.items["fresh"]
	cm.mu.RUnlock()

	if staleOK {
		t.Error("expired entry must be purged")
	}

	if !freshOK {
		t.Error("live entry must survive purge")
	}
}

// ----- Benchmarks -----

func BenchmarkCacheSet(b *testing.B) {
	cm := newTestCacheManager(b)
	value := []byte("some-cached-value-payload")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		cm.CacheSecurityItem("key", value)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	cm := newTestCacheManager(b)
	cm.CacheSecurityItem("key", []byte("payload"))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = cm.GetSecurityItem("key")
	}
}

func BenchmarkCacheGet_Miss(b *testing.B) {
	cm := newTestCacheManager(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = cm.GetSecurityItem("absent")
	}
}

// ----- Stats, clear, shutdown, and nil/disabled guards -----

func TestCacheManager_GetCacheStats_Enabled(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.CacheSecurityItem("k", []byte("v"))
	_, _ = cm.GetSecurityItem("k")

	stats := cm.GetCacheStats()
	if stats["enabled"] != true {
		t.Fatalf("enabled = %v", stats["enabled"])
	}

	sec, ok := stats["security"].(map[string]any)
	if !ok {
		t.Fatalf("missing security section: %v", stats)
	}

	if sec["ttl"] != time.Minute.String() {
		t.Errorf("ttl = %v", sec["ttl"])
	}

	ops, ok := stats["operations"].(map[string]any)
	if !ok {
		t.Fatalf("missing operations section: %v", stats)
	}

	if ops["writes"] != int64(1) || ops["reads"] != int64(1) {
		t.Errorf("operations = %v", ops)
	}
}

func TestCacheManager_GetCacheStats_Disabled(t *testing.T) {
	t.Parallel()

	cm := &CacheManager{enabled: false}

	stats := cm.GetCacheStats()
	if stats["enabled"] != false {
		t.Errorf("enabled = %v", stats["enabled"])
	}

	if _, ok := stats["operations"]; ok {
		t.Error("disabled stats must not include operations")
	}
}

func TestCacheManager_ClearSecurityCache(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.CacheSecurityItem("k", []byte("v"))

	cm.ClearSecurityCache()

	if _, ok := cm.GetSecurityItem("k"); ok {
		t.Error("expected miss after clear")
	}
}

func TestCacheManager_NilReceiverGuards(t *testing.T) {
	t.Parallel()

	var cm *CacheManager // typed nil: all methods must be safe no-ops

	cm.CacheSecurityItem("k", []byte("v"))
	cm.DeleteSecurityItem("k")
	cm.Shutdown()
	cm.ClearSecurityCache() // nil receiver: must be a safe no-op

	if _, ok := cm.GetSecurityItem("k"); ok {
		t.Error("nil cache must miss")
	}
}

func TestCacheManager_ShutdownDisabled(t *testing.T) {
	t.Parallel()

	cm := &CacheManager{enabled: false}
	cm.Shutdown() // must not panic with no janitor running
}

// ----- newCacheManagerFromConfig -----

func TestNewCacheManagerFromConfig_Disabled(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.Enabled = false

	cm := newCacheManagerFromConfig(cfg)

	if cm.enabled || cm.items != nil {
		t.Errorf("expected disabled no-op manager, got %+v", cm)
	}
}

func TestNewCacheManagerFromConfig_Enabled(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	cm := newCacheManagerFromConfig(cfg)
	t.Cleanup(cm.Shutdown)

	if !cm.enabled || cm.items == nil {
		t.Fatal("expected enabled manager with a live store")
	}

	if cm.securityTTL != 5*time.Minute {
		t.Errorf("securityTTL = %v", cm.securityTTL)
	}
}

func TestNewCacheManagerFromConfig_BadDurations(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.SecurityTTL = testBogusValue
	cfg.Cache.CleanupInterval = "also-bogus"

	cm := newCacheManagerFromConfig(cfg)
	t.Cleanup(cm.Shutdown)

	if cm.securityTTL != 5*time.Minute {
		t.Errorf("bad TTL must fall back to 5m, got %v", cm.securityTTL)
	}
}

func TestCacheManager_DeleteMissingKey(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.DeleteSecurityItem("never-existed") // absent: must not count

	if got := cm.stats.Deletes.Load(); got != 0 {
		t.Errorf("Deletes = %d, want 0 for missing key", got)
	}
}

func TestCacheManager_ShutdownIdempotent(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.Shutdown()
	cm.Shutdown() // CAS guard makes the second call a no-op
}
