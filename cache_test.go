package main

import (
	"context"
	"testing"
	"time"

	"github.com/allegro/bigcache/v3"
)

// newTestCacheManager builds an isolated, enabled cache for tests.
func newTestCacheManager(tb testing.TB) *CacheManager {
	tb.Helper()

	cfg := bigcache.DefaultConfig(time.Minute)
	cfg.CleanWindow = time.Minute
	cfg.MaxEntriesInWindow = 1000
	cfg.MaxEntrySize = 256
	cfg.Shards = 16
	cfg.Verbose = false

	// Use context.Background here rather than tb.Context() — bigcache's cleanup
	// goroutine emits a log line when its context is canceled, which would
	// pollute benchmark output. We close the cache via cm.Shutdown in Cleanup
	// instead, which terminates the goroutine cleanly.
	bc, err := bigcache.New(context.Background(), cfg)
	if err != nil {
		tb.Fatalf("bigcache.New: %v", err)
	}

	cm := &CacheManager{
		cache:       bc,
		enabled:     true,
		securityTTL: time.Minute,
	}
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

	err := cm.ClearSecurityCache()
	if err != nil {
		t.Errorf("ClearSecurityCache on disabled cache: %v", err)
	}
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

	err := cm.ClearSecurityCache()
	if err != nil {
		t.Fatalf("ClearSecurityCache: %v", err)
	}

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

	if _, ok := cm.GetSecurityItem("k"); ok {
		t.Error("nil cache must miss")
	}

	err := cm.ClearSecurityCache()
	if err != nil {
		t.Errorf("nil cache clear: %v", err)
	}
}

func TestCacheManager_ShutdownDisabled(t *testing.T) {
	t.Parallel()

	cm := &CacheManager{enabled: false}
	cm.Shutdown() // must not panic with nil inner cache
}

// ----- newCacheManagerFromConfig -----

func TestNewCacheManagerFromConfig_Disabled(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.Enabled = false

	cm, err := newCacheManagerFromConfig(cfg)
	if err != nil {
		t.Fatalf("newCacheManagerFromConfig: %v", err)
	}

	if cm.enabled || cm.cache != nil {
		t.Errorf("expected disabled no-op manager, got %+v", cm)
	}
}

func TestNewCacheManagerFromConfig_Enabled(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.ShardCount = 16
	cfg.Server.LogRequests = false

	cm, err := newCacheManagerFromConfig(cfg)
	if err != nil {
		t.Fatalf("newCacheManagerFromConfig: %v", err)
	}

	t.Cleanup(cm.Shutdown)

	if !cm.enabled || cm.cache == nil {
		t.Fatal("expected enabled manager with live cache")
	}

	if cm.securityTTL != 5*time.Minute {
		t.Errorf("securityTTL = %v", cm.securityTTL)
	}
}

func TestNewCacheManagerFromConfig_BadDurations(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.ShardCount = 16
	cfg.Cache.SecurityTTL = testBogusValue
	cfg.Cache.CleanupInterval = "also-bogus"

	cm, err := newCacheManagerFromConfig(cfg)
	if err != nil {
		t.Fatalf("newCacheManagerFromConfig: %v", err)
	}

	t.Cleanup(cm.Shutdown)

	if cm.securityTTL != 5*time.Minute {
		t.Errorf("bad TTL must fall back to 5m, got %v", cm.securityTTL)
	}
}

func TestNewCacheManagerFromConfig_BigcacheError(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Cache.ShardCount = 3 // bigcache requires a power of two

	_, err := newCacheManagerFromConfig(cfg)
	if err == nil {
		t.Error("expected bigcache init error for non-power-of-two shard count")
	}
}

// TestCacheManager_WriteError forces a bigcache Set failure (entry larger
// than a shard) and verifies the error branch updates WriteErrors.
func TestCacheManager_WriteError(t *testing.T) {
	t.Parallel()

	cfg := bigcache.DefaultConfig(time.Minute)
	cfg.Shards = 2
	cfg.HardMaxCacheSize = 1 // MB; each shard caps at 512 KiB
	cfg.Verbose = false

	bc, err := bigcache.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bigcache.New: %v", err)
	}

	cm := &CacheManager{cache: bc, enabled: true, securityTTL: time.Minute}
	t.Cleanup(cm.Shutdown)

	huge := make([]byte, 1<<20) // 1 MiB entry cannot fit a 512 KiB shard
	cm.CacheSecurityItem("too-big", huge)

	if got := cm.stats.WriteErrors.Load(); got != 1 {
		t.Errorf("WriteErrors = %d, want 1", got)
	}
}

func TestCacheManager_DeleteMissingKey(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.DeleteSecurityItem("never-existed") // NotFound: not an error

	if got := cm.stats.Deletes.Load(); got != 0 {
		t.Errorf("Deletes = %d, want 0 for missing key", got)
	}

	if got := cm.stats.DeleteErrors.Load(); got != 0 {
		t.Errorf("DeleteErrors = %d, want 0 for NotFound", got)
	}
}

func TestCacheManager_ShutdownIdempotent(t *testing.T) {
	t.Parallel()
	cm := newTestCacheManager(t)

	cm.Shutdown()
	cm.Shutdown() // CAS guard: bigcache panics on double Close without it
}
