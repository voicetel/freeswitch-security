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
	bc, err := bigcache.New(context.Background(), cfg) //nolint:usetesting // see comment
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

	if err := cm.ClearSecurityCache(); err != nil {
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
