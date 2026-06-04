package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// CacheManager is a small TTL cache for HTTP response bodies — currently just
// the /security/stats JSON. The authoritative security state (whitelist,
// blacklist, counters) lives in SecurityManager's maps; this is a best-effort
// response cache, so it is a plain mutex-guarded map with per-entry expiry
// rather than an external cache library.
type CacheManager struct {
	enabled     bool
	securityTTL time.Duration

	mu    sync.RWMutex
	items map[string]cacheItem

	// Lifecycle for the background expiry janitor.
	cancel context.CancelFunc
	closed atomic.Bool
	wg     sync.WaitGroup

	stats CacheStats
}

// cacheItem is a stored value with an optional expiry. A zero expires means the
// entry never expires.
type cacheItem struct {
	data    []byte
	expires time.Time
}

// CacheStats tracks cache statistics via atomic counters.
type CacheStats struct {
	Writes  atomic.Int64
	Reads   atomic.Int64
	Misses  atomic.Int64
	Deletes atomic.Int64
}

var (
	cacheManager     *CacheManager
	cacheManagerOnce sync.Once
)

// defaultCacheTTL is the fallback for the security TTL and cleanup interval
// when the configured values cannot be parsed.
const defaultCacheTTL = 5 * time.Minute

// newCacheManagerFromConfig builds a CacheManager from the given app config.
// Unparsable durations fall back to defaultCacheTTL; a disabled config yields a
// no-op manager.
func newCacheManagerFromConfig(cfg *AppConfig) *CacheManager {
	if !cfg.Cache.Enabled {
		log.Println("Cache is disabled in configuration")

		return &CacheManager{enabled: false}
	}

	securityTTL, err := time.ParseDuration(cfg.Cache.SecurityTTL)
	if err != nil {
		log.Printf("Error parsing security TTL, using default %s: %v", defaultCacheTTL, err)

		securityTTL = defaultCacheTTL
	}

	cleanupInterval, err := time.ParseDuration(cfg.Cache.CleanupInterval)
	if err != nil {
		log.Printf("Error parsing cleanup interval, using default %s: %v", defaultCacheTTL, err)

		cleanupInterval = defaultCacheTTL
	}

	ctx, cancel := context.WithCancel(context.Background())
	cm := &CacheManager{
		enabled:     true,
		securityTTL: securityTTL,
		items:       make(map[string]cacheItem),
		cancel:      cancel,
	}

	cm.wg.Add(1)
	go cm.janitor(ctx, cleanupInterval)

	log.Printf("Cache initialized - security TTL: %s", securityTTL)

	return cm
}

// InitCache initializes the cache manager.
func InitCache() error {
	cacheManagerOnce.Do(func() {
		cacheManager = newCacheManagerFromConfig(GetConfig())
	})

	if cacheManager != nil && cacheManager.enabled && cacheManager.items == nil {
		return ErrCacheInit
	}

	return nil
}

// CacheSecurityItem caches a value under key. It is safe to call concurrently.
// The data is copied, so the caller may reuse its buffer.
func (cm *CacheManager) CacheSecurityItem(key string, data []byte) {
	if cm == nil || !cm.enabled || cm.items == nil {
		return
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	var expires time.Time
	if cm.securityTTL > 0 {
		expires = time.Now().Add(cm.securityTTL)
	}

	cm.mu.Lock()
	cm.items[key] = cacheItem{data: buf, expires: expires}
	cm.mu.Unlock()

	cm.stats.Writes.Add(1)
}

// GetSecurityItem retrieves a value by key. Expired entries read as a miss.
func (cm *CacheManager) GetSecurityItem(key string) ([]byte, bool) {
	if cm == nil || !cm.enabled || cm.items == nil {
		return nil, false
	}

	cm.mu.RLock()
	item, ok := cm.items[key]
	cm.mu.RUnlock()

	if !ok || (!item.expires.IsZero() && item.expires.Before(time.Now())) {
		cm.stats.Misses.Add(1)

		return nil, false
	}

	cm.stats.Reads.Add(1)

	out := make([]byte, len(item.data))
	copy(out, item.data)

	return out, true
}

// DeleteSecurityItem removes a key. It is a no-op (and not counted) if absent.
func (cm *CacheManager) DeleteSecurityItem(key string) {
	if cm == nil || !cm.enabled || cm.items == nil {
		return
	}

	cm.mu.Lock()
	_, ok := cm.items[key]
	delete(cm.items, key)
	cm.mu.Unlock()

	if ok {
		cm.stats.Deletes.Add(1)
	}
}

// ClearSecurityCache drops every cached entry.
func (cm *CacheManager) ClearSecurityCache() {
	if cm == nil || !cm.enabled || cm.items == nil {
		return
	}

	cm.mu.Lock()
	cm.items = make(map[string]cacheItem)
	cm.mu.Unlock()
}

// GetCacheStats returns cache statistics.
func (cm *CacheManager) GetCacheStats() map[string]any {
	stats := map[string]any{"enabled": cm.enabled}
	if !cm.enabled {
		return stats
	}

	cm.mu.RLock()
	entries := len(cm.items)
	cm.mu.RUnlock()

	stats["security"] = map[string]any{
		"hits":    cm.stats.Reads.Load(),
		"misses":  cm.stats.Misses.Load(),
		"entries": entries,
		"ttl":     cm.securityTTL.String(),
	}

	stats["operations"] = map[string]any{
		"writes":  cm.stats.Writes.Load(),
		"reads":   cm.stats.Reads.Load(),
		"misses":  cm.stats.Misses.Load(),
		"deletes": cm.stats.Deletes.Load(),
	}

	return stats
}

// Shutdown stops the janitor. It is safe to call multiple times.
func (cm *CacheManager) Shutdown() {
	if cm == nil || !cm.enabled {
		return
	}

	if !cm.closed.CompareAndSwap(false, true) {
		return
	}

	if cm.cancel != nil {
		cm.cancel()
	}

	cm.wg.Wait()
}

// janitor periodically purges expired entries until the context is canceled.
func (cm *CacheManager) janitor(ctx context.Context, interval time.Duration) {
	defer cm.wg.Done()

	if interval <= 0 {
		interval = defaultCacheTTL
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.purgeExpired()
		}
	}
}

// purgeExpired removes entries whose expiry has passed.
func (cm *CacheManager) purgeExpired() {
	now := time.Now()

	cm.mu.Lock()
	for key, item := range cm.items {
		if !item.expires.IsZero() && item.expires.Before(now) {
			delete(cm.items, key)
		}
	}
	cm.mu.Unlock()
}

// GetCacheManager returns the cache manager instance, initializing it on first call.
func GetCacheManager() *CacheManager {
	if cacheManager == nil {
		err := InitCache()
		if err != nil {
			log.Printf("Error initializing cache: %v", err)
		}
	}

	return cacheManager
}

// CloseCache shuts down the global cache manager.
func CloseCache() {
	if cacheManager != nil {
		cacheManager.Shutdown()
	}
}
