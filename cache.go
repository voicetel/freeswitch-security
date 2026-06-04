package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/allegro/bigcache/v3"
)

// CacheManager wraps a bigcache.BigCache instance.
//
// bigcache is already thread-safe with sharded internal locks, so this type
// adds nothing beyond a no-op when caching is disabled and a small statistics
// surface for observability.
type CacheManager struct {
	cache       *bigcache.BigCache
	enabled     bool
	securityTTL time.Duration

	// closed makes Shutdown idempotent: bigcache panics on a second Close.
	closed atomic.Bool

	// Statistics. All fields are accessed via atomic operations.
	stats CacheStats
}

// CacheStats tracks cache statistics.
type CacheStats struct {
	Writes       atomic.Int64
	Reads        atomic.Int64
	Deletes      atomic.Int64
	WriteErrors  atomic.Int64
	ReadErrors   atomic.Int64
	DeleteErrors atomic.Int64
}

var (
	cacheManager     *CacheManager
	cacheManagerOnce sync.Once
)

// newCacheManagerFromConfig builds a CacheManager from the given app config.
// Unparsable durations fall back to 5 minutes; a disabled config yields a
// no-op manager and no error.
func newCacheManagerFromConfig(cfg *AppConfig) (*CacheManager, error) {
	if !cfg.Cache.Enabled {
		log.Println("Cache is disabled in configuration")

		return &CacheManager{enabled: false}, nil
	}

	securityTTL, err := time.ParseDuration(cfg.Cache.SecurityTTL)
	if err != nil {
		log.Printf("Error parsing security TTL, using default 5m: %v", err)

		securityTTL = 5 * time.Minute
	}

	cleanupInterval, err := time.ParseDuration(cfg.Cache.CleanupInterval)
	if err != nil {
		log.Printf("Error parsing cleanup interval, using default 5m: %v", err)

		cleanupInterval = 5 * time.Minute
	}

	bcCfg := bigcache.DefaultConfig(securityTTL)
	bcCfg.CleanWindow = cleanupInterval
	bcCfg.MaxEntriesInWindow = cfg.Cache.MaxEntriesInWindow
	bcCfg.MaxEntrySize = cfg.Cache.MaxEntrySize
	bcCfg.Shards = cfg.Cache.ShardCount
	bcCfg.Verbose = cfg.Server.LogRequests

	bc, err := bigcache.New(context.Background(), bcCfg)
	if err != nil {
		log.Printf("Error initializing security cache: %v", err)

		return nil, fmt.Errorf("initializing bigcache: %w", err)
	}

	log.Printf("Cache initialized - security TTL: %s", securityTTL)

	return &CacheManager{
		cache:       bc,
		enabled:     true,
		securityTTL: securityTTL,
	}, nil
}

// InitCache initializes the cache manager.
func InitCache() error {
	var initErr error

	cacheManagerOnce.Do(func() {
		cacheManager, initErr = newCacheManagerFromConfig(GetConfig())
	})

	if cacheManager != nil && cacheManager.enabled && cacheManager.cache == nil {
		return ErrCacheInit
	}

	return initErr
}

// CacheSecurityItem caches a security item. It is safe to call concurrently.
// Errors are logged but not returned because the cache is best-effort.
func (cm *CacheManager) CacheSecurityItem(key string, data []byte) {
	if cm == nil || !cm.enabled || cm.cache == nil {
		return
	}

	err := cm.cache.Set(key, data)
	if err != nil {
		cm.stats.WriteErrors.Add(1)
		GetLogger().Error("cache set %q: %v", key, err)

		return
	}

	cm.stats.Writes.Add(1)
}

// GetSecurityItem retrieves a security item by key.
func (cm *CacheManager) GetSecurityItem(key string) ([]byte, bool) {
	if cm == nil || !cm.enabled || cm.cache == nil {
		return nil, false
	}

	data, err := cm.cache.Get(key)
	if err != nil {
		// bigcache returns ErrEntryNotFound on miss; that's not an error.
		if !errors.Is(err, bigcache.ErrEntryNotFound) {
			cm.stats.ReadErrors.Add(1)
		}

		return nil, false
	}

	cm.stats.Reads.Add(1)

	return data, true
}

// DeleteSecurityItem deletes a security item.
func (cm *CacheManager) DeleteSecurityItem(key string) {
	if cm == nil || !cm.enabled || cm.cache == nil {
		return
	}

	err := cm.cache.Delete(key)
	if err != nil {
		if !errors.Is(err, bigcache.ErrEntryNotFound) {
			cm.stats.DeleteErrors.Add(1)
		}

		return
	}

	cm.stats.Deletes.Add(1)
}

// ClearSecurityCache clears the security cache.
func (cm *CacheManager) ClearSecurityCache() error {
	if cm == nil || !cm.enabled || cm.cache == nil {
		return nil
	}

	err := cm.cache.Reset()
	if err != nil {
		return fmt.Errorf("bigcache reset: %w", err)
	}

	return nil
}

// GetCacheStats returns cache statistics.
func (cm *CacheManager) GetCacheStats() map[string]any {
	stats := map[string]any{"enabled": cm.enabled}
	if !cm.enabled {
		return stats
	}

	if cm.cache != nil {
		bc := cm.cache.Stats()
		stats["security"] = map[string]any{
			"hits":       bc.Hits,
			"misses":     bc.Misses,
			"collisions": bc.Collisions,
			"del_hits":   bc.DelHits,
			"del_misses": bc.DelMisses,
			"ttl":        cm.securityTTL.String(),
		}
	}

	stats["operations"] = map[string]any{
		"writes":        cm.stats.Writes.Load(),
		"reads":         cm.stats.Reads.Load(),
		"deletes":       cm.stats.Deletes.Load(),
		"write_errors":  cm.stats.WriteErrors.Load(),
		"read_errors":   cm.stats.ReadErrors.Load(),
		"delete_errors": cm.stats.DeleteErrors.Load(),
	}

	return stats
}

// Shutdown closes the underlying cache. It is safe to call multiple times.
func (cm *CacheManager) Shutdown() {
	if cm == nil || !cm.enabled || cm.cache == nil {
		return
	}

	if !cm.closed.CompareAndSwap(false, true) {
		return
	}

	err := cm.cache.Close()
	if err != nil {
		log.Printf("Error closing cache: %v", err)
	}
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
