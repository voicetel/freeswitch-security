package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/allegro/bigcache/v3"
)

// CacheManager handles caching operations
type CacheManager struct {
	securityCache *bigcache.BigCache
	enabled       bool
	securityTTL   time.Duration
	mutex         sync.RWMutex
}

var (
	cacheManager     *CacheManager
	cacheManagerOnce sync.Once
)

// InitCache initializes the cache manager
func InitCache() error {
	var err error
	cacheManagerOnce.Do(func() {
		config := GetConfig()
		if !config.Cache.Enabled {
			log.Println("Cache is disabled in configuration")
			cacheManager = &CacheManager{
				enabled: false,
			}
			return
		}

		// Parse TTL durations from config
		securityTTL, err := time.ParseDuration(config.Cache.SecurityTTL)
		if err != nil {
			log.Printf("Error parsing security TTL, using default 5m: %v", err)
			securityTTL = 5 * time.Minute
		}

		cleanupInterval, err := time.ParseDuration(config.Cache.CleanupInterval)
		if err != nil {
			log.Printf("Error parsing cleanup interval, using default 5m: %v", err)
			cleanupInterval = 5 * time.Minute
		}

		// Create security cache
		secCacheConfig := bigcache.DefaultConfig(securityTTL)
		secCacheConfig.CleanWindow = cleanupInterval
		secCacheConfig.MaxEntriesInWindow = config.Cache.MaxEntriesInWindow
		secCacheConfig.MaxEntrySize = config.Cache.MaxEntrySize
		secCacheConfig.Shards = config.Cache.ShardCount
		secCacheConfig.Verbose = config.Server.LogRequests // Use request logging as verbosity indicator

		secCache, err := bigcache.New(context.Background(), secCacheConfig)
		if err != nil {
			log.Printf("Error initializing security cache: %v", err)
			return
		}

		cacheManager = &CacheManager{
			securityCache: secCache,
			enabled:       true,
			securityTTL:   securityTTL,
		}

		log.Printf("Cache initialized - Security TTL: %s", securityTTL.String())
	})

	if cacheManager.enabled && cacheManager.securityCache == nil {
		return fmt.Errorf("failed to initialize cache")
	}

	return err
}

// GetCacheManager returns the cache manager instance
func GetCacheManager() *CacheManager {
	if cacheManager == nil {
		if err := InitCache(); err != nil {
			log.Printf("Error initializing cache: %v", err)
		}
	}
	return cacheManager
}

// CloseCache closes the cache manager
func CloseCache() {
	if cacheManager != nil && cacheManager.enabled {
		if cacheManager.securityCache != nil {
			cacheManager.securityCache.Close()
		}
		log.Println("Cache closed")
	}
}

// CacheSecurityItem caches security item by key
func (cm *CacheManager) CacheSecurityItem(key string, data []byte) error {
	if !cm.enabled || cm.securityCache == nil {
		return nil
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	return cm.securityCache.Set(key, data)
}

// GetSecurityItem retrieves security item by key
func (cm *CacheManager) GetSecurityItem(key string) ([]byte, bool) {
	if !cm.enabled || cm.securityCache == nil {
		return nil, false
	}

	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	data, err := cm.securityCache.Get(key)
	if err != nil {
		return nil, false
	}
	return data, true
}

// ClearSecurityCache clears the security cache
func (cm *CacheManager) ClearSecurityCache() error {
	if !cm.enabled || cm.securityCache == nil {
		return nil
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	return cm.securityCache.Reset()
}

// GetCacheStats returns cache statistics
func (cm *CacheManager) GetCacheStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled": cm.enabled,
	}

	if !cm.enabled {
		return stats
	}

	if cm.securityCache != nil {
		secStats := cm.securityCache.Stats()
		stats["security"] = map[string]interface{}{
			"hits":       secStats.Hits,
			"misses":     secStats.Misses,
			"collisions": secStats.Collisions,
			"del_hits":   secStats.DelHits,
			"del_misses": secStats.DelMisses,
			"ttl":        cm.securityTTL.String(),
		}
	}

	return stats
}
