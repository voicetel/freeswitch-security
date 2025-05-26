package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/allegro/bigcache/v3"
)

// CacheManager handles caching operations
type CacheManager struct {
	securityCache *bigcache.BigCache
	enabled       bool
	securityTTL   time.Duration
	mutex         sync.RWMutex

	// Channel-based write operations
	writeQueue  chan CacheWriteRequest
	deleteQueue chan CacheDeleteRequest

	// Statistics
	stats CacheStats

	// Shutdown mechanism
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// CacheWriteRequest represents a cache write operation
type CacheWriteRequest struct {
	Key      string
	Value    []byte
	Response chan error
}

// CacheDeleteRequest represents a cache delete operation
type CacheDeleteRequest struct {
	Key      string
	Response chan error
}

// CacheStats tracks cache statistics
type CacheStats struct {
	Writes        int64
	Reads         int64
	Deletes       int64
	WriteErrors   int64
	ReadErrors    int64
	DeleteErrors  int64
	QueuedWrites  int64
	QueuedDeletes int64
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
		secCacheConfig.Verbose = config.Server.LogRequests

		secCache, err := bigcache.New(context.Background(), secCacheConfig)
		if err != nil {
			log.Printf("Error initializing security cache: %v", err)
			return
		}

		// Create context for shutdown
		ctx, cancel := context.WithCancel(context.Background())

		cacheManager = &CacheManager{
			securityCache: secCache,
			enabled:       true,
			securityTTL:   securityTTL,
			writeQueue:    make(chan CacheWriteRequest, 1000),
			deleteQueue:   make(chan CacheDeleteRequest, 500),
			ctx:           ctx,
			cancel:        cancel,
		}

		// Start worker goroutines
		cacheManager.wg.Add(2)
		go cacheManager.processWriteQueue()
		go cacheManager.processDeleteQueue()

		log.Printf("Cache initialized with channel-based operations - Security TTL: %s", securityTTL.String())
	})

	if cacheManager.enabled && cacheManager.securityCache == nil {
		return fmt.Errorf("failed to initialize cache")
	}

	return err
}

// processWriteQueue handles batched cache writes
func (cm *CacheManager) processWriteQueue() {
	defer cm.wg.Done()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]CacheWriteRequest, 0, 50)

	for {
		select {
		case <-cm.ctx.Done():
			// Process any remaining items
			cm.processBatchWrites(batch)
			return

		case req := <-cm.writeQueue:
			batch = append(batch, req)
			atomic.AddInt64(&cm.stats.QueuedWrites, 1)

			// Process batch if it's full
			if len(batch) >= 50 {
				cm.processBatchWrites(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Process any pending items
			if len(batch) > 0 {
				cm.processBatchWrites(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchWrites processes a batch of cache writes
func (cm *CacheManager) processBatchWrites(batch []CacheWriteRequest) {
	if len(batch) == 0 {
		return
	}

	// Group writes by shard for better performance
	for _, req := range batch {
		err := cm.securityCache.Set(req.Key, req.Value)

		if err != nil {
			atomic.AddInt64(&cm.stats.WriteErrors, 1)
		} else {
			atomic.AddInt64(&cm.stats.Writes, 1)
		}

		// Send response if requested
		if req.Response != nil {
			select {
			case req.Response <- err:
			case <-time.After(10 * time.Millisecond):
				// Timeout sending response
			}
		}
	}
}

// processDeleteQueue handles batched cache deletes
func (cm *CacheManager) processDeleteQueue() {
	defer cm.wg.Done()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]CacheDeleteRequest, 0, 20)

	for {
		select {
		case <-cm.ctx.Done():
			// Process any remaining items
			cm.processBatchDeletes(batch)
			return

		case req := <-cm.deleteQueue:
			batch = append(batch, req)
			atomic.AddInt64(&cm.stats.QueuedDeletes, 1)

			// Process batch if it's full
			if len(batch) >= 20 {
				cm.processBatchDeletes(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Process any pending items
			if len(batch) > 0 {
				cm.processBatchDeletes(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatchDeletes processes a batch of cache deletes
func (cm *CacheManager) processBatchDeletes(batch []CacheDeleteRequest) {
	if len(batch) == 0 {
		return
	}

	for _, req := range batch {
		err := cm.securityCache.Delete(req.Key)

		if err != nil {
			atomic.AddInt64(&cm.stats.DeleteErrors, 1)
		} else {
			atomic.AddInt64(&cm.stats.Deletes, 1)
		}

		// Send response if requested
		if req.Response != nil {
			select {
			case req.Response <- err:
			case <-time.After(10 * time.Millisecond):
				// Timeout sending response
			}
		}
	}
}

// CacheSecurityItemAsync caches security item asynchronously
func (cm *CacheManager) CacheSecurityItemAsync(key string, data []byte) {
	if !cm.enabled || cm.securityCache == nil {
		return
	}

	select {
	case cm.writeQueue <- CacheWriteRequest{
		Key:      key,
		Value:    data,
		Response: nil, // Fire and forget
	}:
		// Queued successfully
	case <-time.After(10 * time.Millisecond):
		// Queue is full, fall back to synchronous write
		cm.CacheSecurityItem(key, data)
	}
}

// CacheSecurityItem caches security item synchronously (for compatibility)
func (cm *CacheManager) CacheSecurityItem(key string, data []byte) error {
	if !cm.enabled || cm.securityCache == nil {
		return nil
	}

	respChan := make(chan error, 1)

	select {
	case cm.writeQueue <- CacheWriteRequest{
		Key:      key,
		Value:    data,
		Response: respChan,
	}:
		select {
		case err := <-respChan:
			return err
		case <-time.After(100 * time.Millisecond):
			// Timeout waiting for response
			return fmt.Errorf("cache write timeout")
		}
	case <-time.After(100 * time.Millisecond):
		// Timeout queueing request, write directly
		cm.mutex.Lock()
		defer cm.mutex.Unlock()
		err := cm.securityCache.Set(key, data)
		if err != nil {
			atomic.AddInt64(&cm.stats.WriteErrors, 1)
		} else {
			atomic.AddInt64(&cm.stats.Writes, 1)
		}
		return err
	}
}

// GetSecurityItem retrieves security item by key (reads are still synchronous for low latency)
func (cm *CacheManager) GetSecurityItem(key string) ([]byte, bool) {
	if !cm.enabled || cm.securityCache == nil {
		return nil, false
	}

	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	data, err := cm.securityCache.Get(key)
	if err != nil {
		atomic.AddInt64(&cm.stats.ReadErrors, 1)
		return nil, false
	}

	atomic.AddInt64(&cm.stats.Reads, 1)
	return data, true
}

// DeleteSecurityItemAsync deletes a security item asynchronously
func (cm *CacheManager) DeleteSecurityItemAsync(key string) {
	if !cm.enabled || cm.securityCache == nil {
		return
	}

	select {
	case cm.deleteQueue <- CacheDeleteRequest{
		Key:      key,
		Response: nil, // Fire and forget
	}:
		// Queued successfully
	case <-time.After(10 * time.Millisecond):
		// Queue is full, delete directly
		cm.mutex.Lock()
		err := cm.securityCache.Delete(key)
		cm.mutex.Unlock()

		if err != nil {
			atomic.AddInt64(&cm.stats.DeleteErrors, 1)
		} else {
			atomic.AddInt64(&cm.stats.Deletes, 1)
		}
	}
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

	// Add channel-based statistics
	stats["operations"] = map[string]interface{}{
		"writes":           atomic.LoadInt64(&cm.stats.Writes),
		"reads":            atomic.LoadInt64(&cm.stats.Reads),
		"deletes":          atomic.LoadInt64(&cm.stats.Deletes),
		"write_errors":     atomic.LoadInt64(&cm.stats.WriteErrors),
		"read_errors":      atomic.LoadInt64(&cm.stats.ReadErrors),
		"delete_errors":    atomic.LoadInt64(&cm.stats.DeleteErrors),
		"queued_writes":    atomic.LoadInt64(&cm.stats.QueuedWrites),
		"queued_deletes":   atomic.LoadInt64(&cm.stats.QueuedDeletes),
		"write_queue_len":  len(cm.writeQueue),
		"delete_queue_len": len(cm.deleteQueue),
	}

	return stats
}

// Shutdown gracefully shuts down the cache manager
func (cm *CacheManager) Shutdown() {
	if !cm.enabled {
		return
	}

	log.Println("Shutting down cache manager...")

	// Cancel context to signal shutdown
	cm.cancel()

	// Wait for workers to finish processing
	done := make(chan bool)
	go func() {
		cm.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		log.Println("Cache workers finished processing")
	case <-time.After(5 * time.Second):
		log.Println("Warning: Cache workers shutdown timeout")
	}

	// Close the cache
	if cm.securityCache != nil {
		err := cm.securityCache.Close()
		if err != nil {
			log.Printf("Error closing cache: %v", err)
		}
	}

	log.Println("Cache manager shutdown complete")
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
		cacheManager.Shutdown()
	}
}
