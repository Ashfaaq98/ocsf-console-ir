package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

// Cache interface for threat intelligence caching
type Cache interface {
	Get(key string) (*ThreatIntelligence, bool)
	Set(key string, intel *ThreatIntelligence, ttl time.Duration)
	Delete(key string)
	Clear()
	Close() error
}

// MemoryCache implements in-memory caching with TTL
type MemoryCache struct {
	mu      sync.RWMutex
	data    map[string]CacheEntry
	maxSize int
	logger  *log.Logger
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(maxSize int, logger *log.Logger) *MemoryCache {
	if maxSize <= 0 {
		maxSize = 1000
	}
	
	cache := &MemoryCache{
		data:    make(map[string]CacheEntry),
		maxSize: maxSize,
		logger:  logger,
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Get retrieves an item from the cache
func (mc *MemoryCache) Get(key string) (*ThreatIntelligence, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	entry, exists := mc.data[key]
	if !exists {
		return nil, false
	}
	
	if time.Now().After(entry.Expiry) {
		// Expired entry, will be cleaned up later
		return nil, false
	}
	
	return entry.Data, true
}

// Set stores an item in the cache with TTL
func (mc *MemoryCache) Set(key string, intel *ThreatIntelligence, ttl time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	// Check if we need to evict entries
	if len(mc.data) >= mc.maxSize {
		mc.evictOldest()
	}
	
	mc.data[key] = CacheEntry{
		Data:   intel,
		Expiry: time.Now().Add(ttl),
	}
}

// Delete removes an item from the cache
func (mc *MemoryCache) Delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	delete(mc.data, key)
}

// Clear removes all items from the cache
func (mc *MemoryCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	mc.data = make(map[string]CacheEntry)
}

// Close shuts down the cache
func (mc *MemoryCache) Close() error {
	mc.Clear()
	return nil
}

// evictOldest removes the oldest entry (simple eviction policy)
func (mc *MemoryCache) evictOldest() {
	if len(mc.data) == 0 {
		return
	}
	
	var oldestKey string
	var oldestTime time.Time
	first := true
	
	for key, entry := range mc.data {
		if first || entry.Expiry.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Expiry
			first = false
		}
	}
	
	if oldestKey != "" {
		delete(mc.data, oldestKey)
	}
}

// cleanup periodically removes expired entries
func (mc *MemoryCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		mc.mu.Lock()
		now := time.Now()
		
		for key, entry := range mc.data {
			if now.After(entry.Expiry) {
				delete(mc.data, key)
			}
		}
		
		mc.mu.Unlock()
	}
}

// RedisCache implements Redis-based caching
type RedisCache struct {
	client *redis.Client
	prefix string
	logger *log.Logger
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(redisURL, prefix string, logger *log.Logger) (*RedisCache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	
	client := redis.NewClient(opts)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	
	if prefix == "" {
		prefix = "opencti:cache:"
	}
	
	return &RedisCache{
		client: client,
		prefix: prefix,
		logger: logger,
	}, nil
}

// Get retrieves an item from Redis cache
func (rc *RedisCache) Get(key string) (*ThreatIntelligence, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	redisKey := rc.prefix + key
	data, err := rc.client.Get(ctx, redisKey).Result()
	if err != nil {
		if err != redis.Nil {
			rc.logger.Printf("Redis cache get error for key %s: %v", key, err)
		}
		return nil, false
	}
	
	var intel ThreatIntelligence
	if err := json.Unmarshal([]byte(data), &intel); err != nil {
		rc.logger.Printf("Failed to unmarshal cached data for key %s: %v", key, err)
		// Delete corrupted entry
		rc.Delete(key)
		return nil, false
	}
	
	return &intel, true
}

// Set stores an item in Redis cache with TTL
func (rc *RedisCache) Set(key string, intel *ThreatIntelligence, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	data, err := json.Marshal(intel)
	if err != nil {
		rc.logger.Printf("Failed to marshal threat intelligence for caching: %v", err)
		return
	}
	
	redisKey := rc.prefix + key
	if err := rc.client.Set(ctx, redisKey, data, ttl).Err(); err != nil {
		rc.logger.Printf("Redis cache set error for key %s: %v", key, err)
	}
}

// Delete removes an item from Redis cache
func (rc *RedisCache) Delete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	redisKey := rc.prefix + key
	if err := rc.client.Del(ctx, redisKey).Err(); err != nil {
		rc.logger.Printf("Redis cache delete error for key %s: %v", key, err)
	}
}

// Clear removes all items from Redis cache (with prefix)
func (rc *RedisCache) Clear() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	pattern := rc.prefix + "*"
	keys, err := rc.client.Keys(ctx, pattern).Result()
	if err != nil {
		rc.logger.Printf("Redis cache clear error: %v", err)
		return
	}
	
	if len(keys) > 0 {
		if err := rc.client.Del(ctx, keys...).Err(); err != nil {
			rc.logger.Printf("Redis cache clear delete error: %v", err)
		}
	}
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

// CacheManager manages both memory and Redis caching
type CacheManager struct {
	primary   Cache
	fallback  Cache
	logger    *log.Logger
	
	// Metrics
	mu        sync.RWMutex
	hits      int64
	misses    int64
}

// NewCacheManager creates a new cache manager
func NewCacheManager(useRedis bool, redisURL string, cacheSize int, logger *log.Logger) (*CacheManager, error) {
	var primary, fallback Cache
	
	// Always create memory cache as fallback
	fallback = NewMemoryCache(cacheSize, logger)
	
	if useRedis && redisURL != "" {
		redisCache, err := NewRedisCache(redisURL, "opencti:cache:", logger)
		if err != nil {
			logger.Printf("Warning: Failed to create Redis cache, using memory cache only: %v", err)
			primary = fallback
			fallback = nil
		} else {
			primary = redisCache
		}
	} else {
		primary = fallback
		fallback = nil
	}
	
	return &CacheManager{
		primary:  primary,
		fallback: fallback,
		logger:   logger,
	}, nil
}

// Get retrieves an item from cache (tries primary, then fallback)
func (cm *CacheManager) Get(key string) (*ThreatIntelligence, bool) {
	// Try primary cache first
	if intel, found := cm.primary.Get(key); found {
		cm.recordHit()
		return intel, true
	}
	
	// Try fallback cache if available
	if cm.fallback != nil {
		if intel, found := cm.fallback.Get(key); found {
			cm.recordHit()
			// Store in primary cache for next time
			cm.primary.Set(key, intel, 1*time.Hour)
			return intel, true
		}
	}
	
	cm.recordMiss()
	return nil, false
}

// Set stores an item in both caches
func (cm *CacheManager) Set(key string, intel *ThreatIntelligence, ttl time.Duration) {
	cm.primary.Set(key, intel, ttl)
	if cm.fallback != nil {
		cm.fallback.Set(key, intel, ttl)
	}
}

// Delete removes an item from both caches
func (cm *CacheManager) Delete(key string) {
	cm.primary.Delete(key)
	if cm.fallback != nil {
		cm.fallback.Delete(key)
	}
}

// Clear removes all items from both caches
func (cm *CacheManager) Clear() {
	cm.primary.Clear()
	if cm.fallback != nil {
		cm.fallback.Clear()
	}
}

// Close shuts down both caches
func (cm *CacheManager) Close() error {
	var err error
	if cm.primary != nil {
		err = cm.primary.Close()
	}
	if cm.fallback != nil {
		if fallbackErr := cm.fallback.Close(); fallbackErr != nil && err == nil {
			err = fallbackErr
		}
	}
	return err
}

// GetStats returns cache statistics
func (cm *CacheManager) GetStats() (hits, misses int64, hitRatio float64) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	hits = cm.hits
	misses = cm.misses
	total := hits + misses
	
	if total > 0 {
		hitRatio = float64(hits) / float64(total)
	}
	
	return
}

// recordHit increments the cache hit counter
func (cm *CacheManager) recordHit() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.hits++
}

// recordMiss increments the cache miss counter
func (cm *CacheManager) recordMiss() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.misses++
}

// generateCacheKey creates a cache key for an observable
func generateCacheKey(observableType, value string) string {
	return fmt.Sprintf("%s:%s", observableType, value)
}