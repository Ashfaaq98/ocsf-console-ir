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

// Cache interface
type Cache interface {
	Get(key string) (*IntelOwlResult, bool)
	Set(key string, intel *IntelOwlResult, ttl time.Duration)
	Delete(key string)
	Clear()
	Close() error
}

// CacheEntry holds value and expiry for memory cache
type CacheEntry struct {
	Data   *IntelOwlResult
	Expiry time.Time
}

// MemoryCache implements in-memory caching with TTL and simple eviction
type MemoryCache struct {
	mu      sync.RWMutex
	data    map[string]CacheEntry
	maxSize int
	logger  *log.Logger
}

func NewMemoryCache(maxSize int, logger *log.Logger) *MemoryCache {
	if maxSize <= 0 {
		maxSize = 1000
	}
	mc := &MemoryCache{
		data:    make(map[string]CacheEntry),
		maxSize: maxSize,
		logger:  logger,
	}
	go mc.cleanup()
	return mc
}

func (mc *MemoryCache) Get(key string) (*IntelOwlResult, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	entry, ok := mc.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.Expiry) {
		return nil, false
	}
	return entry.Data, true
}

func (mc *MemoryCache) Set(key string, intel *IntelOwlResult, ttl time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if len(mc.data) >= mc.maxSize {
		mc.evictOldest()
	}
	mc.data[key] = CacheEntry{
		Data:   intel,
		Expiry: time.Now().Add(ttl),
	}
}

func (mc *MemoryCache) Delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	delete(mc.data, key)
}

func (mc *MemoryCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.data = make(map[string]CacheEntry)
}

func (mc *MemoryCache) Close() error {
	mc.Clear()
	return nil
}

func (mc *MemoryCache) evictOldest() {
	if len(mc.data) == 0 {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, v := range mc.data {
		if first || v.Expiry.Before(oldest) {
			oldestKey = k
			oldest = v.Expiry
			first = false
		}
	}
	if oldestKey != "" {
		delete(mc.data, oldestKey)
	}
}

func (mc *MemoryCache) cleanup() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		mc.mu.Lock()
		now := time.Now()
		for k, v := range mc.data {
			if now.After(v.Expiry) {
				delete(mc.data, k)
			}
		}
		mc.mu.Unlock()
	}
}

// RedisCache implements Redis-based cache
type RedisCache struct {
	client *redis.Client
	prefix string
	logger *log.Logger
}

func NewRedisCache(redisURL, prefix string, logger *log.Logger) (*RedisCache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	c := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	if prefix == "" {
		prefix = "intelowl:cache:"
	}
	return &RedisCache{client: c, prefix: prefix, logger: logger}, nil
}

func (rc *RedisCache) Get(key string) (*IntelOwlResult, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := rc.client.Get(ctx, rc.prefix+key).Result()
	if err != nil {
		if err != redis.Nil {
			rc.logger.Printf("Redis get error for %s: %v", key, err)
		}
		return nil, false
	}
	var res IntelOwlResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		rc.logger.Printf("Redis unmarshal error for %s: %v", key, err)
		_ = rc.client.Del(ctx, rc.prefix+key).Err()
		return nil, false
	}
	return &res, true
}

func (rc *RedisCache) Set(key string, intel *IntelOwlResult, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := json.Marshal(intel)
	if err != nil {
		rc.logger.Printf("Redis marshal error: %v", err)
		return
	}
	if err := rc.client.Set(ctx, rc.prefix+key, b, ttl).Err(); err != nil {
		rc.logger.Printf("Redis set error for %s: %v", key, err)
	}
}

func (rc *RedisCache) Delete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rc.client.Del(ctx, rc.prefix+key).Err(); err != nil {
		rc.logger.Printf("Redis del error for %s: %v", key, err)
	}
}

func (rc *RedisCache) Clear() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := rc.client.Keys(ctx, rc.prefix+"*").Result()
	if err != nil {
		rc.logger.Printf("Redis keys error: %v", err)
		return
	}
	if len(keys) > 0 {
		if err := rc.client.Del(ctx, keys...).Err(); err != nil {
			rc.logger.Printf("Redis clear error: %v", err)
		}
	}
}

func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

// CacheManager coordinates primary and fallback caches
type CacheManager struct {
	primary  Cache
	fallback Cache
	logger   *log.Logger

	mu      sync.RWMutex
	hits    int64
	misses  int64
}

func NewCacheManager(useRedis bool, redisURL string, size int, logger *log.Logger) (*CacheManager, error) {
	var primary, fallback Cache
	fallback = NewMemoryCache(size, logger)
	if useRedis && redisURL != "" {
		rc, err := NewRedisCache(redisURL, "intelowl:cache:", logger)
		if err != nil {
			logger.Printf("Redis cache unavailable, falling back to memory: %v", err)
			primary = fallback
			fallback = nil
		} else {
			primary = rc
		}
	} else {
		primary = fallback
		fallback = nil
	}
	return &CacheManager{primary: primary, fallback: fallback, logger: logger}, nil
}

func (cm *CacheManager) Get(key string) (*IntelOwlResult, bool) {
	if v, ok := cm.primary.Get(key); ok {
		cm.recordHit()
		return v, true
	}
	if cm.fallback != nil {
		if v, ok := cm.fallback.Get(key); ok {
			cm.recordHit()
			cm.primary.Set(key, v, 1*time.Hour)
			return v, true
		}
	}
	cm.recordMiss()
	return nil, false
}

func (cm *CacheManager) Set(key string, intel *IntelOwlResult, ttl time.Duration) {
	cm.primary.Set(key, intel, ttl)
	if cm.fallback != nil {
		cm.fallback.Set(key, intel, ttl)
	}
}

func (cm *CacheManager) Delete(key string) {
	cm.primary.Delete(key)
	if cm.fallback != nil {
		cm.fallback.Delete(key)
	}
}

func (cm *CacheManager) Clear() {
	cm.primary.Clear()
	if cm.fallback != nil {
		cm.fallback.Clear()
	}
}

func (cm *CacheManager) Close() error {
	var err error
	if cm.primary != nil {
		err = cm.primary.Close()
	}
	if cm.fallback != nil {
		if e := cm.fallback.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (cm *CacheManager) recordHit() {
	cm.mu.Lock()
	cm.hits++
	cm.mu.Unlock()
}

func (cm *CacheManager) recordMiss() {
	cm.mu.Lock()
	cm.misses++
	cm.mu.Unlock()
}

func (cm *CacheManager) GetStats() (hits, misses int64, ratio float64) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	hits = cm.hits
	misses = cm.misses
	total := hits + misses
	if total > 0 {
		ratio = float64(hits) / float64(total)
	}
	return
}

// generateCacheKey helpers
func generateCacheKey(observableType, value string) string {
	return fmt.Sprintf("%s:%s", observableType, value)
}