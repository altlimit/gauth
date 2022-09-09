package cache

import (
	"context"
	"fmt"
	"time"
)

type (
	// To enable rate limiting such as registration per IP, 2fa guessing etc,
	// by default it will use internal memory for rate limiting you can use distributed caching here
	RateLimiter interface {
		RateLimit(ctx context.Context, key string, rate int, t time.Duration) error
	}

	Rate struct {
		Rate     int
		Duration time.Duration
	}

	// RateLimitError info
	RateLimitError struct {
		Rate Rate
	}

	MemoryRateLimit struct {
		cache *LRUCache
	}
)

func (rle RateLimitError) Error() string {
	return fmt.Sprintf("Rate limit exceeded: %d requests in %s", rle.Rate.Rate, rle.Rate.Duration.String())
}

func NewMemoryRateLimit() *MemoryRateLimit {
	return &MemoryRateLimit{
		cache: NewLRUCache(1000),
	}
}

func (mrl *MemoryRateLimit) RateLimit(ctx context.Context, key string, rate int, t time.Duration) error {
	key = "rate:" + key
	var hits int
	cache, ok := mrl.cache.Get(key)
	if ok {
		hits, _ = cache.(int)
	}
	hits++
	if hits > rate {
		return RateLimitError{Rate: Rate{Rate: rate, Duration: t}}
	}
	mrl.cache.Put(key, hits, t)
	return nil
}
