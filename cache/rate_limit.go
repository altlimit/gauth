package cache

import (
	"context"
	"fmt"
	"sync"
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
		Cache map[string]*CacheItem

		lock sync.Mutex
	}

	CacheItem struct {
		Value   interface{}
		Expires time.Time
	}
)

func (rle RateLimitError) Error() string {
	return fmt.Sprintf("Rate limit exceeded: %d requests in %s", rle.Rate.Rate, rle.Rate.Duration.String())
}

func NewMemoryRateLimit() *MemoryRateLimit {
	mrl := &MemoryRateLimit{
		Cache: make(map[string]*CacheItem),
	}
	// clears cache every 10 minute
	go func() {
		for {
			time.Sleep(time.Minute * 10)
			now := time.Now()
			mrl.lock.Lock()
			for k, v := range mrl.Cache {
				if v.Expires.Before(now) {
					delete(mrl.Cache, k)
				}
			}
			mrl.lock.Unlock()
		}
	}()
	return mrl
}

func (mrl *MemoryRateLimit) RateLimit(ctx context.Context, key string, rate int, t time.Duration) error {
	key = "rate:" + key
	mrl.lock.Lock()
	defer mrl.lock.Unlock()
	item, ok := mrl.Cache[key]
	now := time.Now()
	if !ok || item.Expires.Before(now) {
		item = &CacheItem{Value: 0, Expires: now.Add(t)}

	}
	val, ok := item.Value.(int)
	if ok {
		item.Value = val + 1
	}
	if val > rate {
		return RateLimitError{Rate: Rate{Rate: rate, Duration: t}}
	}
	mrl.Cache[key] = item
	return nil
}
