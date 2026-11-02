package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = now

	// Check if we have enough tokens
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}

	return false
}

// AllowN checks if N requests are allowed
func (rl *RateLimiter) AllowN(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = now

	if rl.tokens >= float64(n) {
		rl.tokens -= float64(n)
		return true
	}

	return false
}

// Wait blocks until a request is allowed
func (rl *RateLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(100 * time.Millisecond)
	}
}

// Tokens returns the current number of tokens
func (rl *RateLimiter) Tokens() float64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.tokens
}

// RateLimitMiddleware creates an HTTP middleware for rate limiting
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Rate limit exceeded", 429)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPRateLimiter manages rate limiters per IP
type IPRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.Mutex
	rate     float64
	burst    int
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(rate float64, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*RateLimiter),
		rate:     rate,
		burst:    burst,
	}
}

// GetLimiter returns the rate limiter for an IP
func (irl *IPRateLimiter) GetLimiter(ip string) *RateLimiter {
	irl.mu.Lock()
	defer irl.mu.Unlock()

	limiter, exists := irl.limiters[ip]
	if !exists {
		limiter = NewRateLimiter(irl.rate, irl.burst)
		irl.limiters[ip] = limiter
	}

	return limiter
}

// Allow checks if a request from an IP is allowed
func (irl *IPRateLimiter) Allow(ip string) bool {
	return irl.GetLimiter(ip).Allow()
}

// Cleanup removes stale limiters
func (irl *IPRateLimiter) Cleanup(maxAge time.Duration) {
	irl.mu.Lock()
	defer irl.mu.Unlock()

	// In a real implementation, track last access time
	// For now, just clear all if too many
	if len(irl.limiters) > 1000 {
		irl.limiters = make(map[string]*RateLimiter)
	}
}
