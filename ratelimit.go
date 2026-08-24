package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Token-bucket limiter per client IP, for the unauthenticated auth endpoints
// (login, register, recover). Authenticated endpoints don't need it: a valid
// session is already proof of a passkey ceremony.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute, burst float64) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket), rate: perMinute / 60, burst: burst}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	// opportunistic cleanup so the map can't grow unboundedly
	if len(rl.buckets) > 10000 {
		for k, b := range rl.buckets {
			if b.tokens >= rl.burst {
				delete(rl.buckets, k)
			}
		}
	}
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	b.tokens = min(rl.burst, b.tokens+now.Sub(b.last).Seconds()*rl.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP trusts X-Forwarded-For only when the direct peer is loopback,
// i.e. the Caddy proxy on the same host. Anything else uses the socket peer.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}
