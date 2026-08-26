package main

import (
	"crypto/subtle"
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
	mu          sync.Mutex
	buckets     map[string]*bucket
	rate        float64 // tokens per second
	burst       float64
	proxySecret string // shared secret proving X-Forwarded-For came from our proxy
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute, burst float64, proxySecret string) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket), rate: perMinute / 60, burst: burst, proxySecret: proxySecret}
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
		if !rl.allow(clientIP(r, rl.proxySecret)) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP resolves the client's IP for rate-limiting. X-Forwarded-For is
// honored only when the request demonstrably came through our own proxy;
// otherwise the socket peer is used, so a client that reaches the listener
// directly cannot forge a fresh bucket per request by spoofing the header.
//
// With proxySecret set (recommended, and required on any host where another
// local process can reach the listener), XFF is trusted only when the proxy
// presents the matching X-GK-Proxy header. With it empty, we fall back to
// trusting a loopback peer — safe only on a single-tenant host.
func clientIP(r *http.Request, proxySecret string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if trustProxyHeaders(r, host, proxySecret) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}

func trustProxyHeaders(r *http.Request, host, proxySecret string) bool {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	if proxySecret == "" {
		return true // back-compat: loopback peer trusted, single-tenant only
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-GK-Proxy")), []byte(proxySecret)) == 1
}
