// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package httpx contains HTTP middleware shared by Central's listeners: request IDs, panic
// recovery, trusted-proxy client IP resolution, security headers, body limits and access logs.
package httpx

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Shaalan15/central/server/internal/crypto"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIPKey
	secureKey
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so the first listed runs outermost.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestID assigns a random request ID (never trusting a client-supplied one) and echoes it
// in the X-Request-Id response header for support correlation.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := crypto.RandomHex(8)
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
		})
	}
}

// RequestIDFrom returns the request ID.
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey).(string)
	return s
}

// Recover turns panics into 500 responses and logs the stack.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() { //nolint:contextcheck // the closure logs with r.Context()
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value
						panic(v)
					}
					log.ErrorContext(r.Context(), "panic in HTTP handler", "panic", v, "path", r.URL.Path,
						"request_id", RequestIDFrom(r.Context()), "stack", string(debug.Stack()))
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP resolves the client address and whether the original request used HTTPS.
//
// X-Forwarded-For / X-Forwarded-Proto are honoured only when the direct peer is a trusted
// proxy; the client IP is then the right-most address in X-Forwarded-For that is not itself a
// trusted proxy (spoofed left-most entries are ignored).
func ClientIP(trusted []netip.Prefix) Middleware {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := peerAddr(r.RemoteAddr)
			ip := peer
			secure := r.TLS != nil
			if peer.IsValid() && isTrusted(peer) {
				if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
					hops := strings.Split(strings.Join(xff, ","), ",")
					for i := len(hops) - 1; i >= 0; i-- {
						a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
						if err != nil {
							break
						}
						ip = a.Unmap()
						if !isTrusted(ip) {
							break
						}
					}
				}
				if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
					secure = strings.EqualFold(strings.TrimSpace(strings.Split(proto, ",")[0]), "https")
				}
			}
			ctx := context.WithValue(r.Context(), clientIPKey, ip)
			ctx = context.WithValue(ctx, secureKey, secure)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ClientIPFrom returns the resolved client IP (invalid if unknown).
func ClientIPFrom(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(clientIPKey).(netip.Addr)
	return a
}

// IsSecure reports whether the original request used HTTPS.
func IsSecure(ctx context.Context) bool {
	b, _ := ctx.Value(secureKey).(bool)
	return b
}

// BaseSecurityHeaders sets headers that apply to every response. HTML responses add a
// nonce-based Content-Security-Policy themselves (see webui); everything else gets a CSP that
// forbids all content, which is correct for API/JSON responses.
func BaseSecurityHeaders(hsts bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			if hsts && IsSecure(r.Context()) {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore marks responses as uncacheable (API responses, anything user-specific).
func NoStore() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBytes limits request bodies.
func MaxBytes(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder captures the status code while preserving streaming interfaces.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Flush supports streaming responses (Connect server streams, SSE).
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack supports WebSocket upgrades.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("httpx: hijacking not supported")
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// AccessLog logs one line per request (no query strings, headers or bodies).
func AccessLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			level := slog.LevelDebug
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelInfo
			}
			log.Log(r.Context(), level, "http request",
				"method", r.Method, "path", r.URL.Path, "status", rec.status,
				"bytes", rec.bytes, "duration_ms", time.Since(start).Milliseconds(),
				"client_ip", ClientIPFrom(r.Context()).String(), "request_id", RequestIDFrom(r.Context()))
		})
	}
}
