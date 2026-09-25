// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")
	cases := []struct {
		name, remote, xff, proto string
		wantIP                   string
		wantSecure               bool
	}{
		{"direct client ignores XFF", "203.0.113.7:1234", "1.2.3.4", "https", "203.0.113.7", false},
		{"trusted proxy", "10.0.0.2:1234", "198.51.100.9", "https", "198.51.100.9", true},
		{"spoofed left-most entry ignored", "10.0.0.2:1234", "6.6.6.6, 198.51.100.9", "http", "198.51.100.9", false},
		{"chain of trusted proxies", "10.0.0.2:1234", "198.51.100.9, 10.0.0.3", "https", "198.51.100.9", true},
		{"garbage XFF falls back", "10.0.0.2:1234", "not-an-ip", "", "10.0.0.2", false},
		{"ipv6 peer", "[2001:db8::1]:443", "", "", "2001:db8::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotIP netip.Addr
			var gotSecure bool
			h := ClientIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotIP, gotSecure = ClientIPFrom(r.Context()), IsSecure(r.Context())
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if gotIP.String() != tc.wantIP || gotSecure != tc.wantSecure {
				t.Fatalf("ip=%s secure=%v, want %s %v", gotIP, gotSecure, tc.wantIP, tc.wantSecure)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		ClientIP(mustPrefixes(t, "10.0.0.0/8")), BaseSecurityHeaders(true))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for k, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'",
	} {
		if got := w.Header().Get(k); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing on HTTPS request")
	}

	// No HSTS over plain HTTP (browsers ignore it and it breaks local dev).
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "203.0.113.1:1"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}
}

func TestRecoverAndRequestID(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }), RequestID(), Recover(log))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "boom") {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if len(w.Header().Get("X-Request-Id")) != 16 {
		t.Fatal("missing request id")
	}
}

func TestMaxBytes(t *testing.T) {
	h := MaxBytes(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too big", http.StatusRequestEntityTooLarge)
		}
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100))))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d", w.Code)
	}
}
