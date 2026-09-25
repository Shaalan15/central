// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package httpx

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cookies applies Central's cookie policy: HttpOnly, SameSite=Strict, Path=/, Secure with the
// __Host- prefix. Only in dev mode over plain HTTP (localhost) are unprefixed, non-Secure
// cookies used so the dev server works without TLS.
type Cookies struct {
	Dev bool
}

func (c Cookies) secure(ctx context.Context) bool { return !c.Dev || IsSecure(ctx) }

// Name returns the effective cookie name for base.
func (c Cookies) Name(ctx context.Context, base string) string {
	if c.secure(ctx) {
		return "__Host-" + base
	}
	return base
}

// Set appends a Set-Cookie header.
func (c Cookies) Set(ctx context.Context, h http.Header, base, value string, maxAge time.Duration) {
	ck := &http.Cookie{ //nolint:gosec // Secure is false only in --dev mode over plain HTTP
		Name:     c.Name(ctx, base),
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   c.secure(ctx),
		SameSite: http.SameSiteStrictMode,
	}
	h.Add("Set-Cookie", ck.String())
}

// Clear expires a cookie.
func (c Cookies) Clear(ctx context.Context, h http.Header, base string) {
	ck := &http.Cookie{ //nolint:gosec // Secure is false only in --dev mode over plain HTTP
		Name: c.Name(ctx, base), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: c.secure(ctx), SameSite: http.SameSiteStrictMode,
	}
	h.Add("Set-Cookie", ck.String())
}

// Read returns the cookie value from request headers ("" if absent).
func (c Cookies) Read(ctx context.Context, reqHeader http.Header, base string) string {
	r := http.Request{Header: reqHeader}
	ck, err := r.Cookie(c.Name(ctx, base))
	if err != nil {
		return ""
	}
	return ck.Value
}

// SameOrigin rejects cross-origin state-changing requests (defense in depth on top of
// SameSite=Strict cookies and non-simple content types). A request passes if its Origin header
// matches the request's own origin or one of the allowed origins, or — for non-browser clients —
// if it has no Origin and no cross-site Sec-Fetch-Site header.
func SameOrigin(allowed func() []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				switch r.Header.Get("Sec-Fetch-Site") {
				case "", "same-origin", "none":
					next.ServeHTTP(w, r)
				default:
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				}
				return
			}
			if originAllowed(r, origin, allowed()) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		})
	}
}

func originAllowed(r *http.Request, origin string, allowed []string) bool {
	scheme := "http"
	if IsSecure(r.Context()) {
		scheme = "https"
	}
	if strings.EqualFold(origin, scheme+"://"+r.Host) {
		return true
	}
	for _, a := range allowed {
		u, err := url.Parse(a)
		if err != nil || u.Host == "" {
			continue
		}
		if strings.EqualFold(origin, u.Scheme+"://"+u.Host) {
			return true
		}
	}
	return false
}
