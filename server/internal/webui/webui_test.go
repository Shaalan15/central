// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                {Data: []byte(`<html><script nonce="__CSP_NONCE__" src="main-ABCD1234.js"></script><app-root ngCspNonce="__CSP_NONCE__"></app-root></html>`)},
		"main-ABCD1234.js":          {Data: []byte(strings.Repeat("console.log('x');", 200))},
		"favicon.ico":               {Data: []byte{0, 0, 1, 0}},
		"media/font-XYZW9876.woff2": {Data: []byte("font")},
		".gitkeep":                  {Data: nil},
	}
}

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestIndexNonce(t *testing.T) {
	h, err := NewFromFS(testFS())
	if err != nil {
		t.Fatal(err)
	}
	a := get(t, h, "/", nil)
	b := get(t, h, "/fleet/agents/123", nil) // SPA route
	for _, w := range []*httptest.ResponseRecorder{a, b} {
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("code=%d ct=%s", w.Code, w.Header().Get("Content-Type"))
		}
		if strings.Contains(w.Body.String(), "__CSP_NONCE__") {
			t.Fatal("placeholder not replaced")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("index must not be cached")
		}
	}
	nonceRe := regexp.MustCompile(`nonce="([A-Za-z0-9_-]+)"`)
	na := nonceRe.FindStringSubmatch(a.Body.String())[1]
	nb := nonceRe.FindStringSubmatch(b.Body.String())[1]
	if na == nb {
		t.Fatal("nonce reused across requests")
	}
	csp := a.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-"+na+"'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("bad CSP: %s", csp)
	}
	for _, d := range []string{"frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'", "require-trusted-types-for 'script'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing %q", d)
		}
	}
}

func TestAssets(t *testing.T) {
	h, _ := NewFromFS(testFS())
	w := get(t, h, "/main-ABCD1234.js", map[string]string{"Accept-Encoding": "gzip, br"})
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("code=%d enc=%q", w.Code, w.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("hashed asset should be immutable")
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	if !strings.HasPrefix(string(body), "console.log") {
		t.Fatal("gzip body mismatch")
	}
	plain := get(t, h, "/main-ABCD1234.js", nil)
	if plain.Header().Get("Content-Encoding") != "" || !strings.HasPrefix(plain.Body.String(), "console.log") {
		t.Fatal("uncompressed fallback broken")
	}
	fav := get(t, h, "/favicon.ico", nil)
	if fav.Code != 200 || strings.Contains(fav.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("favicon: %d %s", fav.Code, fav.Header().Get("Cache-Control"))
	}
	if get(t, h, "/media/font-XYZW9876.woff2", nil).Header().Get("Content-Type") != "font/woff2" {
		t.Fatal("woff2 content type")
	}
}

func TestNotFoundAndTraversal(t *testing.T) {
	h, _ := NewFromFS(testFS())
	for _, p := range []string{"/missing.js", "/.gitkeep", "/../../etc/passwd.txt"} {
		if w := get(t, h, p, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: code %d", p, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

func TestPlaceholderWhenNotBuilt(t *testing.T) {
	h, err := NewFromFS(fstest.MapFS{".gitkeep": {}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Built() {
		t.Fatal("should not report built")
	}
	if w := get(t, h, "/", nil); !strings.Contains(w.Body.String(), "make web") {
		t.Fatal("placeholder page missing")
	}
}
