// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package webui serves the embedded Angular application.
//
// The production build (web/dist/browser) is copied into ./dist by `make web` and embedded at
// compile time. index.html is served with a fresh CSP nonce per request: every
// "__CSP_NONCE__" placeholder is replaced and a matching Content-Security-Policy header is sent,
// so no inline script or style ever needs 'unsafe-inline'. Hashed assets are served with
// immutable caching and precompressed with gzip.
package webui

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Shaalan15/central/server/internal/crypto"
)

//go:embed all:dist
var embedded embed.FS

const noncePlaceholder = "__CSP_NONCE__"

// hashedAsset matches Angular's content-hashed output names (main-ABCD1234.js, media/...).
var hashedAsset = regexp.MustCompile(`-[A-Z0-9]{8}\.[a-z0-9]+$`)

type asset struct {
	body        []byte
	gz          []byte
	contentType string
	immutable   bool
}

// Handler serves the UI.
type Handler struct {
	index  []byte
	assets map[string]*asset
	built  bool
}

// New loads the embedded UI (or a placeholder page when the UI was not built).
func New() (*Handler, error) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, err
	}
	return NewFromFS(sub)
}

// NewFromFS loads a UI from any filesystem (used by tests).
func NewFromFS(fsys fs.FS) (*Handler, error) {
	h := &Handler{assets: map[string]*asset{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path.Base(p), ".") {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if p == "index.html" {
			h.index = data
			h.built = true
			return nil
		}
		a := &asset{body: data, contentType: contentType(p), immutable: hashedAsset.MatchString(p)}
		if compressible(a.contentType) && len(data) > 1024 {
			a.gz = gzipBytes(data)
		}
		h.assets["/"+p] = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !h.built {
		h.index = []byte(placeholderPage)
	}
	return h, nil
}

// Built reports whether a real UI build is embedded.
func (h *Handler) Built() bool { return h.built }

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	if a, ok := h.assets[p]; ok {
		h.serveAsset(w, r, a)
		return
	}
	// Unknown files with an extension are real 404s; everything else is an SPA route.
	if path.Ext(p) != "" && p != "/" {
		http.NotFound(w, r)
		return
	}
	h.serveIndex(w, r)
}

func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, a *asset) {
	hdr := w.Header()
	hdr.Set("Content-Type", a.contentType)
	if a.immutable {
		hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		hdr.Set("Cache-Control", "public, max-age=3600")
	}
	body := a.body
	if a.gz != nil {
		hdr.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			hdr.Set("Content-Encoding", "gzip")
			body = a.gz
		}
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	nonce := crypto.RandomToken(18)
	body := bytes.ReplaceAll(h.index, []byte(noncePlaceholder), []byte(nonce))
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", CSP(nonce))
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// CSP returns the Content-Security-Policy for the UI document.
func CSP(nonce string) string {
	directives := []string{
		"default-src 'self'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data: blob:",
		"font-src 'self'",
		"connect-src 'self'",
		"worker-src 'self' blob:",
		"manifest-src 'self'",
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"require-trusted-types-for 'script'",
		"trusted-types angular angular#bundler angular#components",
	}
	return strings.Join(directives, "; ")
}

func contentType(p string) string {
	if t := mime.TypeByExtension(path.Ext(p)); t != "" {
		return t
	}
	switch path.Ext(p) {
	case ".woff2":
		return "font/woff2"
	case ".webmanifest":
		return "application/manifest+json"
	}
	return "application/octet-stream"
}

func compressible(ct string) bool {
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "json") || strings.Contains(ct, "svg") || strings.Contains(ct, "xml")
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, q, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") && !strings.Contains(q, "q=0") {
			return true
		}
	}
	return false
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

const placeholderPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Central</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><main><h1>Central</h1>
<p>The web UI is not included in this build. Run <code>make web</code> (or <code>make build</code>)
and rebuild the server, or use the Angular dev server with <code>make dev-web</code>.</p>
</main></body></html>
`
