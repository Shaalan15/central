// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package logging configures structured logging (log/slog).
//
// Never log secrets: wrap them in crypto.Secret, which redacts itself. Request logs record
// method, path (without query strings, which may carry tickets), status, duration and client
// IP — never headers or bodies.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New creates a logger. format is "json" or "text"; level is debug|info|warn|error.
func New(w io.Writer, format, level string) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: ParseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

// ParseLevel converts a level name (default info).
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
