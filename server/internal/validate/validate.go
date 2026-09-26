// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package validate holds input validation shared by API handlers. Every value that arrives
// from a client goes through one of these (or a stricter, domain-specific check) before use.
package validate

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Email validates and normalizes an email address (lowercase, trimmed).
func Email(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 254 {
		return "", errors.New("email must be 1-254 characters")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || addr.Name != "" {
		return "", errors.New("email is not a valid address")
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || !strings.Contains(domain, ".") || strings.ContainsAny(s, " \"<>(),;:\\[]") {
		return "", errors.New("email is not a valid address")
	}
	return s, nil
}

// DisplayText validates a human-readable name/label: trimmed, 1..max runes, printable, no
// control or bidi-override characters (which can disguise text in the UI and audit log).
func DisplayText(field, s string, maxRunes int) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s must be valid UTF-8", field)
	}
	n := utf8.RuneCountInString(s)
	if n == 0 || n > maxRunes {
		return "", fmt.Errorf("%s must be 1-%d characters", field, maxRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) || !unicode.IsPrint(r) && r != ' ' {
			return "", fmt.Errorf("%s contains unsupported characters", field)
		}
	}
	return s, nil
}

// OptionalText is DisplayText that allows the empty string.
func OptionalText(field, s string, maxRunes int) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	return DisplayText(field, s, maxRunes)
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,62}$`)

// Tag validates an agent tag (lowercase, 1-63 chars).
func Tag(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !tagRe.MatchString(s) {
		return "", fmt.Errorf("invalid tag %q: use 1-63 of a-z 0-9 . _ : / - starting with a letter or digit", s)
	}
	return s, nil
}

// Tags validates, normalizes and de-duplicates tags (max 32).
func Tags(in []string) ([]string, error) {
	if len(in) > 32 {
		return nil, errors.New("at most 32 tags")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		v, err := Tag(t)
		if err != nil {
			return nil, err
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

var idRe = regexp.MustCompile(`^[a-z0-9]{1,36}$`)

// ID validates an opaque resource ID from a client.
func ID(field, s string) error {
	if !idRe.MatchString(s) {
		return fmt.Errorf("%s is not a valid ID", field)
	}
	return nil
}
