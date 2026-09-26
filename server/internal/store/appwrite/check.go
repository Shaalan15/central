// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package appwrite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// MinMajorVersion is the oldest Appwrite major version Central supports.
const MinMajorVersion = 2

// CheckResult describes a connectivity test.
type CheckResult struct {
	OK               bool
	ServerVersion    string
	VersionSupported bool
	MissingScopes    []string
	DatabaseExists   bool
	Error            string
}

var missingScopeRe = regexp.MustCompile(`missing scopes? \(?\[?([a-z0-9_.,\s"]+)\]?\)?`)

// Check verifies that Central can use an Appwrite project: the server answers, its version is
// supported, and the API key can read the database. It never creates anything.
func Check(ctx context.Context, cfg config.AppwriteConfig, apiKey crypto.Secret) CheckResult {
	d, err := Open(cfg, apiKey)
	if err != nil {
		return CheckResult{Error: err.Error()}
	}
	defer func() { _ = d.Close() }()

	res := CheckResult{}
	version, err := d.serverVersion(ctx)
	switch {
	case err != nil:
		return CheckResult{Error: "cannot reach Appwrite: " + err.Error()}
	case version == "":
		// Some deployments hide the version endpoint; accept and rely on the TablesDB probe.
		res.ServerVersion = "unknown"
		res.VersionSupported = true
	default:
		res.ServerVersion = version
		res.VersionSupported = majorVersion(version) >= MinMajorVersion
	}
	d.version = res.ServerVersion

	err = call(ctx, true, func() error {
		_, err := d.db.Get(d.cfg.DatabaseID)
		return err
	})
	switch {
	case err == nil:
		res.DatabaseExists = true
	case errors.Is(err, store.ErrNotFound):
		res.DatabaseExists = false
	default:
		return withScopes(res, err)
	}
	if res.DatabaseExists {
		err = call(ctx, true, func() error {
			_, err := d.db.ListTables(d.cfg.DatabaseID)
			return err
		})
		if err != nil {
			return withScopes(res, err)
		}
	}
	res.OK = true
	return res
}

func withScopes(res CheckResult, err error) CheckResult {
	msg := err.Error()
	if m := missingScopeRe.FindStringSubmatch(msg); m != nil {
		for _, s := range strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' || r == '"' }) {
			if s != "" && !slices.Contains(res.MissingScopes, s) {
				res.MissingScopes = append(res.MissingScopes, s)
			}
		}
	}
	switch {
	case len(res.MissingScopes) > 0:
		res.Error = "the API key is missing required scopes"
	case strings.Contains(msg, "permission denied"):
		res.Error = "the API key was rejected (check the project ID and key, and that the key has the scopes: " +
			strings.Join(RequiredScopes, ", ") + ")"
	default:
		res.Error = msg
	}
	return res
}

// serverVersion reads GET /health/version (public on Appwrite). "" means not available.
func (d *Driver) serverVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(d.cfg.Endpoint, "/")+"/health/version", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Appwrite-Project", d.cfg.ProjectID)
	resp, err := d.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", errors.New("unexpected response from the health endpoint (is this an Appwrite endpoint ending in /v1?)")
	}
	return v.Version, nil
}

func majorVersion(v string) int {
	major, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}
