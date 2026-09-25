// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package appwrite is the Appwrite 2.x storage driver (TablesDB API, Go SDK v7).
//
// Layout: one table per collection, no row-level permissions (only Central's server API key
// can read or write). Each row has an optional org_id column (tenant tables), one typed column
// per indexed field, and a longtext "data" column with the entity's JSON document.
//
// Tenant isolation does not rely on Appwrite: every read verifies org_id against the scope and
// every write verifies the existing row's org before replacing it.
package appwrite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/appwrite/sdk-for-go/v7/appwrite"
	"github.com/appwrite/sdk-for-go/v7/client"
	"github.com/appwrite/sdk-for-go/v7/tablesdb"

	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Column names used by the driver.
const (
	colOrg  = "org_id"
	colData = "data"
)

// RequiredScopes are the API key scopes Central needs.
var RequiredScopes = []string{
	"databases.read", "databases.write", "tables.read", "tables.write",
	"columns.read", "columns.write", "indexes.read", "indexes.write",
	"rows.read", "rows.write",
}

// Driver implements store.Driver on Appwrite.
type Driver struct {
	cfg     config.AppwriteConfig
	db      *tablesdb.TablesDB
	http    *http.Client
	apiKey  crypto.Secret
	version string
	schemas map[string]store.SchemaInfo
}

// Open connects to Appwrite. It does not migrate; call Migrate (store.Store.Migrate).
func Open(cfg config.AppwriteConfig, apiKey crypto.Secret) (*Driver, error) {
	if cfg.DatabaseID == "" {
		cfg.DatabaseID = "central"
	}
	hc, err := httpClient(cfg.CABundleFile)
	if err != nil {
		return nil, err
	}
	c := appwrite.NewClient(
		appwrite.WithEndpoint(strings.TrimRight(cfg.Endpoint, "/")),
		appwrite.WithProject(cfg.ProjectID),
		appwrite.WithKey(apiKey.Reveal()),
	)
	// Replace the SDK's default client (which has a cookie jar and no custom CA support).
	c.Client = hc
	return &Driver{cfg: cfg, db: appwrite.NewTablesDB(c), http: hc, apiKey: apiKey, schemas: map[string]store.SchemaInfo{}}, nil
}

func httpClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // path from trusted configuration
		if err != nil {
			return nil, fmt.Errorf("appwrite: read CA bundle: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("appwrite: CA bundle contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

// Info implements store.Driver.
func (d *Driver) Info() store.DriverInfo {
	return store.DriverInfo{Name: "appwrite", Endpoint: hostOf(d.cfg.Endpoint), Version: d.version}
}

// Ping implements store.Driver.
func (d *Driver) Ping(ctx context.Context) error {
	return call(ctx, true, func() error {
		_, err := d.db.Get(d.cfg.DatabaseID)
		return err
	})
}

// call runs one SDK request. The SDK has no context support, so cancellation is checked before
// the request and the HTTP client's timeouts bound its duration. For idempotent requests
// (retry=true), transient failures (429, 5xx, network errors) are retried with backoff for up to
// three attempts; non-idempotent requests (row creation) are never retried.
func call(ctx context.Context, retry bool, fn func() error) error {
	attempts := 1
	if retry {
		attempts = 3
	}
	var err error
	for attempt := range attempts {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		err = mapErr(fn())
		if err == nil || !errors.Is(err, store.ErrUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(200*(attempt+1)*(attempt+1)) * time.Millisecond):
		}
	}
	return err
}

// Close implements store.Driver.
func (d *Driver) Close() error {
	d.http.CloseIdleConnections()
	return nil
}

// Collection implements store.Driver.
func (d *Driver) Collection(schema store.SchemaInfo) store.RawCollection {
	d.schemas[schema.Name] = schema
	return &collection{d: d, schema: schema}
}

func hostOf(endpoint string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	host, _, _ := strings.Cut(s, "/")
	return host
}

// apiError is the decoded Appwrite error body.
type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    int    `json:"code"`
}

func decodeAPIError(err error) (int, apiError, bool) {
	var ae *client.AppwriteError
	if !errors.As(err, &ae) {
		return 0, apiError{}, false
	}
	var body apiError
	_ = json.Unmarshal([]byte(ae.GetResponse()), &body)
	if body.Message == "" {
		body.Message = ae.GetMessage()
	}
	return ae.GetStatusCode(), body, true
}

// mapErr converts SDK errors into store errors. Messages never include the API key.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	status, body, ok := decodeAPIError(err)
	if !ok {
		return fmt.Errorf("%w: %v", store.ErrUnavailable, err) //nolint:errorlint // network errors are not wrapped further
	}
	switch {
	case status == http.StatusNotFound:
		return store.ErrNotFound
	case status == http.StatusConflict:
		return fmt.Errorf("%w: %s", store.ErrAlreadyExists, body.Message)
	case status == http.StatusBadRequest:
		return fmt.Errorf("%w: appwrite: %s (%s)", store.ErrInvalidQuery, body.Message, body.Type)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("appwrite: permission denied: %s", body.Message)
	case status == http.StatusTooManyRequests || status >= 500:
		return fmt.Errorf("%w: appwrite %d: %s", store.ErrUnavailable, status, body.Message)
	}
	return fmt.Errorf("appwrite %d: %s (%s)", status, body.Message, body.Type)
}
