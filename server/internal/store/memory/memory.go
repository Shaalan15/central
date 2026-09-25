// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package memory is an in-process storage driver for tests and `central serve --dev`.
//
// It keeps everything in memory and can optionally snapshot to a JSON file (0600) so a dev
// instance survives restarts. It is not intended for production: there is no concurrency
// across processes and queries are linear scans.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
)

// Driver is the in-memory store.Driver.
type Driver struct {
	mu     sync.RWMutex
	tables map[string]*table
	// pending holds records loaded from disk for collections not yet registered.
	pending map[string][]persisted

	path    string
	dirty   chan struct{}
	done    chan struct{}
	stopped sync.WaitGroup
	closeMu sync.Once
}

type table struct {
	schema store.SchemaInfo
	rows   map[string]store.Record
}

type persisted struct {
	ID    string          `json:"id"`
	OrgID string          `json:"org_id,omitempty"`
	Index map[string]any  `json:"index,omitempty"`
	Data  json.RawMessage `json:"data"`
}

type snapshot struct {
	Version     int                    `json:"version"`
	Collections map[string][]persisted `json:"collections"`
}

// New returns a volatile in-memory driver.
func New() *Driver {
	return &Driver{tables: map[string]*table{}, pending: map[string][]persisted{}}
}

// Open returns a driver persisted to path (created if missing).
func Open(path string) (*Driver, error) {
	d := New()
	d.path = path
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted configuration
	switch {
	case err == nil:
		var snap snapshot
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&snap); err != nil {
			return nil, fmt.Errorf("memory: read snapshot %s: %w", path, err)
		}
		for name, recs := range snap.Collections {
			d.pending[name] = recs
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("memory: %w", err)
	}
	d.dirty = make(chan struct{}, 1)
	d.done = make(chan struct{})
	d.stopped.Add(1)
	go d.flushLoop()
	return d, nil
}

// Info implements store.Driver.
func (d *Driver) Info() store.DriverInfo {
	endpoint := "memory"
	if d.path != "" {
		endpoint = "file:" + d.path
	}
	return store.DriverInfo{Name: "memory", Endpoint: endpoint, Version: "1"}
}

// Migrate implements store.Driver.
func (d *Driver) Migrate(_ context.Context, schemas []store.SchemaInfo) error {
	for _, s := range schemas {
		d.register(s)
	}
	return nil
}

// Ping implements store.Driver.
func (d *Driver) Ping(context.Context) error { return nil }

// Close flushes the snapshot (if persistent) and stops the background writer.
func (d *Driver) Close() error {
	var err error
	d.closeMu.Do(func() {
		if d.done != nil {
			close(d.done)
			d.stopped.Wait()
			err = d.flush()
		}
	})
	return err
}

// Collection implements store.Driver.
func (d *Driver) Collection(schema store.SchemaInfo) store.RawCollection {
	d.register(schema)
	return &collection{d: d, name: schema.Name}
}

func (d *Driver) register(schema store.SchemaInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.tables[schema.Name]; ok {
		t.schema = schema
		return
	}
	t := &table{schema: schema, rows: map[string]store.Record{}}
	for _, p := range d.pending[schema.Name] {
		t.rows[p.ID] = store.Record{ID: p.ID, OrgID: p.OrgID, Index: normalizeIndex(schema, p.Index), Data: []byte(p.Data)}
	}
	delete(d.pending, schema.Name)
	d.tables[schema.Name] = t
}

func normalizeIndex(schema store.SchemaInfo, in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for _, f := range schema.Fields {
		v, ok := in[f.Name]
		if !ok {
			continue
		}
		switch f.Type {
		case store.FieldInt:
			switch n := v.(type) {
			case json.Number:
				i, _ := n.Int64()
				out[f.Name] = i
			case float64:
				out[f.Name] = int64(n)
			case int64:
				out[f.Name] = n
			}
		case store.FieldBool:
			b, _ := v.(bool)
			out[f.Name] = b
		default:
			s, _ := v.(string)
			out[f.Name] = s
		}
	}
	return out
}

func (d *Driver) markDirty() {
	if d.dirty == nil {
		return
	}
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

func (d *Driver) flushLoop() {
	defer d.stopped.Done()
	for {
		select {
		case <-d.done:
			return
		case <-d.dirty:
			// Coalesce bursts of writes.
			select {
			case <-d.done:
				return
			case <-time.After(250 * time.Millisecond):
			}
			if err := d.flush(); err != nil {
				slog.Error("memory store: snapshot failed", "path", d.path, "error", err)
			}
		}
	}
}

func (d *Driver) flush() error {
	if d.path == "" {
		return nil
	}
	d.mu.RLock()
	snap := snapshot{Version: 1, Collections: map[string][]persisted{}}
	for name, t := range d.tables {
		recs := make([]persisted, 0, len(t.rows))
		for _, r := range t.rows {
			recs = append(recs, persisted{ID: r.ID, OrgID: r.OrgID, Index: r.Index, Data: r.Data})
		}
		slices.SortFunc(recs, func(a, b persisted) int { return strings.Compare(a.ID, b.ID) })
		snap.Collections[name] = recs
	}
	for name, recs := range d.pending {
		snap.Collections[name] = recs
	}
	d.mu.RUnlock()
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return crypto.WriteFileAtomic(d.path, data, 0o600)
}

type collection struct {
	d    *Driver
	name string
}

func (c *collection) tbl() *table { return c.d.tables[c.name] }

func clone(r store.Record) store.Record {
	out := store.Record{ID: r.ID, OrgID: r.OrgID, Data: bytes.Clone(r.Data)}
	if r.Index != nil {
		out.Index = make(map[string]any, len(r.Index))
		for k, v := range r.Index {
			out.Index[k] = v
		}
	}
	return out
}

func visible(t *table, scope store.Scope, r store.Record) bool {
	return !t.schema.Tenant || scope.IsSystem() || r.OrgID == scope.OrgID()
}

func (c *collection) Get(_ context.Context, scope store.Scope, id string) (store.Record, error) {
	c.d.mu.RLock()
	defer c.d.mu.RUnlock()
	t := c.tbl()
	if err := store.CheckScope(t.schema, scope, "", false); err != nil {
		return store.Record{}, err
	}
	r, ok := t.rows[id]
	if !ok || !visible(t, scope, r) {
		return store.Record{}, store.ErrNotFound
	}
	return clone(r), nil
}

func (c *collection) write(scope store.Scope, rec store.Record, mustExist, mustNotExist bool) error {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	t := c.tbl()
	if !t.schema.Tenant {
		rec.OrgID = ""
	}
	if err := store.CheckScope(t.schema, scope, rec.OrgID, true); err != nil {
		return err
	}
	existing, exists := t.rows[rec.ID]
	if exists && !visible(t, scope, existing) {
		// Never reveal or overwrite another tenant's row.
		if mustExist {
			return store.ErrNotFound
		}
		return store.ErrAlreadyExists
	}
	if exists && existing.OrgID != rec.OrgID {
		return fmt.Errorf("%w: cannot move %s/%s between organizations", store.ErrScope, t.schema.Name, rec.ID)
	}
	if mustExist && !exists {
		return store.ErrNotFound
	}
	if mustNotExist && exists {
		return store.ErrAlreadyExists
	}
	if err := checkUnique(t, rec); err != nil {
		return err
	}
	t.rows[rec.ID] = clone(rec)
	c.d.markDirty()
	return nil
}

func checkUnique(t *table, rec store.Record) error {
	for _, ix := range t.schema.Indexes {
		if !ix.Unique {
			continue
		}
		for id, other := range t.rows {
			if id == rec.ID {
				continue
			}
			same := true
			for _, f := range ix.Fields {
				if fieldValue(t.schema, other, f) != fieldValue(t.schema, rec, f) {
					same = false
					break
				}
			}
			if same {
				return fmt.Errorf("%w: %s unique index %s", store.ErrAlreadyExists, t.schema.Name, ix.Name)
			}
		}
	}
	return nil
}

func (c *collection) Insert(_ context.Context, scope store.Scope, rec store.Record) error {
	return c.write(scope, rec, false, true)
}

func (c *collection) Replace(_ context.Context, scope store.Scope, rec store.Record) error {
	return c.write(scope, rec, true, false)
}

func (c *collection) Upsert(_ context.Context, scope store.Scope, rec store.Record) error {
	return c.write(scope, rec, false, false)
}

func (c *collection) Delete(_ context.Context, scope store.Scope, id string) error {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	t := c.tbl()
	if err := store.CheckScope(t.schema, scope, "", false); err != nil {
		return err
	}
	r, ok := t.rows[id]
	if !ok || !visible(t, scope, r) {
		return store.ErrNotFound
	}
	delete(t.rows, id)
	c.d.markDirty()
	return nil
}

func fieldValue(schema store.SchemaInfo, r store.Record, field string) any {
	switch field {
	case "id":
		return r.ID
	case "org_id":
		return r.OrgID
	}
	if v, ok := r.Index[field]; ok {
		return v
	}
	for _, f := range schema.Fields {
		if f.Name == field {
			switch f.Type {
			case store.FieldInt:
				return int64(0)
			case store.FieldBool:
				return false
			default:
				return ""
			}
		}
	}
	return nil
}

func compareValues(a, b any) int {
	switch x := a.(type) {
	case string:
		y, _ := b.(string)
		return strings.Compare(x, y)
	case int64:
		y, _ := b.(int64)
		return cmp.Compare(x, y)
	case bool:
		y, _ := b.(bool)
		switch {
		case x == y:
			return 0
		case !x:
			return -1
		default:
			return 1
		}
	}
	return 0
}

func matches(schema store.SchemaInfo, r store.Record, conds []store.Cond) bool {
	for _, c := range conds {
		v := fieldValue(schema, r, c.Field)
		switch c.Op {
		case store.OpEq:
			if compareValues(v, c.Value) != 0 {
				return false
			}
		case store.OpNe:
			if compareValues(v, c.Value) == 0 {
				return false
			}
		case store.OpLt:
			if compareValues(v, c.Value) >= 0 {
				return false
			}
		case store.OpLte:
			if compareValues(v, c.Value) > 0 {
				return false
			}
		case store.OpGt:
			if compareValues(v, c.Value) <= 0 {
				return false
			}
		case store.OpGte:
			if compareValues(v, c.Value) < 0 {
				return false
			}
		case store.OpPrefix:
			s, _ := v.(string)
			p, _ := c.Value.(string)
			if !strings.HasPrefix(s, p) {
				return false
			}
		case store.OpIn:
			found := false
			switch list := c.Value.(type) {
			case []string:
				found = slices.Contains(list, fmt.Sprint(v))
			case []int64:
				n, _ := v.(int64)
				found = slices.Contains(list, n)
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func (c *collection) selectRows(scope store.Scope, q store.Query) ([]store.Record, error) {
	t := c.tbl()
	if err := store.CheckScope(t.schema, scope, "", false); err != nil {
		return nil, err
	}
	if err := q.Validate(t.schema); err != nil {
		return nil, err
	}
	var out []store.Record
	for _, r := range t.rows {
		if visible(t, scope, r) && matches(t.schema, r, q.Where) {
			out = append(out, r)
		}
	}
	order := q.OrderBy
	if order == "" {
		order = "id"
	}
	slices.SortFunc(out, func(a, b store.Record) int {
		n := compareValues(fieldValue(t.schema, a, order), fieldValue(t.schema, b, order))
		if n == 0 {
			n = strings.Compare(a.ID, b.ID)
		}
		if q.Desc {
			return -n
		}
		return n
	})
	return out, nil
}

func (c *collection) Find(_ context.Context, scope store.Scope, q store.Query) ([]store.Record, string, error) {
	c.d.mu.RLock()
	defer c.d.mu.RUnlock()
	rows, err := c.selectRows(scope, q)
	if err != nil {
		return nil, "", err
	}
	start := 0
	if q.After != "" {
		start = len(rows)
		for i, r := range rows {
			if r.ID == q.After {
				start = i + 1
				break
			}
		}
	}
	limit := q.EffectiveLimit()
	end := min(start+limit, len(rows))
	page := make([]store.Record, 0, end-start)
	for _, r := range rows[start:end] {
		page = append(page, clone(r))
	}
	next := ""
	if end < len(rows) && len(page) > 0 {
		next = page[len(page)-1].ID
	}
	return page, next, nil
}

func (c *collection) Count(_ context.Context, scope store.Scope, q store.Query) (int, error) {
	c.d.mu.RLock()
	defer c.d.mu.RUnlock()
	rows, err := c.selectRows(scope, q)
	return len(rows), err
}
