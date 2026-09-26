// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package appwrite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Shaalan15/central/server/internal/store"
)

// Migrate creates the database, tables, columns and indexes that are missing, then waits until
// Appwrite reports them available. It never drops or alters existing columns, so it is safe to
// run on every start.
func (d *Driver) Migrate(ctx context.Context, schemas []store.SchemaInfo) error {
	if err := d.ensureDatabase(ctx); err != nil {
		return err
	}
	for _, s := range schemas {
		if err := d.ensureTable(ctx, s); err != nil {
			return fmt.Errorf("appwrite: table %s: %w", s.Name, err)
		}
	}
	for _, s := range schemas {
		if err := d.ensureColumns(ctx, s); err != nil {
			return fmt.Errorf("appwrite: columns of %s: %w", s.Name, err)
		}
	}
	for _, s := range schemas {
		if err := d.waitColumns(ctx, s); err != nil {
			return fmt.Errorf("appwrite: columns of %s: %w", s.Name, err)
		}
		if err := d.ensureIndexes(ctx, s); err != nil {
			return fmt.Errorf("appwrite: indexes of %s: %w", s.Name, err)
		}
	}
	for _, s := range schemas {
		if err := d.waitIndexes(ctx, s); err != nil {
			return fmt.Errorf("appwrite: indexes of %s: %w", s.Name, err)
		}
	}
	return nil
}

func (d *Driver) ensureDatabase(ctx context.Context) error {
	err := call(ctx, true, func() error {
		_, err := d.db.Get(d.cfg.DatabaseID)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	err = call(ctx, false, func() error {
		_, err := d.db.Create(d.cfg.DatabaseID, "Central")
		return err
	})
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil
	}
	return err
}

func (d *Driver) ensureTable(ctx context.Context, s store.SchemaInfo) error {
	err := call(ctx, true, func() error {
		_, err := d.db.GetTable(d.cfg.DatabaseID, s.Name)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	err = call(ctx, false, func() error {
		// No table permissions and no row security: only server API keys can access rows.
		_, err := d.db.CreateTable(d.cfg.DatabaseID, s.Name, s.Name,
			d.db.WithCreateTablePermissions([]string{}),
			d.db.WithCreateTableRowSecurity(false),
			d.db.WithCreateTableEnabled(true),
		)
		return err
	})
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil
	}
	return err
}

type columnInfo struct {
	Key    string `json:"key"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

func (d *Driver) listColumns(ctx context.Context, table string) (map[string]columnInfo, error) {
	var out struct {
		Columns []columnInfo `json:"columns"`
	}
	err := call(ctx, true, func() error {
		res, err := d.db.ListColumns(d.cfg.DatabaseID, table)
		if err != nil {
			return err
		}
		return res.Decode(&out)
	})
	if err != nil {
		return nil, err
	}
	m := make(map[string]columnInfo, len(out.Columns))
	for _, c := range out.Columns {
		m[c.Key] = c
	}
	return m, nil
}

func (d *Driver) ensureColumns(ctx context.Context, s store.SchemaInfo) error {
	existing, err := d.listColumns(ctx, s.Name)
	if err != nil {
		return err
	}
	db, t := d.cfg.DatabaseID, s.Name
	create := func(key string, fn func() error) error {
		if _, ok := existing[key]; ok {
			return nil
		}
		err := call(ctx, false, fn)
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil
		}
		return err
	}
	if s.Tenant {
		if err := create(colOrg, func() error {
			_, err := d.db.CreateVarcharColumn(db, t, colOrg, 36, false, d.db.WithCreateVarcharColumnDefault(""))
			return err
		}); err != nil {
			return err
		}
	}
	for _, f := range s.Fields {
		var fn func() error
		switch f.Type {
		case store.FieldInt:
			fn = func() error {
				_, err := d.db.CreateBigIntColumn(db, t, f.Name, false, d.db.WithCreateBigIntColumnDefault(0))
				return err
			}
		case store.FieldBool:
			fn = func() error {
				_, err := d.db.CreateBooleanColumn(db, t, f.Name, false, d.db.WithCreateBooleanColumnDefault(false))
				return err
			}
		default:
			size := f.Size
			if size <= 0 {
				size = 255
			}
			fn = func() error {
				_, err := d.db.CreateVarcharColumn(db, t, f.Name, size, false, d.db.WithCreateVarcharColumnDefault(""))
				return err
			}
		}
		if err := create(f.Name, fn); err != nil {
			return err
		}
	}
	return create(colData, func() error {
		_, err := d.db.CreateLongtextColumn(db, t, colData, true)
		return err
	})
}

func (d *Driver) waitColumns(ctx context.Context, s store.SchemaInfo) error {
	want := []string{colData}
	if s.Tenant {
		want = append(want, colOrg)
	}
	for _, f := range s.Fields {
		want = append(want, f.Name)
	}
	return poll(ctx, func() (bool, error) {
		cols, err := d.listColumns(ctx, s.Name)
		if err != nil {
			return false, err
		}
		for _, k := range want {
			c, ok := cols[k]
			if !ok {
				return false, nil
			}
			switch c.Status {
			case "available":
			case "failed", "stuck":
				return false, fmt.Errorf("column %s is %s: %s", k, c.Status, c.Error)
			default:
				return false, nil
			}
		}
		return true, nil
	})
}

type indexInfo struct {
	Key    string   `json:"key"`
	Status string   `json:"status"`
	Error  string   `json:"error"`
	Cols   []string `json:"columns"`
}

func indexKey(name string) string { return "ix_" + name }

func (d *Driver) listIndexes(ctx context.Context, table string) (map[string]indexInfo, error) {
	var out struct {
		Indexes []indexInfo `json:"indexes"`
	}
	err := call(ctx, true, func() error {
		res, err := d.db.ListIndexes(d.cfg.DatabaseID, table)
		if err != nil {
			return err
		}
		return res.Decode(&out)
	})
	if err != nil {
		return nil, err
	}
	m := make(map[string]indexInfo, len(out.Indexes))
	for _, ix := range out.Indexes {
		m[ix.Key] = ix
	}
	return m, nil
}

func wantedIndexes(s store.SchemaInfo) []store.Index {
	var out []store.Index
	if s.Tenant {
		out = append(out, store.Index{Name: "org", Fields: []string{colOrg}})
	}
	return append(out, s.Indexes...)
}

func (d *Driver) ensureIndexes(ctx context.Context, s store.SchemaInfo) error {
	existing, err := d.listIndexes(ctx, s.Name)
	if err != nil {
		return err
	}
	for _, ix := range wantedIndexes(s) {
		key := indexKey(ix.Name)
		if _, ok := existing[key]; ok {
			continue
		}
		typ := "key"
		if ix.Unique {
			typ = "unique"
		}
		err := call(ctx, false, func() error {
			_, err := d.db.CreateIndex(d.cfg.DatabaseID, s.Name, key, typ, ix.Fields)
			return err
		})
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return err
		}
	}
	return nil
}

func (d *Driver) waitIndexes(ctx context.Context, s store.SchemaInfo) error {
	return poll(ctx, func() (bool, error) {
		have, err := d.listIndexes(ctx, s.Name)
		if err != nil {
			return false, err
		}
		for _, ix := range wantedIndexes(s) {
			got, ok := have[indexKey(ix.Name)]
			if !ok {
				return false, nil
			}
			switch got.Status {
			case "available":
			case "failed", "stuck":
				return false, fmt.Errorf("index %s is %s: %s", ix.Name, got.Status, got.Error)
			default:
				return false, nil
			}
		}
		return true, nil
	})
}

// pollInitialDelay is the first wait while Appwrite creates columns/indexes (tests lower it).
var pollInitialDelay = 100 * time.Millisecond

// poll retries check until it reports done, fails, or two minutes pass.
func poll(ctx context.Context, check func() (bool, error)) error {
	deadline := time.Now().Add(2 * time.Minute)
	delay := pollInitialDelay
	for {
		done, err := check()
		if err != nil || done {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for Appwrite to finish creating the schema")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 2*time.Second)
	}
}
