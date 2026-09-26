// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package appwrite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/appwrite/sdk-for-go/v7/models"
	"github.com/appwrite/sdk-for-go/v7/query"

	"github.com/Shaalan15/central/server/internal/store"
)

type collection struct {
	d      *Driver
	schema store.SchemaInfo
}

func (c *collection) table() string { return c.schema.Name }

// rowData is the column payload written to Appwrite.
func (c *collection) rowData(rec store.Record) map[string]any {
	m := map[string]any{colData: string(rec.Data)}
	if c.schema.Tenant {
		m[colOrg] = rec.OrgID
	}
	for _, f := range c.schema.Fields {
		v, ok := rec.Index[f.Name]
		if !ok {
			switch f.Type {
			case store.FieldInt:
				v = int64(0)
			case store.FieldBool:
				v = false
			default:
				v = ""
			}
		}
		m[f.Name] = v
	}
	return m
}

func (c *collection) toRecord(raw []byte) (store.Record, error) {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return store.Record{}, fmt.Errorf("appwrite: decode row: %w", err)
	}
	id, _ := generic["$id"].(string)
	org, _ := generic[colOrg].(string)
	data, _ := generic[colData].(string)
	rec := store.Record{ID: id, OrgID: org, Data: []byte(data), Index: map[string]any{}}
	for _, f := range c.schema.Fields {
		switch f.Type {
		case store.FieldInt:
			if n, ok := generic[f.Name].(float64); ok {
				rec.Index[f.Name] = int64(n)
			} else {
				rec.Index[f.Name] = int64(0)
			}
		case store.FieldBool:
			b, _ := generic[f.Name].(bool)
			rec.Index[f.Name] = b
		default:
			s, _ := generic[f.Name].(string)
			rec.Index[f.Name] = s
		}
	}
	if !c.schema.Tenant {
		rec.OrgID = ""
	}
	return rec, nil
}

func (c *collection) visible(scope store.Scope, rec store.Record) bool {
	return !c.schema.Tenant || scope.IsSystem() || rec.OrgID == scope.OrgID()
}

func (c *collection) getRow(ctx context.Context, id string) (store.Record, error) {
	var row *models.Row
	err := call(ctx, true, func() error {
		var err error
		row, err = c.d.db.GetRow(c.d.cfg.DatabaseID, c.table(), id)
		return err
	})
	if err != nil {
		return store.Record{}, err
	}
	var raw json.RawMessage
	if err := row.Decode(&raw); err != nil {
		return store.Record{}, fmt.Errorf("appwrite: decode row: %w", err)
	}
	return c.toRecord(raw)
}

func (c *collection) Get(ctx context.Context, scope store.Scope, id string) (store.Record, error) {
	if err := store.CheckScope(c.schema, scope, "", false); err != nil {
		return store.Record{}, err
	}
	rec, err := c.getRow(ctx, id)
	if err != nil {
		return store.Record{}, err
	}
	if !c.visible(scope, rec) {
		return store.Record{}, store.ErrNotFound
	}
	return rec, nil
}

func (c *collection) prepareWrite(scope store.Scope, rec *store.Record) error {
	if !c.schema.Tenant {
		rec.OrgID = ""
	}
	return store.CheckScope(c.schema, scope, rec.OrgID, true)
}

// checkExisting enforces that an existing row may only be replaced within its own org.
func (c *collection) checkExisting(ctx context.Context, scope store.Scope, rec store.Record) (bool, error) {
	existing, err := c.getRow(ctx, rec.ID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !c.visible(scope, existing) {
		return true, store.ErrNotFound
	}
	if existing.OrgID != rec.OrgID {
		return true, fmt.Errorf("%w: cannot move %s/%s between organizations", store.ErrScope, c.schema.Name, rec.ID)
	}
	return true, nil
}

func (c *collection) Insert(ctx context.Context, scope store.Scope, rec store.Record) error {
	if err := c.prepareWrite(scope, &rec); err != nil {
		return err
	}
	return call(ctx, false, func() error {
		_, err := c.d.db.CreateRow(c.d.cfg.DatabaseID, c.table(), rec.ID, c.rowData(rec))
		return err
	})
}

func (c *collection) Replace(ctx context.Context, scope store.Scope, rec store.Record) error {
	if err := c.prepareWrite(scope, &rec); err != nil {
		return err
	}
	exists, err := c.checkExisting(ctx, scope, rec)
	if err != nil {
		return err
	}
	if !exists {
		return store.ErrNotFound
	}
	return call(ctx, true, func() error {
		_, err := c.d.db.UpdateRow(c.d.cfg.DatabaseID, c.table(), rec.ID, c.d.db.WithUpdateRowData(c.rowData(rec)))
		return err
	})
}

func (c *collection) Upsert(ctx context.Context, scope store.Scope, rec store.Record) error {
	if err := c.prepareWrite(scope, &rec); err != nil {
		return err
	}
	exists, err := c.checkExisting(ctx, scope, rec)
	if err != nil {
		if exists && errors.Is(err, store.ErrNotFound) {
			return store.ErrAlreadyExists // row exists in another org: never overwrite it
		}
		return err
	}
	return call(ctx, true, func() error {
		_, err := c.d.db.UpsertRow(c.d.cfg.DatabaseID, c.table(), rec.ID, c.d.db.WithUpsertRowData(c.rowData(rec)))
		return err
	})
}

func (c *collection) Delete(ctx context.Context, scope store.Scope, id string) error {
	if _, err := c.Get(ctx, scope, id); err != nil {
		return err
	}
	return call(ctx, true, func() error {
		_, err := c.d.db.DeleteRow(c.d.cfg.DatabaseID, c.table(), id)
		if errors.Is(mapErr(err), store.ErrNotFound) {
			return nil // already gone (e.g. a retried delete)
		}
		return err
	})
}

func (c *collection) buildQueries(scope store.Scope, q store.Query) ([]string, error) {
	if err := store.CheckScope(c.schema, scope, "", false); err != nil {
		return nil, err
	}
	if err := q.Validate(c.schema); err != nil {
		return nil, err
	}
	var qs []string
	if c.schema.Tenant && !scope.IsSystem() {
		qs = append(qs, query.Equal(colOrg, scope.OrgID()))
	}
	for _, cond := range q.Where {
		attr := cond.Field
		if attr == "id" {
			attr = "$id"
		}
		qs = append(qs, translate(attr, cond))
	}
	return qs, nil
}

func translate(attr string, c store.Cond) string {
	switch c.Op {
	case store.OpNe:
		return query.NotEqual(attr, c.Value)
	case store.OpLt:
		return query.LessThan(attr, c.Value)
	case store.OpLte:
		return query.LessThanEqual(attr, c.Value)
	case store.OpGt:
		return query.GreaterThan(attr, c.Value)
	case store.OpGte:
		return query.GreaterThanEqual(attr, c.Value)
	case store.OpPrefix:
		return query.StartsWith(attr, c.Value)
	case store.OpIn:
		var vals []any
		switch list := c.Value.(type) {
		case []string:
			for _, v := range list {
				vals = append(vals, v)
			}
		case []int64:
			for _, v := range list {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			// Empty IN matches nothing; Appwrite rejects empty value lists.
			return query.Equal("$id", "\x00no-match")
		}
		return query.Equal(attr, vals)
	default:
		return query.Equal(attr, c.Value)
	}
}

type rowList struct {
	Total int               `json:"total"`
	Rows  []json.RawMessage `json:"rows"`
}

func (c *collection) Find(ctx context.Context, scope store.Scope, q store.Query) ([]store.Record, string, error) {
	qs, err := c.buildQueries(scope, q)
	if err != nil {
		return nil, "", err
	}
	order := q.OrderBy
	if order == "" || order == "id" {
		order = "$id"
	}
	if q.Desc {
		qs = append(qs, query.OrderDesc(order))
	} else {
		qs = append(qs, query.OrderAsc(order))
	}
	if order != "$id" {
		// Deterministic tie-break so cursors are stable.
		if q.Desc {
			qs = append(qs, query.OrderDesc("$id"))
		} else {
			qs = append(qs, query.OrderAsc("$id"))
		}
	}
	limit := q.EffectiveLimit()
	qs = append(qs, query.Limit(limit+1))
	if q.After != "" {
		qs = append(qs, query.CursorAfter(q.After))
	}
	var list rowList
	err = call(ctx, true, func() error {
		res, err := c.d.db.ListRows(c.d.cfg.DatabaseID, c.table(), c.d.db.WithListRowsQueries(qs), c.d.db.WithListRowsTotal(false))
		if err != nil {
			return err
		}
		return res.Decode(&list)
	})
	if err != nil {
		return nil, "", err
	}
	out := make([]store.Record, 0, min(len(list.Rows), limit))
	for i, raw := range list.Rows {
		if i == limit {
			break
		}
		rec, err := c.toRecord(raw)
		if err != nil {
			return nil, "", err
		}
		if !c.visible(scope, rec) {
			// Defense in depth: never return another tenant's row even if the query filter failed.
			return nil, "", fmt.Errorf("%w: appwrite returned a row from another organization", store.ErrScope)
		}
		out = append(out, rec)
	}
	next := ""
	if len(list.Rows) > limit && len(out) > 0 {
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// Count returns the number of matches. Appwrite caps counts (5000 by default on self-hosted);
// callers use counts for display and small-set checks only.
func (c *collection) Count(ctx context.Context, scope store.Scope, q store.Query) (int, error) {
	qs, err := c.buildQueries(scope, q)
	if err != nil {
		return 0, err
	}
	qs = append(qs, query.Limit(1))
	var list rowList
	err = call(ctx, true, func() error {
		res, err := c.d.db.ListRows(c.d.cfg.DatabaseID, c.table(), c.d.db.WithListRowsQueries(qs), c.d.db.WithListRowsTotal(true))
		if err != nil {
			return err
		}
		return res.Decode(&list)
	})
	if err != nil {
		return 0, err
	}
	return min(list.Total, math.MaxInt32), nil
}
