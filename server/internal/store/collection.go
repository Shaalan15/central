// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Entity is implemented by every stored type.
type Entity interface {
	EntityID() string
	// EntityOrgID returns the owning organization ("" for global entities).
	EntityOrgID() string
}

// Schema describes a typed collection.
type Schema[T Entity] struct {
	SchemaInfo
	// New returns a fresh zero value to decode into.
	New func() T
	// IndexOf extracts the indexed field values.
	IndexOf func(T) map[string]any
}

// Collection is the typed API over a driver collection.
type Collection[T Entity] struct {
	schema Schema[T]
	raw    RawCollection
}

// NewCollection binds a schema to a driver.
func NewCollection[T Entity](d Driver, s Schema[T]) *Collection[T] {
	return &Collection[T]{schema: s, raw: d.Collection(s.SchemaInfo)}
}

// Schema returns the collection's schema.
func (c *Collection[T]) Schema() SchemaInfo { return c.schema.SchemaInfo }

func (c *Collection[T]) encode(v T) (Record, error) {
	id := v.EntityID()
	if !ValidID(id) {
		return Record{}, fmt.Errorf("store: invalid id %q for %s", id, c.schema.Name)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return Record{}, fmt.Errorf("store: encode %s: %w", c.schema.Name, err)
	}
	var idx map[string]any
	if c.schema.IndexOf != nil {
		idx = c.schema.IndexOf(v)
	}
	return Record{ID: id, OrgID: v.EntityOrgID(), Index: idx, Data: data}, nil
}

func (c *Collection[T]) decode(r Record) (T, error) {
	v := c.schema.New()
	if err := json.Unmarshal(r.Data, v); err != nil {
		var zero T
		return zero, fmt.Errorf("store: decode %s/%s: %w", c.schema.Name, r.ID, err)
	}
	return v, nil
}

// Get returns one entity by ID.
func (c *Collection[T]) Get(ctx context.Context, scope Scope, id string) (T, error) {
	var zero T
	if !ValidID(id) {
		return zero, ErrNotFound
	}
	r, err := c.raw.Get(ctx, scope, id)
	if err != nil {
		return zero, err
	}
	return c.decode(r)
}

// Create inserts a new entity (ErrAlreadyExists on ID or unique-index conflict).
func (c *Collection[T]) Create(ctx context.Context, scope Scope, v T) error {
	r, err := c.encode(v)
	if err != nil {
		return err
	}
	return c.raw.Insert(ctx, scope, r)
}

// Update replaces an existing entity (ErrNotFound if absent).
func (c *Collection[T]) Update(ctx context.Context, scope Scope, v T) error {
	r, err := c.encode(v)
	if err != nil {
		return err
	}
	return c.raw.Replace(ctx, scope, r)
}

// Upsert creates or replaces an entity.
func (c *Collection[T]) Upsert(ctx context.Context, scope Scope, v T) error {
	r, err := c.encode(v)
	if err != nil {
		return err
	}
	return c.raw.Upsert(ctx, scope, r)
}

// Delete removes an entity (ErrNotFound if absent).
func (c *Collection[T]) Delete(ctx context.Context, scope Scope, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	return c.raw.Delete(ctx, scope, id)
}

// Find returns one page of matches and the next-page cursor.
func (c *Collection[T]) Find(ctx context.Context, scope Scope, q Query) ([]T, string, error) {
	if err := q.Validate(c.schema.SchemaInfo); err != nil {
		return nil, "", err
	}
	recs, next, err := c.raw.Find(ctx, scope, q)
	if err != nil {
		return nil, "", err
	}
	out := make([]T, 0, len(recs))
	for _, r := range recs {
		v, err := c.decode(r)
		if err != nil {
			return nil, "", err
		}
		out = append(out, v)
	}
	return out, next, nil
}

// FindOne returns the first match or ErrNotFound.
func (c *Collection[T]) FindOne(ctx context.Context, scope Scope, q Query) (T, error) {
	q.Limit, q.After = 1, ""
	items, _, err := c.Find(ctx, scope, q)
	if err != nil {
		var zero T
		return zero, err
	}
	if len(items) == 0 {
		var zero T
		return zero, ErrNotFound
	}
	return items[0], nil
}

// All returns every match, paging through results. Use only for bounded result sets.
func (c *Collection[T]) All(ctx context.Context, scope Scope, q Query) ([]T, error) {
	var out []T
	q.Limit = MaxLimit
	q.After = ""
	for {
		page, next, err := c.Find(ctx, scope, q)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		q.After = next
	}
}

// Count returns the number of matches.
func (c *Collection[T]) Count(ctx context.Context, scope Scope, q Query) (int, error) {
	if err := q.Validate(c.schema.SchemaInfo); err != nil {
		return 0, err
	}
	return c.raw.Count(ctx, scope, q)
}

// DeleteWhere deletes every match and returns how many were deleted.
func (c *Collection[T]) DeleteWhere(ctx context.Context, scope Scope, q Query) (int, error) {
	items, err := c.All(ctx, scope, q)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if err := c.raw.Delete(ctx, scope, it.EntityID()); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}
