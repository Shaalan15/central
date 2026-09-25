// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"fmt"
)

// Op is a comparison operator.
type Op int

// Supported operators. Values are string, int64 or bool; In takes []string or []int64.
const (
	OpEq Op = iota + 1
	OpNe
	OpLt
	OpLte
	OpGt
	OpGte
	OpIn
	// OpPrefix matches strings starting with the value.
	OpPrefix
)

// Cond is one condition on an indexed field.
type Cond struct {
	Field string
	Op    Op
	Value any
}

// Query selects records. Conditions are ANDed.
type Query struct {
	Where []Cond
	// OrderBy is an indexed field or "id" (default). Ties are broken by id.
	OrderBy string
	Desc    bool
	// Limit defaults to DefaultLimit and is capped at MaxLimit.
	Limit int
	// After is the cursor returned by the previous page.
	After string
}

// Limits for Query.Limit.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Where starts a query with one condition.
func Where(field string, op Op, value any) Query {
	return Query{Where: []Cond{{Field: field, Op: op, Value: value}}}
}

// Eq is shorthand for Where(field, OpEq, value).
func Eq(field string, value any) Query { return Where(field, OpEq, value) }

// And adds a condition.
func (q Query) And(field string, op Op, value any) Query {
	q.Where = append(append([]Cond(nil), q.Where...), Cond{Field: field, Op: op, Value: value})
	return q
}

// Order sets the sort order.
func (q Query) Order(field string, desc bool) Query {
	q.OrderBy, q.Desc = field, desc
	return q
}

// Page sets limit and cursor.
func (q Query) Page(limit int, after string) Query {
	q.Limit, q.After = limit, after
	return q
}

// EffectiveLimit returns the bounded limit.
func (q Query) EffectiveLimit() int {
	switch {
	case q.Limit <= 0:
		return DefaultLimit
	case q.Limit > MaxLimit:
		return MaxLimit
	default:
		return q.Limit
	}
}

// Validate checks that the query only references indexed fields with well-typed values.
func (q Query) Validate(schema SchemaInfo) error {
	if q.OrderBy != "" && !schema.HasField(q.OrderBy) {
		return fmt.Errorf("%w: %s cannot be ordered by %q", ErrInvalidQuery, schema.Name, q.OrderBy)
	}
	for _, c := range q.Where {
		if !schema.HasField(c.Field) {
			return fmt.Errorf("%w: %s has no indexed field %q", ErrInvalidQuery, schema.Name, c.Field)
		}
		switch v := c.Value.(type) {
		case string, int64, bool:
			if c.Op == OpIn {
				return fmt.Errorf("%w: OpIn needs a slice", ErrInvalidQuery)
			}
			if c.Op == OpPrefix {
				if _, ok := v.(string); !ok {
					return fmt.Errorf("%w: OpPrefix needs a string", ErrInvalidQuery)
				}
			}
		case []string, []int64:
			if c.Op != OpIn {
				return fmt.Errorf("%w: slice value requires OpIn", ErrInvalidQuery)
			}
		default:
			return fmt.Errorf("%w: unsupported value type %T for %q", ErrInvalidQuery, c.Value, c.Field)
		}
		if c.Op < OpEq || c.Op > OpPrefix {
			return fmt.Errorf("%w: unknown operator", ErrInvalidQuery)
		}
	}
	return nil
}
