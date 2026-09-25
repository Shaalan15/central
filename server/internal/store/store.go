// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package store is Central's persistence layer.
//
// Design:
//   - Entities are stored as JSON documents plus a small set of typed index fields that can be
//     queried. Each storage driver (memory, Appwrite, ...) implements the untyped Driver and
//     RawCollection interfaces; the generic Collection[T] wrapper provides the typed API.
//   - Tenant isolation is structural: every operation takes a Scope. Tenant(orgID) confines
//     reads and writes to one organization; System() is required for global collections and
//     for the few deliberate cross-tenant lookups (e.g. finding an enrollment token by ID
//     before the organization is known). Grep for "store.System()" to audit those.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by drivers. Wrap-compatible: use errors.Is.
var (
	ErrNotFound      = errors.New("store: not found")
	ErrAlreadyExists = errors.New("store: already exists")
	ErrScope         = errors.New("store: scope violation")
	ErrInvalidQuery  = errors.New("store: invalid query")
	ErrUnavailable   = errors.New("store: backend unavailable")
)

// Scope confines an operation to one organization or marks it as a deliberate system-level
// operation. The zero Scope is invalid and rejected by drivers.
type Scope struct {
	org    string
	system bool
}

// Tenant returns a scope limited to one organization. It panics on an empty ID because that
// would indicate a missing authorization step, which must never silently widen access.
func Tenant(orgID string) Scope {
	if orgID == "" {
		panic("store: Tenant scope with empty organization ID")
	}
	return Scope{org: orgID}
}

// System returns the unrestricted scope for global collections and deliberate cross-tenant
// lookups. Use sparingly and only in code paths that establish tenancy themselves.
func System() Scope { return Scope{system: true} }

// OrgID returns the organization of a tenant scope ("" for System).
func (s Scope) OrgID() string { return s.org }

// IsSystem reports whether this is the system scope.
func (s Scope) IsSystem() bool { return s.system }

// Valid reports whether the scope was constructed with Tenant or System.
func (s Scope) Valid() bool { return s.system || s.org != "" }

// String implements fmt.Stringer.
func (s Scope) String() string {
	if s.system {
		return "system"
	}
	return "org:" + s.org
}

// FieldType is the type of an indexed field.
type FieldType int

// Field types supported by all drivers.
const (
	FieldString FieldType = iota + 1
	FieldInt              // int64
	FieldBool
)

// Field declares an indexed (queryable) field of a collection.
type Field struct {
	Name string
	Type FieldType
	// Size is the maximum length for string fields.
	Size int
}

// Index declares a database index over fields.
type Index struct {
	Name   string
	Fields []string
	Unique bool
}

// SchemaInfo is the driver-facing description of a collection.
type SchemaInfo struct {
	// Name is the collection/table name (lower_snake_case).
	Name string
	// Tenant collections carry an org_id and are isolated per organization.
	Tenant  bool
	Fields  []Field
	Indexes []Index
}

// HasField reports whether name is an indexed field (or the implicit id/org_id).
func (s SchemaInfo) HasField(name string) bool {
	if name == "id" || (s.Tenant && name == "org_id") {
		return true
	}
	for _, f := range s.Fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// Record is the driver-level representation of one entity.
type Record struct {
	ID    string
	OrgID string
	// Index holds values for the schema's indexed fields: string, int64 or bool.
	Index map[string]any
	// Data is the JSON document.
	Data []byte
}

// RawCollection is implemented by drivers for each collection.
type RawCollection interface {
	Get(ctx context.Context, scope Scope, id string) (Record, error)
	Insert(ctx context.Context, scope Scope, rec Record) error
	// Replace overwrites an existing record (ErrNotFound if absent).
	Replace(ctx context.Context, scope Scope, rec Record) error
	Upsert(ctx context.Context, scope Scope, rec Record) error
	Delete(ctx context.Context, scope Scope, id string) error
	// Find returns one page of matching records and the cursor for the next page ("" at end).
	Find(ctx context.Context, scope Scope, q Query) ([]Record, string, error)
	Count(ctx context.Context, scope Scope, q Query) (int, error)
}

// DriverInfo describes a storage backend.
type DriverInfo struct {
	Name     string
	Endpoint string
	Version  string
}

// Driver is a storage backend.
type Driver interface {
	Info() DriverInfo
	// Migrate creates or updates collections to match the schemas (idempotent).
	Migrate(ctx context.Context, schemas []SchemaInfo) error
	Collection(schema SchemaInfo) RawCollection
	Ping(ctx context.Context) error
	Close() error
}

// CheckScope validates scope usage for a collection and, for writes, the record's org.
func CheckScope(schema SchemaInfo, scope Scope, recOrg string, write bool) error {
	if !scope.Valid() {
		return fmt.Errorf("%w: zero scope on %s", ErrScope, schema.Name)
	}
	if !schema.Tenant {
		if !scope.IsSystem() {
			return fmt.Errorf("%w: %s is global and requires the system scope", ErrScope, schema.Name)
		}
		return nil
	}
	if write {
		if recOrg == "" {
			return fmt.Errorf("%w: %s record without org_id", ErrScope, schema.Name)
		}
		if !scope.IsSystem() && recOrg != scope.OrgID() {
			return fmt.Errorf("%w: %s record belongs to another organization", ErrScope, schema.Name)
		}
	}
	return nil
}

// ValidID reports whether id is acceptable to every driver (Appwrite row ID rules: 1-36 chars
// of [A-Za-z0-9._-], not starting with a special character).
func ValidID(id string) bool {
	if id == "" || len(id) > 36 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '.' || r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// NormalizeEmail lowercases and trims an email address for storage and lookup.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
