// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package appwritefake is an in-process fake of the Appwrite 2.x TablesDB REST API subset used
// by Central's Appwrite driver. It is for tests only.
package appwritefake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Fake implements the subset of the Appwrite 2.x TablesDB REST API that the driver
// uses, with Appwrite's semantics for status codes, async column/index creation and JSON
// queries. It lets the store contract suite run against the real driver code in CI.
type Fake struct {
	t  *testing.T
	mu sync.Mutex
	// Project and Key are the credentials the fake accepts.
	Project string
	Key     string
	// Version is reported by /v1/health/version.
	Version string
	// DenyScope makes every request fail with a missing-scope error.
	DenyScope string
	dbs       map[string]*fakeDB
	requests  int
}

type fakeDB struct {
	tables map[string]*fakeTable
}

type fakeTable struct {
	columns map[string]*fakeColumn
	indexes map[string]*fakeIndex
	rows    map[string]map[string]any
	order   []string
}

type fakeColumn struct {
	Key    string `json:"key"`
	Type   string `json:"type"`
	Status string `json:"status"`
	listed bool
}

type fakeIndex struct {
	Key     string   `json:"key"`
	Type    string   `json:"type"`
	Status  string   `json:"status"`
	Columns []string `json:"columns"`
	listed  bool
}

// New starts a fake Appwrite server (closed when the test ends).
func New(t *testing.T) (*Fake, *httptest.Server) {
	f := &Fake{t: t, Project: "proj", Key: "secret-key-0123456789", Version: "2.0.3", dbs: map[string]*fakeDB{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, map[string]any{"message": msg, "code": status, "type": typ, "version": "2.0.3"})
}

var (
	reDB      = regexp.MustCompile(`^/v1/tablesdb/([^/]+)$`)
	reTables  = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables$`)
	reTable   = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables/([^/]+)$`)
	reColumns = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables/([^/]+)/columns(?:/([a-z]+))?$`)
	reIndexes = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables/([^/]+)/indexes$`)
	reRows    = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables/([^/]+)/rows$`)
	reRow     = regexp.MustCompile(`^/v1/tablesdb/([^/]+)/tables/([^/]+)/rows/([^/]+)$`)
)

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	p := r.URL.Path
	if p == "/v1/health/version" {
		writeJSON(w, http.StatusOK, map[string]string{"version": f.Version})
		return
	}
	if r.Header.Get("X-Appwrite-Project") != f.Project {
		apiErr(w, http.StatusNotFound, "project_not_found", "Project with the requested ID could not be found.")
		return
	}
	if r.Header.Get("X-Appwrite-Key") != f.Key {
		apiErr(w, http.StatusUnauthorized, "user_unauthorized", "The current user is not authorized to perform the requested action.")
		return
	}
	if f.DenyScope != "" {
		apiErr(w, http.StatusUnauthorized, "general_unauthorized_scope",
			"app.proj@service.cloud.appwrite.io (role: applications) missing scopes ([\""+f.DenyScope+"\"])")
		return
	}
	var body map[string]any
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			apiErr(w, http.StatusBadRequest, "general_argument_invalid", "invalid JSON body")
			return
		}
	}
	switch {
	case p == "/v1/tablesdb" && r.Method == http.MethodPost:
		id, _ := body["databaseId"].(string)
		if f.dbs[id] != nil {
			apiErr(w, http.StatusConflict, "database_already_exists", "Database already exists")
			return
		}
		f.dbs[id] = &fakeDB{tables: map[string]*fakeTable{}}
		writeJSON(w, http.StatusCreated, map[string]any{"$id": id, "name": body["name"]})
	case reDB.MatchString(p) && r.Method == http.MethodGet:
		id := reDB.FindStringSubmatch(p)[1]
		if f.dbs[id] == nil {
			apiErr(w, http.StatusNotFound, "database_not_found", "Database not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"$id": id, "name": id, "enabled": true})
	case reTables.MatchString(p):
		db := f.dbs[reTables.FindStringSubmatch(p)[1]]
		if db == nil {
			apiErr(w, http.StatusNotFound, "database_not_found", "Database not found")
			return
		}
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"total": len(db.tables), "tables": []any{}})
			return
		}
		id, _ := body["tableId"].(string)
		if db.tables[id] != nil {
			apiErr(w, http.StatusConflict, "table_already_exists", "Table already exists")
			return
		}
		if rs, _ := body["rowSecurity"].(bool); rs {
			f.t.Errorf("table %s created with row security enabled", id)
		}
		if perms, _ := body["permissions"].([]any); len(perms) != 0 {
			f.t.Errorf("table %s created with permissions %v", id, perms)
		}
		db.tables[id] = &fakeTable{columns: map[string]*fakeColumn{}, indexes: map[string]*fakeIndex{}, rows: map[string]map[string]any{}}
		writeJSON(w, http.StatusCreated, map[string]any{"$id": id})
	case reTable.MatchString(p) && r.Method == http.MethodGet:
		m := reTable.FindStringSubmatch(p)
		if f.table(m[1], m[2]) == nil {
			apiErr(w, http.StatusNotFound, "table_not_found", "Table not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"$id": m[2]})
	case reColumns.MatchString(p):
		m := reColumns.FindStringSubmatch(p)
		t := f.table(m[1], m[2])
		if t == nil {
			apiErr(w, http.StatusNotFound, "table_not_found", "Table not found")
			return
		}
		if r.Method == http.MethodGet {
			var cols []*fakeColumn
			for _, c := range t.columns {
				// Columns become available after they have been listed once (async creation).
				if c.listed {
					c.Status = "available"
				}
				c.listed = true
				cols = append(cols, c)
			}
			writeJSON(w, http.StatusOK, map[string]any{"total": len(cols), "columns": cols})
			return
		}
		key, _ := body["key"].(string)
		if t.columns[key] != nil {
			apiErr(w, http.StatusConflict, "column_already_exists", "Column already exists")
			return
		}
		t.columns[key] = &fakeColumn{Key: key, Type: m[3], Status: "processing"}
		writeJSON(w, http.StatusAccepted, map[string]any{"key": key, "type": m[3], "status": "processing"})
	case reIndexes.MatchString(p):
		m := reIndexes.FindStringSubmatch(p)
		t := f.table(m[1], m[2])
		if t == nil {
			apiErr(w, http.StatusNotFound, "table_not_found", "Table not found")
			return
		}
		if r.Method == http.MethodGet {
			var ixs []*fakeIndex
			for _, ix := range t.indexes {
				if ix.listed {
					ix.Status = "available"
				}
				ix.listed = true
				ixs = append(ixs, ix)
			}
			writeJSON(w, http.StatusOK, map[string]any{"total": len(ixs), "indexes": ixs})
			return
		}
		key, _ := body["key"].(string)
		if t.indexes[key] != nil {
			apiErr(w, http.StatusConflict, "index_already_exists", "Index already exists")
			return
		}
		var cols []string
		for _, c := range body["columns"].([]any) {
			col := c.(string)
			if t.columns[col] == nil || t.columns[col].Status != "available" {
				apiErr(w, http.StatusBadRequest, "column_not_available", "column "+col+" not available")
				return
			}
			cols = append(cols, col)
		}
		t.indexes[key] = &fakeIndex{Key: key, Type: body["type"].(string), Status: "processing", Columns: cols}
		writeJSON(w, http.StatusAccepted, t.indexes[key])
	case reRows.MatchString(p):
		m := reRows.FindStringSubmatch(p)
		t := f.table(m[1], m[2])
		if t == nil {
			apiErr(w, http.StatusNotFound, "table_not_found", "Table not found")
			return
		}
		if r.Method == http.MethodGet {
			f.listRows(w, r, m[2], t)
			return
		}
		id, _ := body["rowId"].(string)
		if t.rows[id] != nil {
			apiErr(w, http.StatusConflict, "row_already_exists", "Row with the requested ID already exists.")
			return
		}
		data, _ := body["data"].(map[string]any)
		if msg := f.validate(t, id, data); msg != "" {
			apiErr(w, http.StatusConflict, "row_already_exists", msg)
			return
		}
		t.rows[id] = normalize(data)
		t.order = append(t.order, id)
		writeJSON(w, http.StatusCreated, f.rowJSON(m[2], id, t.rows[id]))
	case reRow.MatchString(p):
		m := reRow.FindStringSubmatch(p)
		t := f.table(m[1], m[2])
		if t == nil {
			apiErr(w, http.StatusNotFound, "table_not_found", "Table not found")
			return
		}
		id := m[3]
		row := t.rows[id]
		switch r.Method {
		case http.MethodGet:
			if row == nil {
				apiErr(w, http.StatusNotFound, "row_not_found", "Row with the requested ID could not be found.")
				return
			}
			writeJSON(w, http.StatusOK, f.rowJSON(m[2], id, row))
		case http.MethodPatch, http.MethodPut:
			if row == nil && r.Method == http.MethodPatch {
				apiErr(w, http.StatusNotFound, "row_not_found", "Row with the requested ID could not be found.")
				return
			}
			data, _ := body["data"].(map[string]any)
			if msg := f.validate(t, id, data); msg != "" {
				apiErr(w, http.StatusConflict, "row_already_exists", msg)
				return
			}
			if row == nil {
				t.order = append(t.order, id)
				row = map[string]any{}
			}
			for k, v := range normalize(data) {
				row[k] = v
			}
			t.rows[id] = row
			writeJSON(w, http.StatusOK, f.rowJSON(m[2], id, row))
		case http.MethodDelete:
			if row == nil {
				apiErr(w, http.StatusNotFound, "row_not_found", "Row with the requested ID could not be found.")
				return
			}
			delete(t.rows, id)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		apiErr(w, http.StatusNotFound, "general_route_not_found", "route not found: "+r.Method+" "+p)
	}
}

// Requests returns the number of requests served.
func (f *Fake) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// SetVersion changes the reported server version.
func (f *Fake) SetVersion(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Version = v
}

// SetDenyScope makes every authenticated request fail with a missing-scope error.
func (f *Fake) SetDenyScope(scope string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DenyScope = scope
}

// TableInfo describes a table's columns and indexes (index key -> type).
type TableInfo struct {
	Columns []string
	Indexes map[string]string
	Rows    int
}

// Table returns information about a table, or false if it does not exist.
func (f *Fake) Table(db, table string) (TableInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.table(db, table)
	if t == nil {
		return TableInfo{}, false
	}
	info := TableInfo{Indexes: map[string]string{}, Rows: len(t.rows)}
	for k := range t.columns {
		info.Columns = append(info.Columns, k)
	}
	for k, ix := range t.indexes {
		info.Indexes[k] = ix.Type
	}
	sort.Strings(info.Columns)
	return info, true
}

// Tables returns the number of tables in a database.
func (f *Fake) Tables(db string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dbs[db] == nil {
		return 0
	}
	return len(f.dbs[db].tables)
}

func (f *Fake) table(db, table string) *fakeTable {
	d := f.dbs[db]
	if d == nil {
		return nil
	}
	return d.tables[table]
}

func normalize(data map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range data {
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				out[k] = float64(i)
				continue
			}
			fl, _ := n.Float64()
			out[k] = fl
			continue
		}
		out[k] = v
	}
	return out
}

// validate rejects unknown columns and unique index violations.
func (f *Fake) validate(t *fakeTable, id string, data map[string]any) string {
	for k := range data {
		if t.columns[k] == nil || t.columns[k].Status != "available" {
			return "Invalid row structure: unknown column " + k
		}
	}
	for _, ix := range t.indexes {
		if ix.Type != "unique" {
			continue
		}
		for otherID, other := range t.rows {
			if otherID == id {
				continue
			}
			same := true
			for _, c := range ix.Columns {
				if fmt.Sprint(other[c]) != fmt.Sprint(normalize(data)[c]) {
					same = false
				}
			}
			if same {
				return "Document with the requested unique attributes already exists."
			}
		}
	}
	return ""
}

func (f *Fake) rowJSON(table, id string, row map[string]any) map[string]any {
	out := map[string]any{"$id": id, "$tableId": table, "$databaseId": "db", "$permissions": []string{}}
	for k, v := range row {
		out[k] = v
	}
	return out
}

type fakeQuery struct {
	Method    string `json:"method"`
	Attribute string `json:"attribute"`
	Values    []any  `json:"values"`
}

func cmpAny(a, b any) int {
	switch x := a.(type) {
	case float64:
		y, _ := b.(float64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case bool:
		y, _ := b.(bool)
		if x == y {
			return 0
		}
		if !x {
			return -1
		}
		return 1
	default:
		return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
	}
}

func (f *Fake) listRows(w http.ResponseWriter, r *http.Request, table string, t *fakeTable) {
	var queries []fakeQuery
	params := r.URL.Query()
	for i := 0; ; i++ {
		raw := params.Get("queries[" + strconv.Itoa(i) + "]")
		if raw == "" {
			break
		}
		var q fakeQuery
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			apiErr(w, http.StatusBadRequest, "general_query_invalid", "invalid query")
			return
		}
		for j, v := range q.Values {
			if n, ok := v.(float64); ok {
				q.Values[j] = n
			}
		}
		queries = append(queries, q)
	}
	get := func(id, attr string) any {
		if attr == "$id" {
			return id
		}
		return t.rows[id][attr]
	}
	var ids []string
	for _, id := range t.order {
		if t.rows[id] == nil {
			continue
		}
		ok := true
		for _, q := range queries {
			v := get(id, q.Attribute)
			switch q.Method {
			case "equal":
				ok = ok && slices.ContainsFunc(q.Values, func(x any) bool { return cmpAny(v, x) == 0 })
			case "notEqual":
				ok = ok && !slices.ContainsFunc(q.Values, func(x any) bool { return cmpAny(v, x) == 0 })
			case "lessThan":
				ok = ok && cmpAny(v, q.Values[0]) < 0
			case "lessThanEqual":
				ok = ok && cmpAny(v, q.Values[0]) <= 0
			case "greaterThan":
				ok = ok && cmpAny(v, q.Values[0]) > 0
			case "greaterThanEqual":
				ok = ok && cmpAny(v, q.Values[0]) >= 0
			case "startsWith":
				ok = ok && strings.HasPrefix(fmt.Sprint(v), fmt.Sprint(q.Values[0]))
			}
		}
		if ok {
			ids = append(ids, id)
		}
	}
	total := len(ids)
	var orders []fakeQuery
	limit, cursor := 25, ""
	for _, q := range queries {
		switch q.Method {
		case "orderAsc", "orderDesc":
			orders = append(orders, q)
		case "limit":
			limit = int(q.Values[0].(float64))
		case "cursorAfter":
			cursor = q.Values[0].(string)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool {
		for _, o := range orders {
			c := cmpAny(get(ids[i], o.Attribute), get(ids[j], o.Attribute))
			if o.Method == "orderDesc" {
				c = -c
			}
			if c != 0 {
				return c < 0
			}
		}
		return false
	})
	if cursor != "" {
		if t.rows[cursor] == nil {
			apiErr(w, http.StatusBadRequest, "general_cursor_not_found", "Invalid cursor")
			return
		}
		idx := slices.Index(ids, cursor)
		ids = ids[idx+1:]
	}
	if len(ids) > limit {
		ids = ids[:limit]
	}
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, f.rowJSON(table, id, t.rows[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "rows": rows})
}
