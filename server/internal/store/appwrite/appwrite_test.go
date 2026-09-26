// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package appwrite

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/crypto"
	"github.com/Shaalan15/central/server/internal/store"
	"github.com/Shaalan15/central/server/internal/store/appwrite/appwritefake"
	"github.com/Shaalan15/central/server/internal/store/storetest"
)

func TestMain(m *testing.M) {
	pollInitialDelay = time.Millisecond
	os.Exit(m.Run())
}

func fakeConfig(url string) config.AppwriteConfig {
	return config.AppwriteConfig{Endpoint: url + "/v1", ProjectID: "proj", DatabaseID: "central"}
}

// TestContractFake runs the store contract suite against the driver talking to the fake.
func TestContractFake(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Driver {
		f, srv := appwritefake.New(t)
		d, err := Open(fakeConfig(srv.URL), crypto.Secret(f.Key))
		if err != nil {
			t.Fatal(err)
		}
		return d
	})
}

// TestContractReal runs the suite against a real Appwrite 2.x project when configured:
//
//	CENTRAL_TEST_APPWRITE_ENDPOINT=https://fra.cloud.appwrite.io/v1
//	CENTRAL_TEST_APPWRITE_PROJECT=<project id>
//	CENTRAL_TEST_APPWRITE_KEY=<server API key with the required scopes>
//
// Each subtest uses a fresh database that is deleted afterwards. Use a throwaway project.
func TestContractReal(t *testing.T) {
	endpoint := os.Getenv("CENTRAL_TEST_APPWRITE_ENDPOINT")
	if endpoint == "" {
		t.Skip("CENTRAL_TEST_APPWRITE_ENDPOINT not set")
	}
	project, key := os.Getenv("CENTRAL_TEST_APPWRITE_PROJECT"), os.Getenv("CENTRAL_TEST_APPWRITE_KEY")
	storetest.Run(t, func(t *testing.T) store.Driver {
		cfg := config.AppwriteConfig{Endpoint: endpoint, ProjectID: project, DatabaseID: "ctest_" + crypto.RandomHex(6)}
		d, err := Open(cfg, crypto.Secret(key))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := d.db.Delete(cfg.DatabaseID); err != nil {
				t.Logf("cleanup: delete database %s: %v", cfg.DatabaseID, err)
			}
		})
		return d
	})
}

func TestMigrateIsIdempotent(t *testing.T) {
	f, srv := appwritefake.New(t)
	d, err := Open(fakeConfig(srv.URL), crypto.Secret(f.Key))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.Migrate(ctx, store.AllSchemas()); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	before := f.Requests()
	if err := d.Migrate(ctx, store.AllSchemas()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// The second run only reads (database, tables, columns, indexes): no creation requests.
	if n := f.Tables("central"); n != len(store.AllSchemas()) {
		t.Fatalf("tables = %d", n)
	}
	if n := f.Requests() - before; n > 1+len(store.AllSchemas())*5 {
		t.Fatalf("second migrate made %d requests", n)
	}
	// Tenant tables have an org_id column and index; the data column exists everywhere.
	agents, _ := f.Table("central", "agents")
	if !slices.Contains(agents.Columns, "org_id") || !slices.Contains(agents.Columns, "data") || agents.Indexes["ix_org"] == "" {
		t.Fatalf("agents table: %+v", agents)
	}
	users, _ := f.Table("central", "users")
	if users.Indexes["ix_email_unique"] != "unique" {
		t.Fatal("users.email index is not unique")
	}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	f, srv := appwritefake.New(t)

	r := Check(ctx, fakeConfig(srv.URL), crypto.Secret(f.Key))
	if !r.OK || r.ServerVersion != "2.0.3" || !r.VersionSupported || r.DatabaseExists {
		t.Fatalf("check = %+v", r)
	}

	f.SetVersion("1.8.1")
	if r := Check(ctx, fakeConfig(srv.URL), crypto.Secret(f.Key)); r.VersionSupported {
		t.Fatalf("1.x reported as supported: %+v", r)
	}
	f.SetVersion("2.1.0")

	if r := Check(ctx, fakeConfig(srv.URL), "wrong-key-0123456789"); r.OK || !strings.Contains(r.Error, "rejected") {
		t.Fatalf("wrong key: %+v", r)
	}
	f.SetDenyScope("databases.read")
	r = Check(ctx, fakeConfig(srv.URL), crypto.Secret(f.Key))
	if r.OK || len(r.MissingScopes) != 1 || r.MissingScopes[0] != "databases.read" {
		t.Fatalf("missing scope: %+v", r)
	}
	if strings.Contains(r.Error, f.Key) {
		t.Fatal("error leaks the API key")
	}
}
