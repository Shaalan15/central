# Using Appwrite as Central's database

Central stores its durable state (organizations, users, agents, enrollment, commands, jobs,
audit log, metric rollups) in an **Appwrite 2.x** project through the **TablesDB** API. Both
Appwrite Cloud and self-hosted Appwrite are supported.

Only the Central server talks to Appwrite. Browsers and agents never do, and Central creates its
tables **without any client permissions and without row security**, so nothing is reachable
with anything but a server API key.

## 1. Create a project and an API key

1. Create a **dedicated project** for Central (do not share it with other apps).
2. In the project, create a **server API key** with exactly these scopes:

   | Scope | Why |
   | ----- | --- |
   | `databases.read`, `databases.write` | create/read Central's database |
   | `tables.read`, `tables.write` | create tables during migrations |
   | `columns.read`, `columns.write` | create columns during migrations |
   | `indexes.read`, `indexes.write` | create indexes during migrations |
   | `rows.read`, `rows.write` | read and write data |

   Give the key an expiry that matches your rotation policy. Treat it like a root password:
   it grants full access to Central's data.

## 2. Point Central at it

Either use the setup wizard (open the UI, enter the setup token from the server log, choose
**Appwrite Cloud** or **Self-hosted**), or configure it up front — useful for Docker,
Kubernetes and infrastructure-as-code:

```bash
CENTRAL_APPWRITE_ENDPOINT=https://fra.cloud.appwrite.io/v1   # your region, or https://appwrite.example.com/v1
CENTRAL_APPWRITE_PROJECT=<project id>
CENTRAL_APPWRITE_API_KEY_FILE=/run/secrets/appwrite_api_key   # or CENTRAL_APPWRITE_API_KEY=...
CENTRAL_APPWRITE_DATABASE_ID=central                          # optional, default "central"
CENTRAL_APPWRITE_CA_FILE=/etc/central/appwrite-ca.pem         # optional, private CA for self-hosted
```

When configured through the wizard, the API key is stored in `<data dir>/central.state.toml`
**encrypted with the master key** (`<data dir>/master.key` or `CENTRAL_MASTER_KEY`). Back up the
master key: without it the stored API key (and Central's CA) cannot be decrypted.

The wizard refuses plain-HTTP endpoints unless they are on localhost, because the API key would
travel in clear text.

## 3. What Central creates

On first start (and on every upgrade) Central runs idempotent migrations: it creates the
database if needed, one table per collection, the columns and indexes it needs, and waits until
Appwrite reports them `available`. Existing columns are never dropped or altered.

Each table has:

- `org_id` (varchar) for tenant-scoped tables — Central checks it on every read and write;
- a few typed columns used for queries (e.g. `status`, `created_at`);
- `data` (longtext) holding the entity as JSON. Secrets inside are either hashed (tokens,
  passwords) or encrypted with the master key (TOTP secrets, CA keys).

## Limits and notes

- Row counts reported by Appwrite are capped (5000 by default on self-hosted); Central uses counts
  only for display and small checks.
- Appwrite latency does not affect live views: fleet status and recent metrics are served from
  Central's memory; Appwrite is written in batches (one metrics chunk per agent per hour).
- Version check: Central requires Appwrite **2.0 or newer** (`GET /v1/health/version`).

## Testing against a real project

The storage contract tests can run against a throwaway Appwrite project:

```bash
export CENTRAL_TEST_APPWRITE_ENDPOINT=https://fra.cloud.appwrite.io/v1
export CENTRAL_TEST_APPWRITE_PROJECT=<test project id>
export CENTRAL_TEST_APPWRITE_KEY=<key with the scopes above>
go test ./server/internal/store/appwrite/ -run TestContractReal -v
```

Each test creates and deletes its own database (`ctest_<random>`).
