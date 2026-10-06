# 👻 Phantom Share

A production-style backend system with CLI support for securely sharing secrets - featuring envelope encryption with zero plaintext persistence, real-time destruction via distributed expiry coordination, async RabbitMQ notifications, atomic Redis rate limiting, and a Go CLI for developer-friendly access.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-async-green?logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-8-red?logo=redis)
![RabbitMQ](https://img.shields.io/badge/RabbitMQ-notifications-orange?logo=rabbitmq)
![Go](https://img.shields.io/badge/CLI-Go-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![Pytest](https://img.shields.io/badge/Tests-pytest-0A9EDC?logo=pytest)
![OpenTelemetry](https://img.shields.io/badge/Tracing-OpenTelemetry-black?logo=opentelemetry)
![Jaeger](https://img.shields.io/badge/Traces-Jaeger-66CFE3?logo=jaegertracing)
![Railway](https://img.shields.io/badge/Deployed-Railway-purple?logo=railway)

<!-- 🚀 Live: https://phantom-share-production.up.railway.app  
📖 Interactive docs: https://phantom-share-production.up.railway.app/docs -->

---

## Why this project matters

This isn't just a CRUD API. It demonstrates:

- Secure data handling (encryption, key management)
- Distributed expiry coordination (Redis + DB fallback)
- Multi-instance safe distributed locking for secret expiry
- Stateless + stateful auth design (JWT + refresh rotation)
- Real-world backend concerns (race conditions, audit trails)
- Async message queue architecture (RabbitMQ) for notifications
- Distributed tracing across HTTP → Postgres → Redis → RabbitMQ, including manual context propagation over AMQP where no auto-instrumentation exists
- A real test suite - unit tests plus integration tests against actual Postgres/Redis containers, not mocks, exercising the concurrency guarantees directly

---

## Features

- 🔑 **Envelope Encryption** - per-secret DEK wrapped by a master KEK (ChaCha20-Poly1305)
- 📱 **Optional E2E Encryption** - client-side mode where server never sees plaintext
- ⚡ **Real-Time Expiry** - Redis keyspace notifications trigger instant deletion
- 🔒 **Distributed Locking** - Redis-based lock on expiry worker, safe for multi-instance deployments
- 💣 **Burn After Read** - secrets auto-delete after max views (DB trigger enforced)
- 🔗 **Signed Share Links** - stateless HMAC tokens + QR codes
- 👥 **Recipient Allow Lists** - restrict secrets to verified email addresses and retain view history
- 🌐 **Location Policies** - restrict signed links by CIDR, country, or both
- 🗂️ **Secret Versioning** - conflict-safe text and file updates, restoration, and re-encryption with rotated DEKs
- 📎 **Encrypted File Sharing** - ClamAV scanning before encrypted S3-compatible storage
- 📏 **Per-user Quotas** - atomic Redis reservations for active-secret and file-storage limits
- 🔐 **JWT Auth** - access tokens + rotating refresh tokens with revocation
- 🛡️ **RBAC** - `readonly -> user -> admin` role hierarchy (backed by enums for type safety)
- 🚦 **Rate Limiting** - atomic sliding window per user/IP via Redis Lua script
- 📊 **Audit Logging** - every sensitive action tracked with actor, IP, and severity level
- 🔔 **Async Notifications** - RabbitMQ-backed email + webhook on secret access
- 🖥️ **Go CLI** - developer-friendly command-line tool to interact with the backend (no Postman or curl needed)
- 🔭 **Distributed Tracing** - OpenTelemetry spans across FastAPI, Postgres, Redis, and RabbitMQ - including manually propagated context through AMQP headers so one HTTP request's trace continues into the async notification worker, viewable in Jaeger
- 🧪 **Real Test Suite** - unit tests for crypto/JWT/token logic + integration tests against live Postgres/Redis via Testcontainers, directly exercising distributed-lock races and rate-limiter concurrency rather than asserting on mocks

---

## System Architecture

![Architecture Diagram](docs/architecture-improved.svg)

---

## Encryption Flow

```
plaintext
    │
    ▼  encrypt with DEK (ChaCha20-Poly1305)
ciphertext + nonce  ──► stored in secrets.content / secrets.nonce

DEK  ──► wrapped with master KEK  ──► stored in secret_keys.wrapped_dek
```

- KEK never touches the database
- Plaintext DEK exists only in memory during encrypt/decrypt operations

---

## Expiry System

Secrets are destroyed via three coordinated mechanisms:

1. **Redis keyspace events** (fast path) - fires the moment the TTL sentinel key expires, triggers immediate hard-delete
2. **PostgreSQL trigger** - deletes the row the instant `view_count >= max_views` on UPDATE, before the app layer returns
3. **DB fallback sweep** - runs every 10 minutes, catches anything missed during Redis downtime. Also purges expired sessions and inactive users

The expiry worker now holds a **Redis distributed lock**, so running multiple instances of the API doesn't cause duplicate deletions.

---

## Notification Architecture

Notifications (email + webhook) are now dispatched via **RabbitMQ** instead of direct SMTP calls. When a secret is viewed, the API publishes an event to the queue; a consumer handles delivery asynchronously. This decouples notification latency from the API response path and makes the system more resilient to SMTP failures.

---

## Testing

The backend and CLI suites run separately because they use different toolchains:

```bash
pip install -r requirements.txt -r requirements-dev.txt

pytest tests/unit -v          # no external services needed
pytest tests/integration -v   # needs Docker running (spins up real Postgres + Redis)

cd cli
go test -race ./...
go vet ./...
```

**Unit tests** (`tests/unit/`) cover encryption and tamper detection, JWT and
signed-link validation, location policies, ClamAV protocol handling, file
cryptography, and trace-context propagation.

**Integration tests** (`tests/integration/`) run against real, ephemeral Postgres and Redis containers via [Testcontainers](https://testcontainers.com/) - not mocks - running the actual dbmate migrations (requires the `dbmate` binary on PATH), so the real triggers (`calculate_expiration`, `delete_secret_if_fully_viewed`, etc.) are exercised exactly as they run in production. These specifically stress-test the concurrency guarantees the architecture claims to provide:

- The Redis distributed lock: 20 concurrent `acquire_lock()` calls on the same key, asserting exactly one wins
- Double-deletion prevention: 10 concurrent instances racing to delete the same secret, asserting exactly one DELETE and one audit log entry
- The rate limiter's Lua script atomicity: firing 2× the configured limit concurrently and asserting exactly the configured number succeed
- The fallback sweep's global lock, and its three cleanup paths (expired/over-viewed secrets, inactive users past their deletion grace period, revoked/expired sessions)
- Email allow lists, verified-recipient access, view tracking, version restore,
  and CIDR/country policy behavior
- Malware rejection, encrypted file round trips, tamper detection, and the
  scan-before-storage ordering guarantee
- Atomic secret and file-byte quota reservations under concurrent requests
- Migration apply, rollback, and reapply against a disposable database

This is also how a real off-by-one bug in the rate limiter's boundary condition got caught - the Lua script and the Python caller disagreed about what a returned count meant on the accept path vs. the reject path, silently rejecting the one request that should have been allowed at exactly the configured limit.

The Go suite uses in-process HTTP and SMTP fakes, so it does not require the
backend to be running. It covers every API client method, automatic token
refresh, command workflows, multipart uploads and downloads, configuration,
validation failures, and output formatting.

---

## Observability (Distributed Tracing)

Requests are traced end-to-end with **OpenTelemetry**, sent through an
OpenTelemetry Collector for memory limiting, batching, queued retry, and
backend routing, and viewable in **Jaeger** at `http://localhost:16686`.

```
POST /api/secrets/{id}  (FastAPI - auto-instrumented)
   │
   ├── SELECT ... FROM secrets   (Postgres - auto-instrumented via psycopg)
   ├── GET phantom:lock:...      (Redis - auto-instrumented)
   │
   └── amqp.publish              (manual span - see below)
          │
          └── amqp.consume.webhook   (separate process, minutes later - same trace)
```

FastAPI, Postgres (`psycopg`), Redis, HTTPX, and the S3 client (`botocore`) use
official OpenTelemetry instrumentation configured in `app/core/tracing.py`.
RabbitMQ has no official instrumentation for `aio-pika`, so
`app/core/amqp_tracing.py` injects W3C trace context into message headers and
extracts it in consumers and retry workers.

Background workers (`cleanup_service.py`'s expiry deletion and fallback sweep) get their own manually-created root spans, since they run on a timer/event loop rather than inside an HTTP request - without this, their DB/Redis spans would have no parent to attach to.

```bash
# Toggle exporters via env var - defaults to OTLP -> Collector -> Jaeger
OTEL_TRACES_EXPORTER=console   # print spans to stdout instead, for local debugging without Jaeger running

# Production controls
OTEL_TRACE_SAMPLE_RATIO=0.1    # parent-based 10% head sampling
OTEL_DEPLOYMENT_ENVIRONMENT=production
OTEL_EXPORTER_OTLP_ENDPOINT=https://your-collector.example.com:4317
OTEL_EXPORTER_OTLP_INSECURE=false
```

API responses include `X-Trace-ID`, allowing an incident report or log entry
to be matched directly to a Jaeger trace. The Compose Jaeger service uses
in-memory storage for local development; production deployments should point
the Collector at a durable, access-controlled tracing backend.

---

## Design Decisions

**Why ChaCha20-Poly1305 over AES-GCM?**
Consistent performance across all hardware without AES acceleration - common on dev machines and low-cost VMs. Also the cipher behind TLS 1.3.

**Why envelope encryption (DEK/KEK)?**
A single key leak compromises everything. With per-secret DEKs wrapped by a master KEK, blast radius is limited and per-secret key rotation is possible without re-encrypting all data.

**Why Redis keyspace notifications over a cron job?**
Cron introduces delay up to the sweep interval. Keyspace notifications fire the moment a key expires - near-instant deletion with the DB sweep as a reliability fallback.

**Why JWT + refresh tokens?**
Short-lived access tokens (15 min) limit stolen token damage without server-side state. Refresh tokens stored in the DB and rotated on each use give stateful revocation when needed - stateless performance, stateful control.

**Why PostgreSQL over MongoDB?**
The data model is relational - users, secrets, keys, and audit logs all have FK constraints and cascade requirements. A document store would lose the transactional guarantees that make the cleanup logic safe.

**Why RabbitMQ for notifications?**
Direct SMTP in the request path ties API latency to mail server availability. A message queue decouples delivery, enables retries, and keeps the API response fast regardless of downstream failures.

**Why a Go CLI?**
Go compiles to a single static binary - no runtime required. The CLI gives developers a fast, ergonomic way to interact with every API endpoint without writing curl commands or setting up Postman.

**Why a Lua script for rate limiting?**
Redis Lua scripts execute atomically on the server side. The previous non-atomic approach had a race condition between the `ZADD` and `EXPIRE` calls; the Lua script eliminates it entirely.

**Why manually propagate trace context over RabbitMQ instead of skipping that hop?**
FastAPI, Postgres, and Redis all have official OpenTelemetry auto-instrumentation; `aio-pika` doesn't. Skipping it would mean every trace involving a notification silently ends at `amqp.publish` with no visibility into whether the consumer actually succeeded, retried, or failed - exactly the part of an async architecture that's hardest to debug without tracing. Injecting the W3C trace context into AMQP message headers on publish, and extracting it on consume, keeps one trace connected across a real async/multi-process boundary instead of two disconnected ones.

**Why Testcontainers over mocking Postgres/Redis in tests?**
The interesting bugs here are concurrency bugs - the Redis distributed lock, the Lua script's atomicity, the DB triggers - none of which a mock can meaningfully exercise, since a mock doesn't have real race conditions to get wrong. Running the actual images means the tests prove the guarantees, not just that the code calls the expected functions.

---

## API Reference

### Email-restricted sharing

Pass `allowed_emails` when creating a secret to restrict retrieval to that list.
Restricted secrets require an authenticated creator. A recipient must register,
log in, and verify the same email address before the share token or password can
be used. Addresses are matched case-insensitively and duplicate entries are
removed. `max_views` remains a total limit shared by all recipients.

Every successful retrieval of an owned secret records the authenticated user,
their email at retrieval time, verification state, and the server timestamp.
The creator can query this history after the encrypted secret has burned or
expired. History defaults to 30 days beyond the secret's expiry and is controlled
by `VIEW_HISTORY_RETENTION_DAYS`. Failed attempts do not consume a view or create
a history entry.

### CIDR and country restrictions

Text-secret creation accepts `allowed_cidrs`, `allowed_countries`,
`location_policy_mode` (`all` or `any`), and `geoip_fail_closed`. For example:

```json
{
  "content": "restricted",
  "allowed_cidrs": ["203.0.113.0/24", "2001:db8:1234::/48"],
  "allowed_countries": ["IN", "SG"],
  "location_policy_mode": "all",
  "geoip_fail_closed": true
}
```

File creation uses repeatable multipart fields named `allowed_cidr` and
`allowed_country`. Updating `/api/secrets/{id}/access-policy` increments the
policy version and returns a replacement signed link; earlier links are rejected.
CIDR and country checks run before passwords, decryption, downloads, and view
accounting. Country location is approximate and can reflect a VPN or carrier
gateway rather than the recipient's physical location.

### Auth

```
POST /api/auth/register       { email, username, password }
POST /api/auth/login          { email, password }            -> { access_token, refresh_token }
POST /api/auth/refresh        { refresh_token }              -> { access_token, refresh_token }  [audited]
POST /api/auth/logout         { refresh_token }              (revokes session)
GET  /api/auth/me                                            (current user info)
POST /api/auth/verification/request                          Send a 15-minute verification code
POST /api/auth/verification/confirm { code }                 Verify account email
```

### Secrets

```
POST   /api/secrets                    Create a versioned text secret (auth required)
GET    /api/secrets/{id}               Retrieve via share URL (?token=&access_password=)
POST   /api/secrets/{id}               Retrieve programmatically (token in query, password in body)
GET    /api/secrets/view/{id}          Browser-friendly retrieval page
GET    /api/secrets/{id}/info          Metadata only - no content, no auth required
DELETE /api/secrets/{id}               Hard-delete (owner or admin)
GET    /api/secrets                    List own secrets (paginated + filtered, auth required)
POST   /api/secrets/{id}/rotate-key    Rotate encryption key (server-encrypted secrets only)
GET    /api/secrets/{id}/views         Creator-only view history, retained after burn/expiry
PUT    /api/secrets/{id}               Append a text version ({ content, expected_version, change_note })
GET    /api/secrets/{id}/versions      List versions (owner only)
POST   /api/secrets/{id}/versions/{v}/restore  Restore as a new version
PUT    /api/secrets/{id}/access-policy Replace CIDR/country policy and issue a new link
POST   /api/secrets/files              Scan, encrypt, and upload a file secret (multipart)
GET    /api/secrets/{id}/file          Download and consume a file view
PUT    /api/secrets/{id}/file          Scan and append a file version (multipart)
GET    /api/quota                      Current usage and effective limits
```

### Admin (admin role required)

```
GET    /api/admin/audit-logs               Query audit log (paginated, filterable by severity)
DELETE /api/admin/cleanup                  Manual sweep
GET    /api/admin/users                    List all users (paginated)
PATCH  /api/admin/users/{id}/role          Change role (admin | user | readonly)
PATCH  /api/admin/users/{id}/switch        Toggle active status
PATCH  /api/admin/users/{id}/quota         Override active-secret/file-byte limits
```

### Stats (public)

```
GET /api/stats                             Active secrets, total created, total viewed
```

---

## Go CLI — Quick Start

```bash
cd cli
go build -o phantom .

# Point the CLI at a non-default API when needed
./phantom config set-url http://localhost:8000

# Register and log in
./phantom auth register
./phantom auth login
./phantom auth request-verification
./phantom auth verify-email

# Work with secrets
./phantom share "database password" --allow-email alice@example.com
./phantom share --file ./credentials.pdf --expires 12h
SHARE_URL="https://example.com/api/secrets/SECRET_ID?token=SIGNED_TOKEN"
./phantom get "$SHARE_URL"
./phantom update "$SHARE_URL" "rotated password" --expected-version 1
./phantom versions "$SHARE_URL"
./phantom restore "$SHARE_URL" 1
./phantom policy "$SHARE_URL" --allow-cidr 203.0.113.0/24 --allow-country IN
./phantom views "$SHARE_URL"
./phantom quota
./phantom list

# Admin
./phantom admin users
./phantom admin quota USER_ID --max-secrets 200 --max-file-bytes 2147483648
./phantom audit --severity warning

# Utilities
./phantom config set-smtp --user me@example.com --password APP_PASSWORD --from me@example.com
./phantom ping "$SHARE_URL" --to recipient@example.com
./phantom stats
./phantom health
```

The CLI persists your base URL and auth tokens locally so you don't need to pass them on every command.
It refreshes expiring access tokens automatically, saves the rotated token pair before retrying, and asks you to log in again only when the refresh token is no longer valid.

---

## Backend Quick Start (Docker)

```bash
git clone https://github.com/superb-striker/phantom-share
cd phantom-share
```

Generate the three independent application secrets, then create `.env` using
the complete template below:

```bash
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
python -c "import secrets; print(secrets.token_hex(32))"
python -c "import secrets; print(secrets.token_hex(32))"
```

```env
APP_NAME=Phantom Share
APP_VERSION=2.0.0
DEBUG=true
BASE_URL=http://localhost:8000

DATABASE_URL=host=localhost port=5432 dbname=phantom user=phantom password=change-me
DBMATE_DATABASE_URL=postgres://phantom:change-me@localhost:5432/phantom?sslmode=disable
DB_MIN_POOL=2
DB_MAX_POOL=10
REDIS_URL=redis://localhost:6379/0
RABBITMQ_URL=amqp://phantom:change-me@localhost:5672/

CHACHA_KEY_BYTES=32
SECRET_ENCRYPTION_KEY=<first-generated-value>
JWT_SECRET_KEY=<second-generated-value>
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30
SIGNED_URL_SECRET=<third-generated-value>

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
CORS_ORIGINS=["http://localhost:3000"]

VIEW_HISTORY_RETENTION_DAYS=30
MAX_SECRET_VERSIONS=100
MAX_FILE_BYTES=52428800
DEFAULT_MAX_ACTIVE_SECRETS=100
DEFAULT_MAX_FILE_STORAGE_BYTES=1073741824

# Required outside Docker for file sharing
S3_BUCKET=phantom-share
S3_REGION=us-east-1
S3_ENDPOINT_URL=http://localhost:9000
S3_ACCESS_KEY_ID=phantom
S3_SECRET_ACCESS_KEY=phantom-local-development
CLAMAV_HOST=localhost
CLAMAV_PORT=3310
GEOIP_DATABASE_PATH=/absolute/path/to/GeoLite2-Country.mmdb
# JSON list. Only these direct peers may supply X-Forwarded-For.
TRUSTED_PROXY_CIDRS=[]

# OpenTelemetry tracing (these are the defaults for local development)
OTEL_ENABLED=true
OTEL_SERVICE_NAME=phantom-share
OTEL_DEPLOYMENT_ENVIRONMENT=development
OTEL_TRACES_EXPORTER=otlp
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_EXPORTER_OTLP_INSECURE=true
OTEL_TRACE_SAMPLE_RATIO=1.0
OTEL_EXCLUDED_URLS=/health

# Used by Docker Compose to provision infrastructure
POSTGRES_USERNAME=phantom
POSTGRES_PASSWORD=change-me
RABBITMQ_USERNAME=phantom
RABBITMQ_PASSWORD=change-me
MINIO_ROOT_USER=phantom
MINIO_ROOT_PASSWORD=phantom-local-development
```

> **Note:** `DATABASE_URL`, `REDIS_URL`, `RABBITMQ_URL`, and `OTEL_EXPORTER_OTLP_ENDPOINT` from `.env` are overridden by the `environment:` block in `docker-compose.yml` for the `phantom-share` service, so the app talks to `postgres`, `redis`, `rabbitmq`, and `otel-collector` by container/service name instead of `localhost`. The values above still matter for anyone running the app outside Docker (see fallback section below).

Build and start the API, migration runner, Postgres, Redis, RabbitMQ, MinIO,
ClamAV, OpenTelemetry Collector, and Jaeger:

```bash
docker compose up --build
```

The `migrate` service applies pending dbmate migrations after PostgreSQL is healthy. The API starts only after migrations succeed. Later migrations also run against existing dbmate-managed volumes. See the transition instructions below for volumes created by the old initializer.

Country restrictions use a local MaxMind GeoLite2/GeoIP2 country database so
recipient addresses are not sent to a third party. For Compose, place
`GeoLite2-Country.mmdb` at `data/GeoLite2-Country.mmdb`. Country-restricted
secrets fail closed when that file is absent or the address has no country.
CIDR restrictions do not require the database. Configure
`TRUSTED_PROXY_CIDRS` when the API is behind a reverse proxy; forwarded address
headers from every other peer are ignored.

Interactive docs -> http://localhost:8000/docs
Traces (Jaeger UI) -> http://localhost:16686

To stop everything:

```bash
docker compose down          # add -v to also wipe Postgres, RabbitMQ, Redis, MinIO, and ClamAV data
```

<details>
<summary><strong>Manual setup without Docker (fallback)</strong></summary>

```bash
python -m venv env
env\Scripts\activate        # Windows
source env/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

Install [dbmate](https://github.com/amacneil/dbmate#installation) (tested with
2.35.1) and PostgreSQL client tools (`pg_dump`), then configure
`DBMATE_DATABASE_URL` in `.env` as described below.

Set up PostgreSQL, Redis, RabbitMQ, S3-compatible storage, and ClamAV. For a
local environment, the easiest option is to run those dependencies from the
Compose file while running the API process on the host:

```bash
docker compose up -d postgres redis rabbitmq minio minio-init clamav otel-collector jaeger
```

Apply migrations and start the server:

```bash
./scripts/dbmate up
uvicorn main:app --reload
```

Interactive docs -> http://localhost:8000/docs

</details>

---

## Scalability Notes

- Stateless API layer scales horizontally behind a load balancer - no sticky sessions needed.
- Redis handles expiry coordination and rate limiting, keeping time-based logic out of PostgreSQL.
- All list endpoints paginated - no unbounded queries.
- Expiry worker holds a **Redis distributed lock** - safe to run multiple instances without duplicate deletions.
- RabbitMQ consumers can be scaled independently of the API to handle notification load.
- Local development uses Docker Compose for Postgres, Redis, RabbitMQ, MinIO,
  ClamAV, the OpenTelemetry Collector, Jaeger, migrations, and the API, with
  health checks and dependency conditions gating startup.
- Distributed tracing means a slow or failing request can be diagnosed by following one trace across every service it touched, instead of correlating logs by hand across four different containers.


## Database migrations

The schema is managed by [dbmate](https://github.com/amacneil/dbmate), using
`database/migrations/*.sql`. Each file has `-- migrate:up` and
`-- migrate:down` sections. Applied versions are recorded in `schema_migrations`.
The old first-boot SQL initializer is no longer used.

### Local commands

Install dbmate 2.35.1 and PostgreSQL client tools (`pg_dump` 16 or newer).
Add a PostgreSQL URL to `.env` (the application's existing `DATABASE_URL`
can remain in psycopg's `host=... dbname=...` format):

```dotenv
DBMATE_DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/phantom?sslmode=disable
```

Percent-encode special characters in the URL's username/password. Use appropriate
TLS settings for remote databases; `sslmode=disable` is for local development.
The wrapper reads `.env` without modifying it.

```bash
./scripts/dbmate status
./scripts/dbmate new add_secret_recipients
# Edit BOTH up and down sections of the generated file.
./scripts/dbmate up
./scripts/dbmate rollback   # undo the single most recent migration
./scripts/dbmate up         # reapply it
```

Commit new migrations and the generated `database/schema.sql` snapshot together.
Do not edit migrations that have already been applied in a shared environment;
create another migration instead. The schema snapshot is for review, not startup.

### Docker Compose

`docker compose up --build` runs migrations before the API starts. For explicit
migration operations on a running stack:

```bash
docker compose run --rm migrate status
```

Create migration files locally with `./scripts/dbmate new NAME`. To apply or
roll back schema changes, stop the API first so incompatible code cannot run:

```bash
docker compose stop phantom-share
docker compose run --rm migrate up
# OR: docker compose run --rm migrate rollback
# Start a version of the API compatible with the resulting schema:
docker compose start phantom-share
```

The migration container intentionally does not write a schema dump. To refresh
it after a Compose migration, run `./scripts/dbmate dump` using the local URL.
Compose passes credentials separately via `PGUSER`/`PGPASSWORD`, so special
characters in those environment values do not require URL encoding.

### Transition from the old initializer

For a fresh database, just start Compose. If your local Postgres volume already
contains the old schema, even without rows, reset that database before applying
the baseline. Stop the API and, using a URL pointing only to that disposable
local database, run `./scripts/dbmate drop` followed by `./scripts/dbmate up`.
This removes the database; do not do it to a database containing data you need.
It does not require deleting Redis or RabbitMQ volumes.

### Rollback and tests

Rollback reverses schema changes; it cannot recover data removed by a migration.
The initial migration's down section removes all application tables, functions,
and enum types. Shared PostgreSQL extensions remain installed. For future
changes, write and test the down SQL and back up valuable data before destructive
changes.

Database tests require Docker and dbmate on PATH. They migrate disposable
PostgreSQL containers, never the database configured in your `.env`:

```bash
python -m pytest
```
