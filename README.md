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

```
Client
   │
   ├── Go CLI (phantom/)        ← developer interface
   │
   ▼
FastAPI (stateless API layer)
   │
   ├── PostgreSQL -> secrets, keys, audit logs, sessions
   ├── Redis     -> expiry coordination + rate limiting + distributed locks
   ├── RabbitMQ  -> async email & webhook notification queue
   └── Jaeger    -> OpenTelemetry traces (OTLP) - one request's full journey
                    across every hop above, including into the async worker
```

```
phantom_share/
├── main.py                            # App entrypoint: registers routers, runs lifespan (DB pool, Redis, expiry worker)
├── Dockerfile                         # Builds the FastAPI app image
├── docker-compose.yml                 # Orchestrates app + Postgres + Redis + RabbitMQ + Jaeger with healthchecks
├── .dockerignore                      # Keeps secrets, dev artifacts, and docs out of the image
├── pytest.ini                         # asyncio strict mode, pythonpath=. so `app` imports resolve from tests/
├── database/
│   └── setup.sql                      # PostgreSQL DDL - auto-run on first Postgres boot via docker-entrypoint-initdb.d
├── requirements.txt                   # Full pinned dependencies (pip freeze) - includes OpenTelemetry packages
├── requirements-dev.txt               # Test-only deps: pytest-asyncio, testcontainers
├── tests/
│   ├── conftest.py                    # Shared fixtures: real Postgres/Redis via testcontainers, loads actual database/setup.sql
│   ├── unit/
│   │   ├── test_helper_crypto.py      # DEK/KEK wrap-unwrap, tamper detection, KEK loading paths
│   │   └── test_security.py           # Password hashing, JWT lifecycle, signed share tokens, get_current_user branching
│   └── integration/
│       ├── test_rate_limit.py         # Sliding-window Lua script under real concurrency, fail-open behavior
│       └── test_cleanup_lock.py       # Distributed lock races, sweep triggers, against real Postgres triggers/constraints
└── app/
    ├── core/                          # Infrastructure - wiring the app together
    │   ├── config.py                  # All settings via environment variables (Pydantic Settings + logging config)
    │   ├── database.py                # Async PostgreSQL connection pool (psycopg3, deprecation warnings resolved)
    │   ├── redis_client.py            # Async Redis client - expiry sentinel keys
    │   ├── rate_limit.py              # Atomic sliding window rate limiting via Redis Lua script
    │   ├── security.py                # JWT creation/validation, signed share tokens, password hashing
    │   ├── permissions.py             # RBAC - FastAPI dependency factories (require_user, require_admin)
    │   ├── tracing.py                 # OTel setup: TracerProvider, OTLP/console exporter, FastAPI+psycopg+redis auto-instrumentation
    │   └── amqp_tracing.py            # Manual trace-context inject/extract for the RabbitMQ hop (no official aio-pika instrumentation exists)
    │
    ├── middleware/
    │   └── audit.py                   # Extracts client IP, attaches to request.state, adds security headers
    │
    ├── routers/                       # HTTP layer - request validation, auth, responses
    │   ├── auth.py                    # /api/auth/*    - register, login, refresh (audited), logout
    │   ├── secrets.py                 # /api/secrets/* - create, retrieve, delete, list, rotate key
    │   ├── admin.py                   # /api/admin/*   - user management + audit log (admin only, all actions audited)
    │   └── stats.py                   # /api/stats     - enhanced usage statistics
    │
    ├── services/                      # Business logic - called by routers
    │   ├── key_service.py             # Generates per-secret DEKs, wraps with master KEK, handles rotation
    │   ├── audit_service.py           # Inserts rows into audit_logs with actor, IP, and severity level
    │   ├── notification_service.py    # Publishes email + webhook events to RabbitMQ queue
    |   ├── notification_worker.py     # Consumes notification events from queue and sends email, in case of NACK, retries from DLQ.
    │   └── cleanup_service.py         # Two-track expiry: Redis keyspace events (fast) + periodic DB sweep (fallback)
    │                                  # Distributed Redis lock prevents duplicate deletions across instances
    │
    ├── helper.py                      # ChaCha20-Poly1305 encrypt/decrypt, DEK/KEK wrap, QR code generation
    └── schemas.py                     # All Pydantic v2 request and response models, enums, and validators

phantom/                               # Go CLI tool
├── cmd/
│   ├── root.go                        # Cobra root command + global flags
│   ├── auth.go                        # register, login, refresh, logout, me
│   ├── secrets.go                     # create, get, delete, list, rotate-key
│   ├── admin.go                       # user management, role changes, audit logs
│   ├── audit.go                       # query audit log
│   ├── stats.go                       # view usage stats
│   ├── ping.go                        # health check
│   └── config.go                      # CLI config management (base URL, token storage)
└── internal/
    ├── api/client.go                  # HTTP client wrapping all API calls
    ├── config/config.go               # Persistent CLI config (stored locally)
    └── output/output.go               # Formatted terminal output helpers
```

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

Two layers, run separately since they need different things:

```bash
pip install -r requirements.txt -r requirements-dev.txt

pytest tests/unit -v          # no external services needed
pytest tests/integration -v   # needs Docker running (spins up real Postgres + Redis)
```

**Unit tests** (`tests/unit/`) cover pure logic with no I/O: DEK/KEK wrap-unwrap round trips and tamper detection in the encryption helpers, JWT and signed-share-token creation/validation/expiry, password hashing, and the branching logic in `get_current_user` (wrong token type, revoked session, inactive user).

**Integration tests** (`tests/integration/`) run against real, ephemeral Postgres and Redis containers via [Testcontainers](https://testcontainers.com/) - not mocks - loading the actual `database/setup.sql` schema, so the real triggers (`calculate_expiration`, `delete_secret_if_fully_viewed`, etc.) are exercised exactly as they run in production. These specifically stress-test the concurrency guarantees the architecture claims to provide:

- The Redis distributed lock: 20 concurrent `acquire_lock()` calls on the same key, asserting exactly one wins
- Double-deletion prevention: 10 concurrent instances racing to delete the same secret, asserting exactly one DELETE and one audit log entry
- The rate limiter's Lua script atomicity: firing 2× the configured limit concurrently and asserting exactly the configured number succeed
- The fallback sweep's global lock, and its three cleanup paths (expired/over-viewed secrets, inactive users past their deletion grace period, revoked/expired sessions)

This is also how a real off-by-one bug in the rate limiter's boundary condition got caught - the Lua script and the Python caller disagreed about what a returned count meant on the accept path vs. the reject path, silently rejecting the one request that should have been allowed at exactly the configured limit.

---

## Observability (Distributed Tracing)

Every request is traced end-to-end with **OpenTelemetry**, viewable in **Jaeger** (bundled in `docker-compose.yml` at `http://localhost:16686`).

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

FastAPI, Postgres (`psycopg`), and Redis are covered by official OpenTelemetry auto-instrumentation with no manual span code required (`app/core/tracing.py`). RabbitMQ has **no official instrumentation for `aio-pika`**, so that hop is bridged manually (`app/core/amqp_tracing.py`): the publisher injects the current trace context into the AMQP message headers as it publishes, and the consumer - running later, in a completely separate async task with no shared Python state - extracts that context back out and continues the same trace. Retries through the dead-letter queue reuse the original headers, so a failed-then-retried notification shows up as more spans on the *same* trace rather than a disconnected one.

Background workers (`cleanup_service.py`'s expiry deletion and fallback sweep) get their own manually-created root spans, since they run on a timer/event loop rather than inside an HTTP request - without this, their DB/Redis spans would have no parent to attach to.

```bash
# Toggle exporters via env var - defaults to OTLP -> Jaeger
OTEL_TRACES_EXPORTER=console   # print spans to stdout instead, for local debugging without Jaeger running
```

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

### Auth

```
POST /api/auth/register       { email, username, password }
POST /api/auth/login          { email, password }            -> { access_token, refresh_token }
POST /api/auth/refresh        { refresh_token }              -> { access_token, refresh_token }  [audited]
POST /api/auth/logout         { refresh_token }              (revokes session)
GET  /api/auth/me                                            (current user info)
```

### Secrets

```
POST   /api/secrets                    Create a secret (auth optional)
GET    /api/secrets/{id}               Retrieve via share URL (?token=&access_password=)
POST   /api/secrets/{id}               Retrieve programmatically (token in query, password in body)
GET    /api/secrets/{id}/info          Metadata only - no content, no auth required
DELETE /api/secrets/{id}               Hard-delete (owner or admin)
GET    /api/secrets                    List own secrets (paginated + filtered, auth required)
POST   /api/secrets/{id}/rotate-key    Rotate encryption key (server-encrypted secrets only)
```

### Admin (admin role required)

```
GET    /api/admin/audit-logs               Query audit log (paginated, filterable by severity)
DELETE /api/admin/cleanup                  Manual sweep
GET    /api/admin/users                    List all users (paginated)
PATCH  /api/admin/users/{id}/role          Change role (admin | user | readonly)
PATCH  /api/admin/users/{id}/switch        Toggle active status
```

### Stats (public)

```
GET /api/stats                             Active secrets, total created, total viewed
```

---

## Go CLI — Quick Start

```bash
cd phantom
go build -o phantom.exe .

# Register and log in
phantom auth register
phantom auth login

# Work with secrets
phantom secrets create
phantom secrets list
phantom secrets get <id>
phantom secrets delete <id>

# Admin
phantom admin users
phantom admin audit-logs

# Utilities
phantom ping
phantom stats
```

The CLI persists your base URL and auth tokens locally so you don't need to pass them on every command.

---

## Backend Quick Start (Docker)

```bash
git clone https://github.com/superb-striker/phantom-share
cd phantom-share
```

Create a `.env` file:

```env
SECRET_ENCRYPTION_KEY=
JWT_SECRET_KEY=
SIGNED_URL_SECRET=
DATABASE_URL=
REDIS_URL=
RABBITMQ_URL=
SMTP_USERNAME=
SMTP_PASSWORD=

# Optional - defaults to localhost:4317 (matches the bundled Jaeger container)
OTEL_EXPORTER_OTLP_ENDPOINT=

# Used by docker-compose to provision Postgres and RabbitMQ containers
POSTGRES_USERNAME=
POSTGRES_PASSWORD=
RABBITMQ_USERNAME=
RABBITMQ_PASSWORD=
```

> **Note:** `DATABASE_URL`, `REDIS_URL`, `RABBITMQ_URL`, and `OTEL_EXPORTER_OTLP_ENDPOINT` from `.env` are overridden by the `environment:` block in `docker-compose.yml` for the `phantom-share` service, so the app talks to `postgres`, `redis`, `rabbitmq`, and `jaeger` by container/service name instead of `localhost`. The values above still matter for anyone running the app outside Docker (see fallback section below).

Build and start everything (API + Postgres + Redis + RabbitMQ + Jaeger):

```bash
docker compose up --build
```

The Postgres container automatically runs `database/setup.sql` on first boot via `docker-entrypoint-initdb.d` - no manual DDL step needed. All services wait on healthchecks before the API container starts.

Interactive docs -> http://localhost:8000/docs
Traces (Jaeger UI) -> http://localhost:16686

To stop everything:

```bash
docker compose down          # add -v to also wipe the named volumes (postgres_data, rabbitmq_data, redis_data)
```

<details>
<summary><strong>Manual setup without Docker (fallback)</strong></summary>

```bash
python -m venv env
env\Scripts\activate        # Windows
source env/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

Run the DDL (idempotent - safe to re-run):

```bash
# paste contents of database/setup.sql into your PostgreSQL client
```

Setup Redis and RabbitMQ:

```bash
# Ubuntu
sudo apt-get install -y redis-server
```

Start services and the server:

```bash
sudo systemctl start redis-server
redis-cli ping              # EXPECTED OUTPUT: PONG
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
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
- Local/dev orchestration via Docker Compose - Postgres, Redis, RabbitMQ, Jaeger, and the API each run in their own container, with healthchecks gating startup order so the app never starts before its dependencies are ready.
- Distributed tracing means a slow or failing request can be diagnosed by following one trace across every service it touched, instead of correlating logs by hand across four different containers.
