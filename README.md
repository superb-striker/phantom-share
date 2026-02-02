# 👻 Phantom Share

A backend system for securely sharing sensitive information with automatic destruction. Secrets are encrypted, time-limited, and burned after reading -with no plaintext ever written to disk.

> Built with FastAPI, PostgreSQL, and Redis.

---

## Features

- 🔑 Envelope encryption : per-secret DEK wrapped by a master KEK (ChaCha20-Poly1305)
- 📱 Optional client-side E2E encryption : server never sees plaintext
- 🔐 JWT authentication with rotating refresh tokens
- 🛡️ Role-based access control (readonly -> user -> admin)
- ⚡ Redis keyspace-driven expiry with DB fallback sweep
- 🔗 Signed share links (HMAC-SHA256) + QR codes
- 🔔 Email (SMTP) and webhook notifications on view
- 📊 Audit log for every sensitive action
- 🚦 Redis sliding window rate limiting per user/IP


---

## Architecture Flow (How it works)

1. User creates a secret  
2. A **Data Encryption Key (DEK)** is generated per secret
3. Secret is encrypted using **ChaCha20-Poly1305** with the DEK
4. DEK is encrypted using a master **KEK** and stored in `secret_keys` table
5. Encrypted payload + nonce stored in PostgreSQL `secrets` table
6. Redis sentinel key created with the same TTL as the secret for expiry tracking
7. Signed share link + QR code generated for access
8. Recipient opens share link - server unwraps DEK, decrypts content, returns plaintext
9. `view_count` incremented; secret deleted immediately if `max_views` reached (DB trigger)
10. On TTL expiry:
    - Redis keyspace event triggers immediate deletion (fast path)
    - Periodic DB fallback sweep runs every 10 minutes as safety net

---

## Design Decisions

**Why ChaCha20-Poly1305 over AES-GCM?**

- ChaCha20-Poly1305 performs consistently across all hardware, even without AES acceleration (common in dev machines and low-cost VMs). It’s also used in modern protocols like TLS 1.3.
- For a system running on unknown environments, it’s a safer and more predictable choice.

**Why envelope encryption (DEK/KEK)?**

- Using a single encryption key means one leak compromises everything.
- With envelope encryption:
  - each secret has its own DEK
  - DEKs are encrypted with a master KEK  
- This limits blast radius and enables per-secret key rotation without re-encrypting all data.

**Why Redis keyspace notifications over a cron job?**  

- A cron-based cleanup introduces delay (up to the sweep interval).
- Redis keyspace notifications:
  - fire the moment a key expires
  - enable near-instant deletion
- Result: real-time expiry, with a DB sweep as a fallback for reliability.

**Why JWT + refresh tokens instead of session-only auth?**

- Short-lived access tokens (15 min) limit the damage of a stolen token - it expires quickly with no server-side invalidation needed.
- Refresh tokens are stored in the DB (`sessions` table) and rotated on each use, giving the ability to revoke access immediately
- This provides:
  - stateless performance (JWT)
  - stateful control (revocation via refresh tokens)

**Why PostgreSQL over MongoDB?**

- The data model is relational
  - users <-> secrets
  - secrets <-> keys
  - secrets <-> audit logs
- PostgreSQL provides:
  - foreign key constraints
  - transactional guarantees
  - safe cascading deletes
- A document store would lose the FK-enforced consistency (e.g. `ON DELETE SET NULL` on audit logs, `ON DELETE CASCADE` on secret keys) that makes the cleanup logic safe.

---

## Architecture overview

```python
phantom_share/
├── main.py                        # App entrypoint: registers routers, runs lifespan (DB pool, Redis, expiry worker)
├── database/
│   └── setup.sql                  # PostgreSQL DDL - run once to create all tables, indexes, and triggers
├── requirements.txt
└── app/
    ├── core/                      # Infrastructure - wiring the app together
    │   ├── config.py              # All settings via environment variables (Pydantic Settings)
    │   ├── database.py            # Async PostgreSQL connection pool (psycopg3)
    │   ├── redis_client.py        # Async Redis client - used for expiry sentinel keys
    │   ├── security.py            # JWT creation/validation, signed share tokens, password hashing
    │   └── permissions.py         # RBAC - FastAPI dependency factories (require_user, require_admin)
    │
    ├── middleware/
    │   └── audit.py               # Extracts client IP, attaches to request.state, adds security response headers
    │
    ├── routers/                   # HTTP layer - request validation, auth, responses
    │   ├── auth.py                # /api/auth/*   - register, login, refresh, logout
    │   ├── secrets.py             # /api/secrets/* - create, retrieve, delete, list, rotate key
    │   ├── admin.py               # /api/admin/*  - user management (admin only)
    │   └── stats.py               # /api/stats    - usage statistics
    │
    ├── services/                  # Business logic - called by routers
    │   ├── key_service.py         # Generates per-secret DEKs, wraps them with the master KEK, handles rotation
    │   ├── audit_service.py       # Inserts rows into audit_logs - called after every sensitive operation
    │   ├── email_service.py       # Sends SMTP email and fires webhooks when a secret is viewed
    │   └── cleanup_service.py     # Two-track expiry: Redis keyspace events (fast) + periodic DB sweep (fallback)
    │
    ├── helper.py                  # Crypto primitives (ChaCha20-Poly1305 encrypt/decrypt, DEK/KEK wrap) + QR code generation
    └── schemas.py                 # All Pydantic v2 request and response models
```

---

## Quick start

### 1. Clone and install

```bash
python -m venv env 
env/Scripts/activate        # Windows
source env/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

### 2. Configure environment

Edit `app/core/config.py` or create a `.env` file. Required fields:

```env
SECRET_ENCRYPTION_KEY
JWT_SECRET_KEY        
SIGNED_URL_SECRET    
DATABASE_URL
```

### 3. Run the DDL script

Run `database/setup.sql` against your PostgreSQL database.

The file is **idempotent** - safe to re-run. It create all tables, indexes, and triggers.

### 4. Setup Redis

```bash
# Ubuntu
sudo apt-get install -y redis-server
sudo systemctl start redis-server
redis-cli ping              # EXPECTED OUTPUT: PONG
```

### 4. Start the server

```bash
uvicorn main:app --reload
```

Interactive docs -> <http://localhost:8000/docs>

---

## API Reference

### Auth

```
POST /api/auth/register       { email, username, password }
POST /api/auth/login          { email, password }            → { access_token, refresh_token }
POST /api/auth/refresh        { refresh_token }              → { access_token, refresh_token }
POST /api/auth/logout         { refresh_token }              (revokes session)
GET  /api/auth/me                                            (current user info)
```

### Secrets

```
POST   /api/secrets                    Create a secret (auth optional)
GET    /api/secrets/{id}               Retrieve via browser/share URL (?token=&access_password=)
POST   /api/secrets/{id}               Retrieve programmatically (token in query, password in body)
GET    /api/secrets/{id}/info          Metadata only - no content, no auth required
DELETE /api/secrets/{id}               Hard-delete (owner or admin)
GET    /api/secrets                    List own secrets (paginated + filtered, auth required)
POST   /api/secrets/{id}/rotate-key    Rotate encryption key (server-encrypted secrets only)
```

### Admin (admin role required)

```
GET    /api/admin/audit-logs               Query audit log (paginated, filterable by action/actor/secret)
DELETE /api/admin/cleanup                  Manual sweep - purge expired secrets, inactive users, dead sessions
GET    /api/admin/users                    List all users (paginated)
PATCH  /api/admin/users/{id}/role          Change a user's role (admin | user | readonly)
PATCH  /api/admin/users/{id}/switch        Toggle a user's active status (activates or deactivates)
```

### Stats (public)

```
GET /api/stats                             Active secrets count, total created, total viewed
```

---

## Feature deep-dive

### 🔐 JWT Authentication

Two-token scheme:

| Token | TTL | Purpose |
|---|---|---|
| Access token | 15 min (configurable) | Bearer token on every API call |
| Refresh token | 7 days (configurable) | Exchange for a new access token; stored in `sessions` table; rotated on each use |

```
POST /api/auth/register   { email, username, password }
POST /api/auth/login      { email, password }            -> { access_token, refresh_token }
POST /api/auth/refresh    { refresh_token }              -> { access_token, refresh_token }
POST /api/auth/logout     { refresh_token }              (revokes session)
GET  /api/auth/me                                        (current user)
```

### 🛡️ RBAC

Three roles in ascending order: `readonly -> user -> admin`

| Endpoint | Min role |
|---|---|
| Create / retrieve / delete secrets | `user` |
| List own secrets | `user` |
| Rotate encryption key | `user` (own secret) or `admin` |
| `/api/admin/*` | `admin` |

Change a user's role:

```
PATCH /api/admin/users/{id}/role?role=admin
```

### 🔑 Key Management System (KMS)

Every secret gets its own **Data Encryption Key (DEK)**:

```
plaintext
    │
    ▼  encrypt with DEK (ChaCha20-Poly1305)
ciphertext + nonce  ──► stored in secrets.content / secrets.nonce
    
DEK  ──► wrap with master KEK (ChaCha20-Poly1305)  ──► stored in secret_keys.wrapped_dek
```

The master **KEK** (`SECRET_ENCRYPTION_KEY`) never touches the DB.
The plaintext DEK is ephemeral - it exists only in memory during encrypt/decrypt.

**Key rotation** decrypts the secret with the current DEK, generates a brand new DEK, re-encrypts atomically, and increments the key version. Only applies to server-encrypted secrets - client-encrypted secrets have no server-side DEK to rotate.

```
POST /api/secrets/{id}/rotate-key
```

### 📱 Client-side End-to-End Encryption

Set `client_encrypted: true` and `client_nonce: "<base64 nonce>"` when creating a secret. The server stores the opaque ciphertext without ever seeing plaintext. No server-side DEK is generated. The recipient needs the key out-of-band to decrypt.

```json
POST /api/secrets
{
  "content": "<base64-encoded ciphertext>",
  "client_encrypted": true,
  "client_nonce": "<base64 nonce>",
  "ttl_hours": 4
}
```

### 📋 Secrets – full API

```
POST   /api/secrets                     Create a secret (auth optional)
GET    /api/secrets/{id}                Retrieve via browser/share URL (?token=<signed>&access_password=<pw>)
POST   /api/secrets/{id}                Retrieve & burn (or ?token=<signed>)
GET    /api/secrets/{id}/info           Metadata only (no content, no auth required)
DELETE /api/secrets/{id}                Hard-delete (owner or admin)
GET    /api/secrets                     List own secrets (paginated + filtered)
POST   /api/secrets/{id}/rotate-key    Rotate encryption key (server-encrypted secrets only)
```

**Pagination & filtering** on `GET /api/secrets`:

| Query param | Type | Description |
|---|---|---|
| `page` | int | Page number (default 1) |
| `page_size` | int | Items per page (1–100, default 20) |
| `viewed` | bool | Filter by viewed status |
| `expired` | bool | Filter by expiry status |

**Advanced expiry** - a secret is destroyed when **either** condition is met:

- `expires_at < NOW()` (TTL-based)
- `view_count >= max_views` (view-count-based, configurable 1–100)

### 🔗 Signed Share URLs

Every created secret returns:

```json
{
  "secret_id": "aB3xK9mZ2pQr",
  "share_url": "https://localhost:8000/api/secrets/aB3xK9mZ2pQr?token=<signed>",
  "signed_token": "<secret_id>.<expiry_ts>.<hmac_sha256>",
  "expires_at": "...",
  "qr_code": "<base64 PNG>"
}
```

The token is self-contained (HMAC-SHA256, no DB lookup to verify). Pass it as `?token=` on `POST /api/secrets/{id}` to access without a password. Tokens expire at the same time as the secret.

### 📊 Audit Logging

Every significant action is recorded in `audit_logs`:

| Action | Triggered by |
|---|---|
| `secret_created` | POST /api/secrets |
| `secret_viewed` | GET or POST /api/secrets/{id} |
| `secret_deleted` | DELETE /api/secrets/{id} or auto_cleanup|
| `key_rotated` | POST /api/secrets/{id}/rotate-key |
| `user_registered` | POST /api/auth/register |
| `user_login` | POST /api/auth/login |
| `user_logout` | POST /api/auth/logout |
| `user_removed` | Fallback sweep (inactive users past 2-day grace period) |

Query the log (admin only):

```curl
GET /api/admin/audit-logs?page=1&page_size=50&action=secret_viewed&secret_id=aB3xK9mZ2pQr
```

### 🔔 Notifications

Set `notify_on_view: true` when creating a secret:

```json
{
  "content": "...",
  "notify_on_view": true,
  "notify_email": "you@example.com",
  "webhook_url": "https://hooks.example.com/phantom"
}
```

When the secret is viewed:

- An HTML email is dispatched via SMTP (configure `SMTP_*` env vars).
- A `POST` is fired to `webhook_url` with `{ secret_id, event, actor_ip }`.

Both run as FastAPI `BackgroundTask`s so they never block the response.

### 🚦 Rate Limiting

Sliding window rate limiting via Redis sorted sets. Each request is recorded as a timestamped entry - entries older than the window are dropped on every request, so the count always reflects only the last N seconds.

Authenticated users are limited by user ID, anonymous users by IP - so a logged-in user can't bypass limits by switching IPs.

| Endpoint | Limit | Window |
|---|---|---|
| `POST /api/auth/login` | 5 requests | 60s |
| `POST /api/auth/register` | 3 requests | 1 hour |
| `POST /api/auth/refresh` | 10 requests | 60s |
| `POST /api/secrets` | 30 requests | 60s |
| `GET/POST /api/secrets/{id}` | 10 requests | 60s |
| `POST /api/secrets/{id}/rotate-key` | 5 requests | 60s |

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header indicating how long to wait.

### 🧹 Auto-cleanup

Four complementary mechanisms:

1. **Redis keyspace notifications** - on creation, a sentinel key is set in Redis with the same TTL as the secret. When it expires, Redis emits a keyspace event and the `expiry_worker` immediately hard-deletes that specific row from PostgreSQL. This is the primary, fast-path deletion route.
2. **Periodic DB fallback sweep** - runs every 10 minutes regardless of Redis availability, hard-deleting any rows where `expires_at < NOW()` or `view_count >= max_views`. Also cleans up revoked/expired sessions and inactive users past their 2-day deletion grace period. Catches anything missed during Redis downtime.
3. **PostgreSQL triggers** - `view_count >= max_views` also fires a DB-level trigger that deletes the secret immediately on the UPDATE, before the application layer even returns.
4. **Manual sweep**: `DELETE /api/admin/cleanup`

---

## Scalability Notes

- The API is designed to be stateless, with access tokens carrying all authentication context. This allows the FastAPI layer to scale horizontally behind a load balancer without requiring sticky sessions.

- Redis is used for expiry coordination, keeping time-based logic out of the database and reducing load on PostgreSQL.

- All list endpoints are paginated to avoid unbounded queries and ensure predictable performance.

- One current limitation is the expiry_worker, which runs as a single asyncio process. In a multi-instance deployment, this would need to be moved to a dedicated worker service or coordinated using a distributed lock to prevent duplicate deletions.

---
