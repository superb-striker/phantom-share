# 👻 Phantom Share

Secure, time-limited, burn-after-reading secret sharing with:

- JWT Auth
- Role-based Access Control
- Envelope encryption (DEK/KEK)
- Audit logging
- Signed share links, QR code sharing
- Webhook/email notifications, and
- Redis keyspace-driven expiry.

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
env/Scripts/activate
pip install -r requirements.txt
```

### 2. Configure environment

Edit `app/core/config.py` following the comments in the file.

### 3. Run the DDL script

Run `database/setup.sql` in your PostgreSQL database (I used pgAdmin 4 for this).

The file is **idempotent** - safe to re-run. It create all tables, indexes, and triggers.

### 4. Setup Redis (Ubuntu)

#### a. Add Redis Repository

```bash
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
```

#### b. Install Redis

```bash
sudo apt-get update
sudo apt-get install -y redis-server
```

#### c. Startup and enable Redis

```bash
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

#### d. Verify installation

```bash
redis-cli ping
```

EXPECTED OUTPUT : `PONG`

### 4. Start the server

```bash
uvicorn main:app --reload
```

Interactive docs -> <http://localhost:8000/docs>

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

### 🧹 Auto-cleanup

Four complementary mechanisms:

1. **Redis keyspace notifications** - on creation, a sentinel key is set in Redis with the same TTL as the secret. When it expires, Redis emits a keyspace event and the `expiry_worker` immediately hard-deletes that specific row from PostgreSQL. This is the primary, fast-path deletion route.
2. **Periodic DB fallback sweep** - runs every 10 minutes regardless of Redis availability, hard-deleting any rows where `expires_at < NOW()` or `view_count >= max_views`. Also cleans up revoked/expired sessions and inactive users past their 2-day deletion grace period. Catches anything missed during Redis downtime.
3. **PostgreSQL triggers** - `view_count >= max_views` also fires a DB-level trigger that deletes the secret immediately on the UPDATE, before the application layer even returns.
4. **Manual sweep**: `DELETE /api/admin/cleanup`

---
