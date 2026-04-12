# 👻 Phantom Share

A production-style backend system for securely sharing secrets with zero plaintext persistence and real-time destruction.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-async-green?logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-blue?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-8-red?logo=redis)
![Railway](https://img.shields.io/badge/Deployed-Railway-purple?logo=railway)

🚀 Live: https://phantom-share-production.up.railway.app  
📖 Interactive docs: https://phantom-share-production.up.railway.app/docs

---

## Why this project matters

This isn't just a CRUD API. It demonstrates:

- Secure data handling (encryption, key management)
- Distributed expiry coordination (Redis + DB fallback)
- Stateless + stateful auth design (JWT + refresh rotation)
- Real-world backend concerns (race conditions, audit trails)

---

## Features

- 🔑 **Envelope Encryption** - per-secret DEK wrapped by a master KEK (ChaCha20-Poly1305)
- 📱 **Optional E2E Encryption** - client-side mode where server never sees plaintext
- ⚡ **Real-Time Expiry** - Redis keyspace notifications trigger instant deletion
- 💣 **Burn After Read** - secrets auto-delete after max views (DB trigger enforced)
- 🔗 **Signed Share Links** - stateless HMAC tokens + QR codes
- 🔐 **JWT Auth** - access tokens + rotating refresh tokens with revocation
- 🛡️ **RBAC** - `readonly -> user -> admin` role hierarchy
- 🚦 **Rate Limiting** - sliding window per user/IP via Redis
- 📊 **Audit Logging** - every sensitive action tracked with actor + IP
- 🔔 **Async Notifications** - email + webhook on secret access

---

## System Architecture

```
Client
   │
   ▼
FastAPI (stateless API layer)
   │
   ├── PostgreSQL -> secrets, keys, audit logs, sessions
   └── Redis     -> expiry coordination + rate limiting
```

```
phantom_share/
├── main.py                        # App entrypoint: registers routers, runs lifespan (DB pool, Redis, expiry worker)
├── database/
│   └── setup.sql                  # PostgreSQL DDL - run once to create all tables, indexes, and triggers
├── requirements.txt
└── app/
    ├── core/                      # Infrastructure - wiring the app together
    │   ├── config.py              # All settings via environment variables (Pydantic Settings)
    │   ├── database.py            # Async PostgreSQL connection pool (psycopg3)
    │   ├── redis_client.py        # Async Redis client - expiry sentinel keys
    │   ├── rate_limit.py          # Sliding window rate limiting via Redis sorted sets
    │   ├── security.py            # JWT creation/validation, signed share tokens, password hashing
    │   └── permissions.py         # RBAC - FastAPI dependency factories (require_user, require_admin)
    │
    ├── middleware/
    │   └── audit.py               # Extracts client IP, attaches to request.state, adds security headers
    │
    ├── routers/                   # HTTP layer - request validation, auth, responses
    │   ├── auth.py                # /api/auth/*    - register, login, refresh, logout
    │   ├── secrets.py             # /api/secrets/* - create, retrieve, delete, list, rotate key
    │   ├── admin.py               # /api/admin/*   - user management (admin only)
    │   └── stats.py               # /api/stats     - usage statistics
    │
    ├── services/                  # Business logic - called by routers
    │   ├── key_service.py         # Generates per-secret DEKs, wraps with master KEK, handles rotation
    │   ├── audit_service.py       # Inserts rows into audit_logs - called after every sensitive operation
    │   ├── email_service.py       # Sends SMTP email and fires webhooks when a secret is viewed
    │   └── cleanup_service.py     # Two-track expiry: Redis keyspace events (fast) + periodic DB sweep (fallback)
    │
    ├── helper.py                  # ChaCha20-Poly1305 encrypt/decrypt, DEK/KEK wrap, QR code generation
    └── schemas.py                 # All Pydantic v2 request and response models
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

---

## API Reference

### Auth

```
POST /api/auth/register       { email, username, password }
POST /api/auth/login          { email, password }            -> { access_token, refresh_token }
POST /api/auth/refresh        { refresh_token }              -> { access_token, refresh_token }
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
GET    /api/admin/audit-logs               Query audit log (paginated, filterable)
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

## Quick Start

```bash
git clone https://github.com/superb-striker/phantom-share
cd phantom-share

python -m venv env
env\Scripts\activate        # Windows
source env/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file:

```env
SECRET_ENCRYPTION_KEY=    
JWT_SECRET_KEY=           
SIGNED_URL_SECRET=        
DATABASE_URL=             
REDIS_URL=   
SMTP_USERNAME=
SMTP_PASSWORD=             
```

Run the DDL (idempotent - safe to re-run):

```bash
# paste contents of database/setup.sql into your PostgreSQL client
```

Setup Redis

```bash
# Ubuntu
sudo apt-get install -y redis-server
```

Start Redis and the server:

```bash
sudo systemctl start redis-server 
redis-cli ping              # EXPECTED OUTPUT: PONG
uvicorn main:app --reload
```

Interactive docs -> http://localhost:8000/docs

---

## Scalability Notes

- Stateless API layer scales horizontally behind a load balancer - no sticky sessions needed.
- Redis handles expiry coordination and rate limiting, keeping time-based logic out of PostgreSQL.
- All list endpoints paginated - no unbounded queries
- ⚠️ Current limitation: `expiry_worker` runs as a single asyncio process - multi-instance deployments would need a dedicated worker or distributed lock to prevent duplicate deletions.