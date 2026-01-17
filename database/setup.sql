CREATE EXTENSION IF NOT EXISTS "pgcrypto";
SELECT gen_random_uuid();
CREATE EXTENSION IF NOT EXISTS "citext";

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'user', 'readonly');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM (
        'secret_created',
        'secret_viewed',
        'secret_deleted',
        'secret_expired',
        'user_registered',
        'user_login',
        'user_logout',
        'key_rotated',
        'admin_cleanup'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS public.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           CITEXT          NOT NULL UNIQUE,
    username        VARCHAR(64)     NOT NULL UNIQUE,
    password_hash   VARCHAR(256)    NOT NULL,
    role            user_role       NOT NULL DEFAULT 'user',
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    is_verified     BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email    ON public.users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users (username);

CREATE TABLE IF NOT EXISTS public.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID            NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    refresh_token   VARCHAR(512)    NOT NULL UNIQUE,
    user_agent      TEXT,
    ip_address      INET,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL,
    revoked         BOOLEAN         NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id       ON public.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON public.sessions (refresh_token);

CREATE TABLE IF NOT EXISTS public.secrets (
    id character varying COLLATE pg_catalog."default" NOT NULL,
    content character varying COLLATE pg_catalog."default" NOT NULL,
    password_protected boolean NOT NULL DEFAULT false,
    access_password character varying COLLATE pg_catalog."default",
    ttl_hours integer NOT NULL DEFAULT 24,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    qr_code character varying COLLATE pg_catalog."default",
    viewed boolean NOT NULL DEFAULT false,
    CONSTRAINT secret_pkey PRIMARY KEY (id),
    CONSTRAINT check_ttl_range CHECK (ttl_hours >= 1 AND ttl_hours <= 168)
);

ALTER TABLE public.secrets
    ADD COLUMN IF NOT EXISTS owner_id           UUID        REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS nonce              VARCHAR     ,   -- ChaCha20 nonce (base64)
    ADD COLUMN IF NOT EXISTS max_views          INTEGER     DEFAULT 1,
    ADD COLUMN IF NOT EXISTS view_count         INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS signed_token       VARCHAR     ,   -- signed share token
    ADD COLUMN IF NOT EXISTS notify_on_view     BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS notify_email       VARCHAR(256),
    ADD COLUMN IF NOT EXISTS webhook_url        VARCHAR(512),
    ADD COLUMN IF NOT EXISTS deleted_at         TIMESTAMPTZ ;   -- soft-delete

CREATE INDEX IF NOT EXISTS idx_secrets_owner_id    ON public.secrets (owner_id);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at  ON public.secrets (expires_at);
CREATE INDEX IF NOT EXISTS idx_secrets_viewed      ON public.secrets (viewed);
CREATE INDEX IF NOT EXISTS idx_secrets_deleted_at  ON public.secrets (deleted_at);

CREATE TABLE IF NOT EXISTS public.secret_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       VARCHAR         NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
    -- The per-secret DEK is itself encrypted with the master KEK.
    -- Server stores only the wrapped key; plaintext DEK is ephemeral.
    wrapped_dek     TEXT            NOT NULL,   -- base64(KEK.encrypt(DEK))
    dek_nonce       TEXT            NOT NULL,   -- nonce used to wrap the DEK
    algorithm       VARCHAR(32)     NOT NULL DEFAULT 'chacha20poly1305',
    version         INTEGER         NOT NULL DEFAULT 1,
    rotated_at      TIMESTAMPTZ     ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_keys_secret_id ON public.secret_keys (secret_id);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id              BIGSERIAL       PRIMARY KEY,
    action          audit_action    NOT NULL,
    actor_id        UUID            REFERENCES public.users(id) ON DELETE SET NULL,
    actor_ip        INET            ,
    secret_id       VARCHAR         REFERENCES public.secrets(id) ON DELETE SET NULL,
    metadata        JSONB           DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id  ON public.audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_secret_id ON public.audit_logs (secret_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action    ON public.audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs (created_at DESC);

CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS set_users_updated_at ON public.users;
CREATE TRIGGER set_users_updated_at
    BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE OR REPLACE FUNCTION calculate_expiration()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.expires_at := NEW.created_at + (NEW.ttl_hours || ' hours')::interval;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_expires_at ON public.secrets;
CREATE OR REPLACE TRIGGER trg_set_expires_at
    BEFORE INSERT ON public.secrets
    FOR EACH ROW EXECUTE FUNCTION calculate_expiration();


