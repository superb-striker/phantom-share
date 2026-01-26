CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- SELECT gen_random_uuid();
CREATE EXTENSION IF NOT EXISTS "citext";

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'user', 'readonly');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE audit_action AS ENUM (
        'secret_created',
        'secret_viewed',
        'secret_deleted',
        'user_registered',
        'user_login',
        'user_logout',
		'user_removed',
        'key_rotated'
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
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
	delete_after TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email    ON public.users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users (username);

CREATE TABLE IF NOT EXISTS public.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID            NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    refresh_token_hash  TEXT  NOT NULL UNIQUE,
    user_agent      TEXT,
    ip_address      INET,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL,
    revoked         BOOLEAN         NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id       ON public.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON public.sessions (expires_at);

CREATE TABLE IF NOT EXISTS public.secrets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content             TEXT NOT NULL,
    password_protected  BOOLEAN NOT NULL DEFAULT FALSE,
    access_password_hash TEXT,
    ttl_hours           INTEGER NOT NULL DEFAULT 24,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    qr_code             TEXT,
    viewed              BOOLEAN NOT NULL DEFAULT FALSE,
    owner_id            UUID REFERENCES public.users(id) ON DELETE SET NULL,
    nonce               TEXT,
    max_views           INTEGER NOT NULL DEFAULT 1,
    view_count          INTEGER NOT NULL DEFAULT 0,
    signed_token        TEXT,
    notify_on_view      BOOLEAN NOT NULL DEFAULT FALSE,
    notify_email        VARCHAR(256),
    webhook_url         VARCHAR(512),
    -- Constraints
    CONSTRAINT check_ttl_range CHECK (ttl_hours >= 1 AND ttl_hours <= 168),
    CONSTRAINT check_view_count CHECK (view_count <= max_views),
    CONSTRAINT check_password_consistency CHECK (
        (password_protected = TRUE AND access_password_hash IS NOT NULL)
        OR
        (password_protected = FALSE AND access_password_hash IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_secrets_owner_id    ON public.secrets (owner_id);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at  ON public.secrets (expires_at);
CREATE INDEX IF NOT EXISTS idx_secrets_view_count      ON public.secrets (view_count, max_views);
CREATE INDEX IF NOT EXISTS idx_secrets_active ON public.secrets (expires_at);

CREATE TABLE IF NOT EXISTS public.secret_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID         NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
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
    secret_id       UUID         REFERENCES public.secrets(id) ON DELETE SET NULL,
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
    NEW.expires_at := NOW() + (NEW.ttl_hours || ' hours')::interval;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_expires_at ON public.secrets;
CREATE OR REPLACE TRIGGER trg_set_expires_at
    BEFORE INSERT ON public.secrets
    FOR EACH ROW EXECUTE FUNCTION calculate_expiration();


CREATE OR REPLACE FUNCTION delete_secret_if_fully_viewed()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.view_count >= NEW.max_views THEN
        INSERT INTO audit_logs (action, secret_id, metadata)
        VALUES (
            'secret_deleted',
            NEW.id,
            jsonb_build_object(
                'reason', 'max_views_achieved',
                'source', 'postgres_trigger',
                'view_count', NEW.view_count,
                'max_views', NEW.max_views
            )
        );
        DELETE FROM secrets WHERE id = NEW.id;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_delete_fully_viewed_secret ON public.secrets;
CREATE TRIGGER trg_delete_fully_viewed_secret
    AFTER UPDATE OF view_count ON public.secrets
    FOR EACH ROW EXECUTE FUNCTION delete_secret_if_fully_viewed();


CREATE OR REPLACE FUNCTION schedule_user_deletion()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.is_active = FALSE AND OLD.is_active = TRUE THEN
        NEW.delete_after := NOW() + INTERVAL '2 days';
    ELSIF NEW.is_active = TRUE THEN
        NEW.delete_after := NULL;  -- clear if reactivated
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_schedule_user_deletion ON public.users;
CREATE TRIGGER trg_schedule_user_deletion
    BEFORE UPDATE OF is_active ON public.users
    FOR EACH ROW EXECUTE FUNCTION schedule_user_deletion();


CREATE OR REPLACE FUNCTION delete_session_if_invalid()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked = TRUE OR NEW.expires_at <= NOW() THEN
        DELETE FROM sessions WHERE id = NEW.id;
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_delete_invalid_session ON public.sessions;
CREATE TRIGGER trg_delete_invalid_session
    AFTER UPDATE OF revoked, expires_at ON public.sessions
    FOR EACH ROW EXECUTE FUNCTION delete_session_if_invalid();