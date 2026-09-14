-- migrate:up
ALTER TABLE secrets
    ADD COLUMN current_version INTEGER     NOT NULL DEFAULT 1,
    ADD COLUMN updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

ALTER TABLE secret_keys
    ADD CONSTRAINT secret_keys_secret_version_unique UNIQUE (secret_id, version);

CREATE TABLE secret_versions (
    secret_id      UUID        NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version        INTEGER     NOT NULL,
    content        TEXT        NOT NULL,
    nonce          TEXT,
    key_version    INTEGER,
    plaintext_size BIGINT      NOT NULL DEFAULT 0 CHECK (plaintext_size >= 0),
    created_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
    change_note    VARCHAR(500),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (secret_id, version)
);

INSERT INTO secret_versions (
    secret_id, version, content, nonce, key_version,
    plaintext_size, created_by, created_at
)
SELECT s.id, 1, s.content, s.nonce,
       (SELECT MAX(sk.version) FROM secret_keys sk WHERE sk.secret_id = s.id),
       0, s.owner_id, s.created_at
FROM secrets s;

ALTER TABLE secret_views ADD COLUMN content_version INTEGER;
UPDATE secret_views SET content_version = 1 WHERE content_version IS NULL;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'secret_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'secret_version_restored';

-- migrate:down
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM secrets WHERE current_version > 1) THEN
        RAISE EXCEPTION 'Delete secrets with multiple versions before rollback';
    END IF;
    IF EXISTS (
        SELECT 1 FROM audit_logs
        WHERE action::text IN ('secret_updated', 'secret_version_restored')
    ) THEN
        RAISE EXCEPTION 'Delete version audit entries before rollback';
    END IF;
END $$;

ALTER TABLE secret_views DROP COLUMN content_version;
DROP TABLE secret_versions;
ALTER TABLE secret_keys DROP CONSTRAINT secret_keys_secret_version_unique;
ALTER TABLE secrets
    DROP COLUMN updated_at,
    DROP COLUMN current_version;

ALTER TYPE audit_action RENAME TO audit_action_with_versions;
CREATE TYPE audit_action AS ENUM (
    'secret_created', 'secret_viewed', 'secret_deleted', 'user_registered',
    'user_login', 'user_logout', 'user_removed', 'key_rotated',
    'secret_expired', 'token_refresh', 'admin_role_change', 'admin_cleanup',
    'admin_user_toggle', 'rate_limit_hit', 'invalid_token'
);
ALTER TABLE audit_logs ALTER COLUMN action TYPE audit_action
    USING action::text::audit_action;
DROP TYPE audit_action_with_versions;
