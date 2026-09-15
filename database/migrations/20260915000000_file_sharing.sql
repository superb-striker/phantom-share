-- migrate:up
ALTER TABLE secrets
    ADD COLUMN payload_type VARCHAR(16) NOT NULL DEFAULT 'text',
    ALTER COLUMN content DROP NOT NULL,
    ADD CONSTRAINT secrets_payload_type_check
        CHECK (payload_type IN ('text', 'file'));

ALTER TABLE secret_versions
    ADD COLUMN payload_type        VARCHAR(16) NOT NULL DEFAULT 'text',
    ADD COLUMN object_key          TEXT        UNIQUE,
    ADD COLUMN encrypted_size      BIGINT      NOT NULL DEFAULT 0
        CHECK (encrypted_size >= 0),
    ADD COLUMN filename_ciphertext TEXT,
    ADD COLUMN filename_nonce      TEXT,
    ADD COLUMN media_type          VARCHAR(255),
    ADD COLUMN content_sha256      CHAR(64),
    ADD COLUMN clamav_version      TEXT,
    ADD COLUMN scanned_at          TIMESTAMPTZ,
    ALTER COLUMN content DROP NOT NULL,
    ADD CONSTRAINT secret_version_payload_type_check
        CHECK (payload_type IN ('text', 'file')),
    ADD CONSTRAINT secret_version_payload_check CHECK (
        (payload_type = 'text' AND content IS NOT NULL
            AND object_key IS NULL)
        OR
        (payload_type = 'file' AND object_key IS NOT NULL
            AND content IS NULL)
    );

CREATE INDEX idx_secret_versions_object_key ON secret_versions(object_key)
    WHERE object_key IS NOT NULL;

CREATE TABLE pending_uploads (
    id             UUID        PRIMARY KEY,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_id      UUID        NOT NULL,
    object_key     TEXT        NOT NULL UNIQUE,
    reservation_id UUID        NOT NULL UNIQUE,
    plaintext_size BIGINT      NOT NULL CHECK (plaintext_size >= 0),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_pending_uploads_expiry ON pending_uploads(expires_at);

CREATE TABLE object_deletion_outbox (
    id              BIGSERIAL   PRIMARY KEY,
    object_key      TEXT        NOT NULL UNIQUE,
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    billed_bytes    BIGINT      NOT NULL DEFAULT 0,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    processed_at    TIMESTAMPTZ,
    last_error      TEXT
);
CREATE INDEX idx_object_deletion_pending
    ON object_deletion_outbox(next_attempt_at) WHERE processed_at IS NULL;

CREATE OR REPLACE FUNCTION enqueue_secret_objects_for_deletion()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO object_deletion_outbox(object_key, user_id, billed_bytes)
    SELECT object_key, OLD.owner_id, plaintext_size
    FROM secret_versions
    WHERE secret_id = OLD.id AND object_key IS NOT NULL
    ON CONFLICT (object_key) DO NOTHING;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_enqueue_secret_objects
    BEFORE DELETE ON secrets
    FOR EACH ROW EXECUTE FUNCTION enqueue_secret_objects_for_deletion();

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'file_uploaded';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'malware_detected';

-- migrate:down
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM secrets WHERE payload_type = 'file') THEN
        RAISE EXCEPTION 'Delete file secrets before rollback';
    END IF;
    IF EXISTS (
        SELECT 1 FROM audit_logs
        WHERE action::text IN ('file_uploaded', 'malware_detected')
    ) THEN
        RAISE EXCEPTION 'Delete file audit entries before rollback';
    END IF;
END $$;

DROP TRIGGER trg_enqueue_secret_objects ON secrets;
DROP FUNCTION enqueue_secret_objects_for_deletion();
DROP TABLE object_deletion_outbox;
DROP TABLE pending_uploads;

ALTER TABLE secret_versions
    DROP CONSTRAINT secret_version_payload_check,
    DROP CONSTRAINT secret_version_payload_type_check,
    DROP COLUMN scanned_at,
    DROP COLUMN clamav_version,
    DROP COLUMN content_sha256,
    DROP COLUMN media_type,
    DROP COLUMN filename_nonce,
    DROP COLUMN filename_ciphertext,
    DROP COLUMN encrypted_size,
    DROP COLUMN object_key,
    DROP COLUMN payload_type,
    ALTER COLUMN content SET NOT NULL;

ALTER TABLE secrets
    DROP CONSTRAINT secrets_payload_type_check,
    DROP COLUMN payload_type,
    ALTER COLUMN content SET NOT NULL;

ALTER TYPE audit_action RENAME TO audit_action_with_files;
CREATE TYPE audit_action AS ENUM (
    'secret_created', 'secret_viewed', 'secret_deleted', 'user_registered',
    'user_login', 'user_logout', 'user_removed', 'key_rotated',
    'secret_expired', 'token_refresh', 'admin_role_change', 'admin_cleanup',
    'admin_user_toggle', 'rate_limit_hit', 'invalid_token',
    'secret_updated', 'secret_version_restored'
);
ALTER TABLE audit_logs ALTER COLUMN action TYPE audit_action
    USING action::text::audit_action;
DROP TYPE audit_action_with_files;
