-- migrate:up
CREATE TABLE user_quotas (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    max_active_secrets INTEGER CHECK (max_active_secrets > 0),
    max_file_bytes BIGINT CHECK (max_file_bytes > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'admin_quota_update';

-- migrate:down
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM audit_logs WHERE action::text = 'admin_quota_update'
    ) THEN
        RAISE EXCEPTION 'Delete quota audit entries before rollback';
    END IF;
END $$;

DROP TABLE user_quotas;

ALTER TYPE audit_action RENAME TO audit_action_with_quotas;
CREATE TYPE audit_action AS ENUM (
    'secret_created', 'secret_viewed', 'secret_deleted', 'user_registered',
    'user_login', 'user_logout', 'user_removed', 'key_rotated',
    'secret_expired', 'token_refresh', 'admin_role_change', 'admin_cleanup',
    'admin_user_toggle', 'rate_limit_hit', 'invalid_token',
    'secret_updated', 'secret_version_restored',
    'file_uploaded', 'malware_detected'
);
ALTER TABLE audit_logs ALTER COLUMN action TYPE audit_action
    USING action::text::audit_action;
DROP TYPE audit_action_with_quotas;
