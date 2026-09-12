-- migrate:up
ALTER TABLE secrets ADD COLUMN email_restricted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE secret_recipients (
    secret_id UUID   NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    email     CITEXT NOT NULL,
    PRIMARY KEY (secret_id, email)
);

-- This metadata intentionally survives deletion of the encrypted payload.
CREATE TABLE secret_tracking (
    secret_id    UUID        PRIMARY KEY,
    owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    retain_until TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_secret_tracking_retention ON secret_tracking(retain_until);
CREATE INDEX idx_secret_tracking_owner     ON secret_tracking(owner_id);

INSERT INTO secret_tracking (secret_id, owner_id, retain_until)
SELECT id, owner_id, expires_at + INTERVAL '30 days'
FROM secrets
WHERE owner_id IS NOT NULL;

CREATE TABLE secret_views (
    id             BIGSERIAL   PRIMARY KEY,
    secret_id      UUID        NOT NULL REFERENCES secret_tracking(secret_id) ON DELETE CASCADE,
    viewer_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
    viewer_email   TEXT,
    email_verified BOOLEAN     NOT NULL DEFAULT FALSE,
    viewed_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX idx_secret_views_history ON secret_views(secret_id, viewed_at DESC, id DESC);

CREATE TABLE email_verifications (
    user_id      UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email        CITEXT      NOT NULL,
    token_hash   TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX idx_email_verifications_expiry ON email_verifications(expires_at);

-- migrate:down
-- Removing this feature while restricted secrets exist would make them public.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM secrets WHERE email_restricted) THEN
        RAISE EXCEPTION 'Delete email-restricted secrets before rolling back email access';
    END IF;
END $$;

DROP TABLE email_verifications;
DROP TABLE secret_views;
DROP TABLE secret_tracking;
DROP TABLE secret_recipients;
ALTER TABLE secrets DROP COLUMN email_restricted;
