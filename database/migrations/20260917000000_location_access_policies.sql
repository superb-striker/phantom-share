-- migrate:up
CREATE TABLE secret_access_policies (
    secret_id UUID PRIMARY KEY REFERENCES secrets(id) ON DELETE CASCADE,
    allowed_cidrs CIDR[] NOT NULL DEFAULT '{}',
    allowed_countries CHAR(2)[] NOT NULL DEFAULT '{}',
    location_policy_mode VARCHAR(3) NOT NULL DEFAULT 'all'
        CHECK (location_policy_mode IN ('all', 'any')),
    geoip_fail_closed BOOLEAN NOT NULL DEFAULT TRUE,
    policy_version INTEGER NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO secret_access_policies(secret_id)
SELECT id FROM secrets;

-- migrate:down
DROP TABLE secret_access_policies;
