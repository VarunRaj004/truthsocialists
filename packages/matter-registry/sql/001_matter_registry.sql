CREATE SCHEMA IF NOT EXISTS matter_registry;

CREATE TABLE IF NOT EXISTS matter_registry.schema_migration (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS matter_registry.tenant_context (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id uuid NOT NULL UNIQUE,
    tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS matter_registry.matter (
    matter_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 4294967295),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    opens_at timestamptz NOT NULL,
    closes_at timestamptz NOT NULL,
    published_at timestamptz NOT NULL,
    matter_key_id bytea NOT NULL UNIQUE CHECK (octet_length(matter_key_id) = 32),
    rsa_spki_der bytea NOT NULL,
    complaint_artifact_id bytea NOT NULL CHECK (octet_length(complaint_artifact_id) = 32),
    vote_artifact_id bytea NOT NULL CHECK (octet_length(vote_artifact_id) = 32),
    handler_org_id uuid NOT NULL,
    handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id) = 32),
    retired_at timestamptz,
    PRIMARY KEY (matter_id, version),
    CHECK (closes_at > opens_at),
    CHECK (published_at <= opens_at - interval '24 hours'),
    CHECK (retired_at IS NULL OR retired_at >= closes_at)
);

CREATE INDEX IF NOT EXISTS matter_public_window_idx
    ON matter_registry.matter (published_at, opens_at, closes_at);

INSERT INTO matter_registry.schema_migration(version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
