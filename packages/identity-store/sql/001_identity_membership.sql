CREATE SCHEMA IF NOT EXISTS ida;

CREATE TABLE IF NOT EXISTS ida.schema_migration (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS ida.tenant_context (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id uuid NOT NULL UNIQUE,
    tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS ida.membership_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    next_leaf_index integer NOT NULL DEFAULT 0 CHECK (next_leaf_index BETWEEN 0 AND 65536),
    current_epoch bigint NOT NULL DEFAULT 0 CHECK (current_epoch >= 0),
    previous_checkpoint_hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(previous_checkpoint_hash) = 32),
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1)
);

CREATE TABLE IF NOT EXISTS ida.enrollment (
    enrollment_id uuid PRIMARY KEY,
    synthetic_identity_ref text NOT NULL UNIQUE CHECK (synthetic_identity_ref LIKE 'synthetic:%'),
    person_anchor numeric(78,0) NOT NULL,
    active_device_hash numeric(78,0) NOT NULL,
    active_leaf_index integer NOT NULL UNIQUE CHECK (active_leaf_index BETWEEN 0 AND 65535),
    recovery_id bytea NOT NULL UNIQUE CHECK (octet_length(recovery_id) = 16),
    recovery_public_key bytea NOT NULL CHECK (octet_length(recovery_public_key) = 32),
    recovery_generation integer NOT NULL DEFAULT 1 CHECK (recovery_generation >= 1),
    active boolean NOT NULL DEFAULT true,
    enrolled_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1)
);

CREATE TABLE IF NOT EXISTS ida.membership_leaf (
    leaf_index integer PRIMARY KEY CHECK (leaf_index BETWEEN 0 AND 65535),
    leaf_value numeric(78,0) NOT NULL,
    state text NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED')),
    updated_epoch bigint CHECK (updated_epoch IS NULL OR updated_epoch >= 1)
);

CREATE TABLE IF NOT EXISTS ida.membership_pending_update (
    pending_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    leaf_index integer NOT NULL CHECK (leaf_index BETWEEN 0 AND 65535),
    operation text NOT NULL CHECK (operation IN ('ACTIVATE', 'REVOKE')),
    new_leaf_value numeric(78,0) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS ida.membership_checkpoint (
    epoch bigint PRIMARY KEY CHECK (epoch >= 1),
    root numeric(78,0) NOT NULL,
    previous_checkpoint_hash bytea NOT NULL CHECK (octet_length(previous_checkpoint_hash) = 32),
    update_batch_hash bytea NOT NULL CHECK (octet_length(update_batch_hash) = 32),
    checkpoint_cbor bytea NOT NULL,
    checkpoint_hash bytea NOT NULL UNIQUE CHECK (octet_length(checkpoint_hash) = 32),
    published_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS ida.membership_update (
    epoch bigint NOT NULL REFERENCES ida.membership_checkpoint(epoch),
    sequence_in_batch integer NOT NULL CHECK (sequence_in_batch >= 0),
    leaf_index integer NOT NULL CHECK (leaf_index BETWEEN 0 AND 65535),
    operation text NOT NULL CHECK (operation IN ('ACTIVATE', 'REVOKE')),
    new_leaf_value numeric(78,0) NOT NULL,
    PRIMARY KEY (epoch, sequence_in_batch),
    UNIQUE (epoch, leaf_index)
);

CREATE TABLE IF NOT EXISTS ida.recovery_challenge (
    challenge_id bytea PRIMARY KEY CHECK (octet_length(challenge_id) = 16),
    enrollment_id uuid NOT NULL REFERENCES ida.enrollment(enrollment_id),
    recovery_generation integer NOT NULL CHECK (recovery_generation >= 1),
    signed_challenge_cbor bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + interval '5 minutes')
);

CREATE INDEX IF NOT EXISTS recovery_challenge_expiry_idx
    ON ida.recovery_challenge (expires_at)
    WHERE consumed_at IS NULL;

INSERT INTO ida.schema_migration(version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
