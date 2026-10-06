CREATE SCHEMA IF NOT EXISTS complaint_store;

CREATE TABLE IF NOT EXISTS complaint_store.schema_migration (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS complaint_store.tenant_context (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id uuid NOT NULL UNIQUE,
    tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS complaint_store.matter (
    matter_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 4294967295),
    opens_at timestamptz NOT NULL,
    closes_at timestamptz NOT NULL,
    matter_key_id bytea NOT NULL UNIQUE CHECK (octet_length(matter_key_id) = 32),
    rsa_spki_der bytea NOT NULL,
    complaint_artifact_id bytea NOT NULL CHECK (octet_length(complaint_artifact_id) = 32),
    handler_org_id uuid NOT NULL,
    handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id) = 32),
    PRIMARY KEY (matter_id, version),
    CHECK (closes_at > opens_at)
);

CREATE TABLE IF NOT EXISTS complaint_store.proof_session (
    challenge_id bytea PRIMARY KEY CHECK (octet_length(challenge_id) = 16),
    epoch bigint NOT NULL CHECK (epoch >= 0),
    membership_root numeric(78,0) NOT NULL,
    signed_lease_cbor bytea NOT NULL,
    signed_lease_hash bytea NOT NULL UNIQUE CHECK (octet_length(signed_lease_hash) = 32),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + interval '60 seconds')
);

CREATE TABLE IF NOT EXISTS complaint_store.spent_entitlement (
    matter_key_id bytea NOT NULL CHECK (octet_length(matter_key_id) = 32),
    serial bytea NOT NULL CHECK (octet_length(serial) = 16),
    spent_at timestamptz NOT NULL,
    PRIMARY KEY (matter_key_id, serial)
);

CREATE TABLE IF NOT EXISTS complaint_store.used_nullifier (
    matter_id uuid NOT NULL,
    matter_version bigint NOT NULL,
    nullifier numeric(78,0) NOT NULL,
    used_at timestamptz NOT NULL,
    PRIMARY KEY (matter_id, matter_version, nullifier),
    FOREIGN KEY (matter_id, matter_version)
      REFERENCES complaint_store.matter(matter_id, version)
);

CREATE TABLE IF NOT EXISTS complaint_store.complaint_record (
    complaint_id uuid PRIMARY KEY,
    matter_id uuid NOT NULL,
    matter_version bigint NOT NULL,
    commitment bytea NOT NULL CHECK (octet_length(commitment) = 32),
    ciphertext_uri text NOT NULL CHECK (ciphertext_uri LIKE 'object://%'),
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    ciphertext_size bigint NOT NULL CHECK (ciphertext_size BETWEEN 17 AND 104857616),
    aead_nonce bytea NOT NULL CHECK (octet_length(aead_nonce) = 12),
    hpke_enc bytea NOT NULL CHECK (octet_length(hpke_enc) = 32),
    wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) = 48),
    handler_org_id uuid NOT NULL,
    handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id) = 32),
    accepted_at timestamptz NOT NULL,
    initial_log_entry_hash bytea NOT NULL UNIQUE CHECK (octet_length(initial_log_entry_hash) = 32),
    FOREIGN KEY (matter_id, matter_version)
      REFERENCES complaint_store.matter(matter_id, version)
);

CREATE TABLE IF NOT EXISTS complaint_store.log_outbox (
    event_id uuid PRIMARY KEY,
    complaint_id uuid NOT NULL UNIQUE REFERENCES complaint_store.complaint_record(complaint_id),
    canonical_event_cbor bytea NOT NULL,
    log_entry_hash bytea NOT NULL UNIQUE CHECK (octet_length(log_entry_hash) = 32),
    created_at timestamptz NOT NULL,
    dispatched_at timestamptz
);

CREATE TABLE IF NOT EXISTS complaint_store.receipt_record (
    receipt_id bytea PRIMARY KEY CHECK (octet_length(receipt_id) = 16),
    complaint_id uuid NOT NULL UNIQUE REFERENCES complaint_store.complaint_record(complaint_id),
    signed_receipt_cbor bytea NOT NULL,
    issued_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS proof_session_unconsumed_expiry_idx
    ON complaint_store.proof_session(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS log_outbox_pending_idx
    ON complaint_store.log_outbox(created_at) WHERE dispatched_at IS NULL;

INSERT INTO complaint_store.schema_migration(version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
