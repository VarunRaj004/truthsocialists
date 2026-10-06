CREATE TABLE IF NOT EXISTS complaint_store.submission_idempotency (
    idempotency_key uuid PRIMARY KEY,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    complaint_id uuid UNIQUE REFERENCES complaint_store.complaint_record(complaint_id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS submission_idempotency_expiry_idx
    ON complaint_store.submission_idempotency(expires_at);

INSERT INTO complaint_store.schema_migration(version) VALUES (2)
ON CONFLICT (version) DO NOTHING;
