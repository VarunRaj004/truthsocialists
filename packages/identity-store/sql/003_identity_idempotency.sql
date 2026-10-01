CREATE TABLE IF NOT EXISTS ida.idempotency_record (
    scope text NOT NULL CHECK (scope IN ('enrollment', 'recovery-complete')),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_cbor bytea,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
    PRIMARY KEY (scope, idempotency_key),
    CHECK (
      (response_cbor IS NULL AND completed_at IS NULL) OR
      (response_cbor IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idempotency_record_expiry_idx
    ON ida.idempotency_record (expires_at);

INSERT INTO ida.schema_migration(version) VALUES (3)
ON CONFLICT (version) DO NOTHING;
