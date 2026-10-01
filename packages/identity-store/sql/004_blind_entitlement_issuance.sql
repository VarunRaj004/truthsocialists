CREATE TABLE IF NOT EXISTS ida.matter_issuance (
    enrollment_id uuid NOT NULL REFERENCES ida.enrollment(enrollment_id),
    matter_id uuid NOT NULL,
    matter_version bigint NOT NULL CHECK (matter_version BETWEEN 1 AND 4294967295),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (enrollment_id, matter_id, matter_version)
);

-- The durable fact intentionally excludes the blinded request and signature.
-- Re-applying migrations is supported; replace the older scope constraint only once.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'idempotency_record_scope_check'
      AND conrelid = 'ida.idempotency_record'::regclass
      AND pg_get_constraintdef(oid) LIKE '%blind-issuance%'
  ) THEN
    ALTER TABLE ida.idempotency_record
      DROP CONSTRAINT IF EXISTS idempotency_record_scope_check;
    ALTER TABLE ida.idempotency_record
      ADD CONSTRAINT idempotency_record_scope_check
      CHECK (scope IN ('enrollment', 'recovery-complete', 'blind-issuance'));
  END IF;
END $$;

INSERT INTO ida.schema_migration(version) VALUES (4)
ON CONFLICT (version) DO NOTHING;
