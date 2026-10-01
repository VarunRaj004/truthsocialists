ALTER TABLE matter_registry.matter
    ADD COLUMN IF NOT EXISTS retirement_evidence bytea
    CHECK (retirement_evidence IS NULL OR octet_length(retirement_evidence) = 32);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'matter_retirement_evidence_consistency'
      AND conrelid = 'matter_registry.matter'::regclass
  ) THEN
    ALTER TABLE matter_registry.matter
      ADD CONSTRAINT matter_retirement_evidence_consistency CHECK (
        (retired_at IS NULL AND retirement_evidence IS NULL) OR
        (retired_at IS NOT NULL AND retirement_evidence IS NOT NULL)
      ) NOT VALID;
  END IF;
END $$;

INSERT INTO matter_registry.schema_migration(version) VALUES (2)
ON CONFLICT (version) DO NOTHING;
