CREATE SCHEMA IF NOT EXISTS community;
CREATE TABLE IF NOT EXISTS community.tenant_context (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), tenant_id uuid NOT NULL UNIQUE,
  tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);
CREATE TABLE IF NOT EXISTS community.redaction (
  redaction_id uuid PRIMARY KEY, complaint_id uuid NOT NULL, version integer NOT NULL CHECK(version > 0),
  payload_cbor bytea NOT NULL, public_commitment bytea NOT NULL UNIQUE CHECK(octet_length(public_commitment)=32),
  source_complaint_commitment bytea NOT NULL CHECK(octet_length(source_complaint_commitment)=32),
  source_ciphertext_hash bytea NOT NULL CHECK(octet_length(source_ciphertext_hash)=32),
  complainant_opt_in boolean NOT NULL CHECK(complainant_opt_in), pii_findings text[] NOT NULL,
  status text NOT NULL CHECK(status IN ('DRAFT','PII_FLAGGED','PENDING_REVIEW','APPROVED','REJECTED','FROZEN')),
  submitted_by uuid NOT NULL, reviewed_by uuid, submitted_at timestamptz NOT NULL, reviewed_at timestamptz,
  vote_opens_at timestamptz, vote_closes_at timestamptz,
  UNIQUE(complaint_id,version), CHECK(vote_closes_at IS NULL OR vote_closes_at = vote_opens_at + interval '7 days')
);
CREATE TABLE IF NOT EXISTS community.vote (
  complaint_id uuid NOT NULL, vote_nullifier numeric(78,0) NOT NULL, choice smallint NOT NULL CHECK(choice BETWEEN 0 AND 3),
  artifact_id bytea NOT NULL CHECK(octet_length(artifact_id)=32), public_signals jsonb NOT NULL, proof_envelope jsonb NOT NULL,
  proof_hash bytea NOT NULL CHECK(octet_length(proof_hash)=32),
  accepted_at timestamptz NOT NULL, PRIMARY KEY(complaint_id,vote_nullifier)
);
CREATE TABLE IF NOT EXISTS community.auditor_assessment (
  assessment_id uuid PRIMARY KEY, complaint_id uuid NOT NULL, redaction_id uuid NOT NULL REFERENCES community.redaction(redaction_id),
  handler_finding text NOT NULL CHECK(handler_finding IN ('SUBSTANTIATED','UNSUBSTANTIATED','PENDING')),
  community_outcome text NOT NULL CHECK(community_outcome IN ('SUPPORT','OPPOSE','INCONCLUSIVE')),
  community_result_hash bytea NOT NULL CHECK(octet_length(community_result_hash)=32),
  comparison_status text NOT NULL CHECK(comparison_status IN ('ALIGNED','CONFLICTING','COMMUNITY_INCONCLUSIVE','HANDLER_PENDING')),
  action text NOT NULL CHECK(action IN ('NONE','REQUEST_JUSTIFICATION','FREEZE_PUBLIC','ESCALATE','UNFREEZE_PUBLIC')),
  reason_code text NOT NULL, auditor_id uuid NOT NULL, signed_event_cbor bytea NOT NULL,
  signature bytea NOT NULL CHECK(octet_length(signature)=64), occurred_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS community.transparency_outbox (
  outbox_id uuid PRIMARY KEY, aggregate_type text NOT NULL, aggregate_id uuid NOT NULL, event_cbor bytea NOT NULL,
  leaf_hash bytea NOT NULL UNIQUE CHECK(octet_length(leaf_hash)=32), state text NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','PUBLISHED','FAILED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), published_at timestamptz
);
CREATE OR REPLACE FUNCTION community.reject_append_only_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only table cannot be mutated'; END $$;
DROP TRIGGER IF EXISTS vote_append_only ON community.vote;
CREATE TRIGGER vote_append_only BEFORE UPDATE OR DELETE ON community.vote FOR EACH ROW EXECUTE FUNCTION community.reject_append_only_mutation();
DROP TRIGGER IF EXISTS assessment_append_only ON community.auditor_assessment;
CREATE TRIGGER assessment_append_only BEFORE UPDATE OR DELETE ON community.auditor_assessment FOR EACH ROW EXECUTE FUNCTION community.reject_append_only_mutation();
