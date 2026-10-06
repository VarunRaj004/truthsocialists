CREATE SCHEMA IF NOT EXISTS handler_workflow;
CREATE TABLE IF NOT EXISTS handler_workflow.tenant_context (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), tenant_id uuid NOT NULL UNIQUE,
  tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);
CREATE TABLE IF NOT EXISTS handler_workflow.staff_credential (
  staff_id uuid NOT NULL, organization_id uuid NOT NULL, credential_id bytea PRIMARY KEY,
  public_key_spki_der bytea NOT NULL, roles text[] NOT NULL CHECK (cardinality(roles) > 0),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0), enabled boolean NOT NULL DEFAULT true,
  enrolled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS handler_workflow.case_record (
  complaint_id uuid PRIMARY KEY, organization_id uuid NOT NULL, assigned_staff_id uuid,
  ciphertext_uri text NOT NULL, ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash)=32),
  handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id)=32),
  state text NOT NULL CHECK (state IN ('SUBMITTED','ACKNOWLEDGED','ASSIGNED','UNDER_REVIEW','ACTION_REQUIRED','RESOLVED','REJECTED','CLOSED','APPEALED')),
  public_suppressed boolean NOT NULL DEFAULT false, row_version bigint NOT NULL DEFAULT 1,
  accepted_at timestamptz NOT NULL, acknowledgement_due_at timestamptz NOT NULL,
  assignment_due_at timestamptz NOT NULL, finding_due_at timestamptz NOT NULL, appeal_until timestamptz
);
CREATE TABLE IF NOT EXISTS handler_workflow.case_event (
  event_id uuid PRIMARY KEY, complaint_id uuid NOT NULL REFERENCES handler_workflow.case_record(complaint_id),
  actor_id uuid NOT NULL, event_cbor bytea NOT NULL, event_hash bytea NOT NULL UNIQUE CHECK (octet_length(event_hash)=32),
  previous_event_hash bytea NOT NULL CHECK (octet_length(previous_event_hash)=32), signature bytea NOT NULL CHECK (octet_length(signature)=64),
  occurred_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS handler_workflow.case_access_event (
  access_event_id uuid PRIMARY KEY, complaint_id uuid NOT NULL REFERENCES handler_workflow.case_record(complaint_id),
  actor_id uuid NOT NULL, action text NOT NULL, decision text NOT NULL CHECK (decision IN ('ALLOWED','DENIED')),
  reason_code text NOT NULL, event_cbor bytea NOT NULL, signature bytea NOT NULL CHECK (octet_length(signature)=64), occurred_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS handler_workflow.mailbox (
  mailbox_id bytea PRIMARY KEY CHECK (octet_length(mailbox_id)=16), complaint_id uuid NOT NULL UNIQUE,
  auth_public_key bytea NOT NULL CHECK (octet_length(auth_public_key)=32), hpke_public_key bytea NOT NULL CHECK (octet_length(hpke_public_key)=32),
  state text NOT NULL CHECK (state IN ('ACTIVE','CLOSED')), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS handler_workflow.mailbox_message (
  mailbox_id bytea NOT NULL REFERENCES handler_workflow.mailbox(mailbox_id), message_number bigint NOT NULL CHECK (message_number>0),
  direction smallint NOT NULL CHECK (direction IN (1,2)), previous_message_hash bytea NOT NULL CHECK (octet_length(previous_message_hash)=32),
  recipient_key_id bytea NOT NULL CHECK (octet_length(recipient_key_id)=32), encapsulated_key bytea NOT NULL CHECK (octet_length(encapsulated_key)=32),
  ciphertext bytea NOT NULL, ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash)=32), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(mailbox_id,message_number)
);
REVOKE UPDATE, DELETE ON handler_workflow.case_event, handler_workflow.case_access_event, handler_workflow.mailbox_message FROM PUBLIC;

CREATE OR REPLACE FUNCTION handler_workflow.reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only table cannot be mutated'; END $$;
DROP TRIGGER IF EXISTS case_event_append_only ON handler_workflow.case_event;
CREATE TRIGGER case_event_append_only BEFORE UPDATE OR DELETE ON handler_workflow.case_event FOR EACH ROW EXECUTE FUNCTION handler_workflow.reject_append_only_mutation();
DROP TRIGGER IF EXISTS access_event_append_only ON handler_workflow.case_access_event;
CREATE TRIGGER access_event_append_only BEFORE UPDATE OR DELETE ON handler_workflow.case_access_event FOR EACH ROW EXECUTE FUNCTION handler_workflow.reject_append_only_mutation();
DROP TRIGGER IF EXISTS mailbox_message_append_only ON handler_workflow.mailbox_message;
CREATE TRIGGER mailbox_message_append_only BEFORE UPDATE OR DELETE ON handler_workflow.mailbox_message FOR EACH ROW EXECUTE FUNCTION handler_workflow.reject_append_only_mutation();
