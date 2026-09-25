-- Cyber Cipher v1 reference PostgreSQL schema.
-- Deploy IDENTITY, COMPLAINT, and LOG sections to separate database clusters.
-- Application roles must not receive UPDATE/DELETE on append-only event/log tables.

-- ========================== IDENTITY ZONE ==========================
CREATE SCHEMA IF NOT EXISTS ida;

CREATE TABLE ida.enrollment (
    enrollment_id uuid PRIMARY KEY,
    nic_lookup bytea NOT NULL UNIQUE CHECK (octet_length(nic_lookup) = 32),
    nic_ciphertext bytea NOT NULL,
    eligibility_status text NOT NULL CHECK (eligibility_status IN ('ACTIVE','SUSPENDED','INELIGIBLE')),
    person_anchor numeric(78,0) NOT NULL,
    active_device_hash numeric(78,0) NOT NULL,
    active_leaf_index integer NOT NULL UNIQUE CHECK (active_leaf_index BETWEEN 0 AND 65535),
    recovery_id bytea NOT NULL UNIQUE CHECK (octet_length(recovery_id) = 16),
    recovery_public_key bytea NOT NULL CHECK (octet_length(recovery_public_key) = 32),
    recovery_generation integer NOT NULL CHECK (recovery_generation >= 1),
    enrolled_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE ida.matter_issuance (
    enrollment_id uuid NOT NULL REFERENCES ida.enrollment(enrollment_id),
    matter_id uuid NOT NULL,
    matter_version integer NOT NULL CHECK (matter_version >= 1),
    completed_at timestamptz NOT NULL,
    PRIMARY KEY (enrollment_id, matter_id, matter_version)
);

CREATE TABLE ida.membership_leaf (
    leaf_index integer PRIMARY KEY CHECK (leaf_index BETWEEN 0 AND 65535),
    leaf_value numeric(78,0) NOT NULL,
    state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    updated_epoch bigint NOT NULL CHECK (updated_epoch >= 1)
);

CREATE TABLE ida.membership_checkpoint (
    epoch bigint PRIMARY KEY CHECK (epoch >= 1),
    root numeric(78,0) NOT NULL,
    previous_checkpoint_hash bytea NOT NULL CHECK (octet_length(previous_checkpoint_hash) = 32),
    update_batch_hash bytea NOT NULL CHECK (octet_length(update_batch_hash) = 32),
    checkpoint_cbor bytea NOT NULL,
    checkpoint_hash bytea NOT NULL UNIQUE CHECK (octet_length(checkpoint_hash) = 32),
    published_at timestamptz NOT NULL
);

CREATE TABLE ida.membership_update (
    epoch bigint NOT NULL REFERENCES ida.membership_checkpoint(epoch),
    sequence_in_batch integer NOT NULL CHECK (sequence_in_batch >= 0),
    leaf_index integer NOT NULL CHECK (leaf_index BETWEEN 0 AND 65535),
    operation text NOT NULL CHECK (operation IN ('ACTIVATE','REVOKE')),
    new_leaf_value numeric(78,0) NOT NULL,
    PRIMARY KEY (epoch, sequence_in_batch),
    UNIQUE (epoch, leaf_index)
);

CREATE TABLE ida.recovery_challenge (
    challenge_id bytea PRIMARY KEY CHECK (octet_length(challenge_id) = 16),
    enrollment_id uuid NOT NULL REFERENCES ida.enrollment(enrollment_id),
    recovery_generation integer NOT NULL,
    challenge_cbor bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    CHECK (expires_at <= issued_at + interval '5 minutes')
);

-- ========================= COMPLAINT ZONE =========================
CREATE SCHEMA IF NOT EXISTS complaint;

CREATE TABLE complaint.matter (
    matter_id uuid NOT NULL,
    version integer NOT NULL CHECK (version >= 1),
    title text NOT NULL,
    opens_at timestamptz NOT NULL,
    closes_at timestamptz NOT NULL,
    published_at timestamptz NOT NULL,
    matter_key_id bytea NOT NULL UNIQUE CHECK (octet_length(matter_key_id) = 32),
    rsa_spki_der bytea NOT NULL,
    complaint_artifact_id bytea NOT NULL CHECK (octet_length(complaint_artifact_id) = 32),
    vote_artifact_id bytea NOT NULL CHECK (octet_length(vote_artifact_id) = 32),
    handler_org_id uuid NOT NULL,
    handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id) = 32),
    state text NOT NULL CHECK (state IN ('PUBLISHED','OPEN','CLOSED','RETIRED')),
    PRIMARY KEY (matter_id, version),
    CHECK (published_at <= opens_at - interval '24 hours'),
    CHECK (closes_at > opens_at)
);

CREATE TABLE complaint.proof_session (
    challenge_id bytea PRIMARY KEY CHECK (octet_length(challenge_id) = 16),
    purpose smallint NOT NULL CHECK (purpose IN (1,2)),
    epoch bigint NOT NULL,
    membership_root numeric(78,0) NOT NULL,
    lease_cbor bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at <= issued_at + interval '60 seconds')
);

CREATE TABLE complaint.idempotency_record (
    idempotency_key uuid PRIMARY KEY,
    operation text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status integer,
    response_cbor bytea,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE complaint.spent_entitlement (
    matter_key_id bytea NOT NULL CHECK (octet_length(matter_key_id) = 32),
    serial bytea NOT NULL CHECK (octet_length(serial) = 16),
    spent_at timestamptz NOT NULL,
    PRIMARY KEY (matter_key_id, serial)
);

CREATE TABLE complaint.used_nullifier (
    scope_type smallint NOT NULL CHECK (scope_type IN (1,2)),
    scope_id uuid NOT NULL,
    nullifier numeric(78,0) NOT NULL,
    used_at timestamptz NOT NULL,
    PRIMARY KEY (scope_type, scope_id, nullifier)
);

CREATE TABLE complaint.complaint_record (
    complaint_id uuid PRIMARY KEY,
    matter_id uuid NOT NULL,
    matter_version integer NOT NULL,
    commitment bytea NOT NULL CHECK (octet_length(commitment) = 32),
    ciphertext_uri text NOT NULL,
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    ciphertext_size bigint NOT NULL CHECK (ciphertext_size BETWEEN 1 AND 104857600),
    aead_nonce bytea NOT NULL CHECK (octet_length(aead_nonce) = 12),
    hpke_enc bytea NOT NULL,
    wrapped_dek bytea NOT NULL,
    hpke_suite smallint NOT NULL DEFAULT 1 CHECK (hpke_suite = 1),
    handler_org_id uuid NOT NULL,
    handler_key_id bytea NOT NULL CHECK (octet_length(handler_key_id) = 32),
    status text NOT NULL,
    accepted_at timestamptz NOT NULL,
    initial_log_entry_hash bytea NOT NULL CHECK (octet_length(initial_log_entry_hash) = 32),
    row_version bigint NOT NULL DEFAULT 1,
    FOREIGN KEY (matter_id, matter_version) REFERENCES complaint.matter(matter_id, version)
);

CREATE TABLE complaint.mailbox (
    mailbox_id bytea PRIMARY KEY CHECK (octet_length(mailbox_id) = 16),
    complaint_id uuid NOT NULL UNIQUE REFERENCES complaint.complaint_record(complaint_id),
    auth_public_key bytea NOT NULL CHECK (octet_length(auth_public_key) = 32),
    hpke_public_key bytea NOT NULL CHECK (octet_length(hpke_public_key) = 32),
    state text NOT NULL CHECK (state IN ('ACTIVE','CLOSED')),
    created_at timestamptz NOT NULL
);

CREATE TABLE complaint.receipt_record (
    receipt_id bytea PRIMARY KEY CHECK (octet_length(receipt_id) = 16),
    complaint_id uuid NOT NULL UNIQUE REFERENCES complaint.complaint_record(complaint_id),
    signed_receipt_cbor bytea NOT NULL,
    issued_at timestamptz NOT NULL
);

CREATE TABLE complaint.case_event (
    event_id uuid PRIMARY KEY,
    complaint_id uuid NOT NULL REFERENCES complaint.complaint_record(complaint_id),
    event_type text NOT NULL,
    previous_event_hash bytea NOT NULL CHECK (octet_length(previous_event_hash) = 32),
    private_event_cbor bytea NOT NULL,
    private_event_hash bytea NOT NULL UNIQUE CHECK (octet_length(private_event_hash) = 32),
    public_event_commitment bytea NOT NULL CHECK (octet_length(public_event_commitment) = 32),
    actor_id uuid,
    actor_signature bytea,
    occurred_at timestamptz NOT NULL,
    log_entry_hash bytea NOT NULL CHECK (octet_length(log_entry_hash) = 32)
);

CREATE TABLE complaint.case_access_event (
    access_event_id uuid PRIMARY KEY,
    complaint_id uuid NOT NULL REFERENCES complaint.complaint_record(complaint_id),
    actor_id uuid NOT NULL,
    action text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('ALLOWED','DENIED')),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    signature bytea NOT NULL
);

CREATE TABLE complaint.mailbox_message (
    mailbox_id bytea NOT NULL CHECK (octet_length(mailbox_id) = 16),
    message_number bigint NOT NULL CHECK (message_number >= 1),
    direction smallint NOT NULL CHECK (direction IN (1,2)),
    previous_message_hash bytea NOT NULL CHECK (octet_length(previous_message_hash) = 32),
    ciphertext bytea NOT NULL,
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (mailbox_id, message_number),
    FOREIGN KEY (mailbox_id) REFERENCES complaint.mailbox(mailbox_id)
);

CREATE TABLE complaint.redaction (
    redaction_id uuid PRIMARY KEY,
    complaint_id uuid NOT NULL REFERENCES complaint.complaint_record(complaint_id),
    version integer NOT NULL CHECK (version >= 1),
    public_payload_cbor bytea NOT NULL,
    public_commitment bytea NOT NULL CHECK (octet_length(public_commitment) = 32),
    complainant_opt_in boolean NOT NULL,
    pii_scan_status text NOT NULL CHECK (pii_scan_status IN ('PENDING','PASS','FLAGGED')),
    review_status text NOT NULL CHECK (review_status IN ('DRAFT','PENDING','APPROVED','REJECTED','FROZEN')),
    submitted_by uuid NOT NULL,
    reviewed_by uuid,
    submitted_at timestamptz NOT NULL,
    reviewed_at timestamptz,
    UNIQUE (complaint_id, version)
);

CREATE TABLE complaint.vote (
    complaint_id uuid NOT NULL REFERENCES complaint.complaint_record(complaint_id),
    vote_nullifier numeric(78,0) NOT NULL,
    choice smallint NOT NULL CHECK (choice BETWEEN 0 AND 3),
    artifact_id bytea NOT NULL CHECK (octet_length(artifact_id) = 32),
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (complaint_id, vote_nullifier)
);

CREATE TABLE complaint.auditor_assessment (
    assessment_id uuid PRIMARY KEY,
    complaint_id uuid NOT NULL REFERENCES complaint.complaint_record(complaint_id),
    comparison_status text NOT NULL CHECK (comparison_status IN ('ALIGNED','CONFLICTING','COMMUNITY_INCONCLUSIVE','HANDLER_PENDING')),
    action text NOT NULL CHECK (action IN ('NONE','REQUEST_JUSTIFICATION','FREEZE_PUBLIC','ESCALATE','UNFREEZE_PUBLIC')),
    reason_code text NOT NULL,
    auditor_id uuid NOT NULL,
    signed_event_cbor bytea NOT NULL,
    occurred_at timestamptz NOT NULL
);

CREATE TABLE complaint.transparency_outbox (
    outbox_id uuid PRIMARY KEY,
    aggregate_type text NOT NULL,
    aggregate_id uuid,
    event_cbor bytea NOT NULL,
    leaf_hash bytea NOT NULL UNIQUE CHECK (octet_length(leaf_hash) = 32),
    state text NOT NULL CHECK (state IN ('PENDING','PUBLISHED','FAILED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at timestamptz NOT NULL,
    published_at timestamptz
);

-- ============================ LOG ZONE ============================
CREATE SCHEMA IF NOT EXISTS transparency;

CREATE TABLE transparency.log_leaf (
    leaf_index bigint PRIMARY KEY CHECK (leaf_index >= 0),
    entry_cbor bytea NOT NULL,
    leaf_hash bytea NOT NULL UNIQUE CHECK (octet_length(leaf_hash) = 32),
    inserted_at timestamptz NOT NULL
);

CREATE TABLE transparency.tree_head (
    tree_size bigint PRIMARY KEY CHECK (tree_size >= 1),
    root_hash bytea NOT NULL CHECK (octet_length(root_hash) = 32),
    previous_tree_head_hash bytea NOT NULL CHECK (octet_length(previous_tree_head_hash) = 32),
    tree_head_cbor bytea NOT NULL,
    tree_head_hash bytea NOT NULL UNIQUE CHECK (octet_length(tree_head_hash) = 32),
    issued_at timestamptz NOT NULL,
    final_at timestamptz
);

CREATE TABLE transparency.witness_signature (
    tree_size bigint NOT NULL REFERENCES transparency.tree_head(tree_size),
    witness_key_id bytea NOT NULL CHECK (octet_length(witness_key_id) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tree_size, witness_key_id)
);
