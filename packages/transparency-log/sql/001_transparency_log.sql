CREATE SCHEMA IF NOT EXISTS transparency_log;

CREATE TABLE IF NOT EXISTS transparency_log.schema_migration (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS transparency_log.tenant_context (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  tenant_id uuid NOT NULL UNIQUE,
  tenant_slug text NOT NULL UNIQUE CHECK (tenant_slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE TABLE IF NOT EXISTS transparency_log.log_leaf (
  leaf_index bigint PRIMARY KEY CHECK (leaf_index >= 0),
  entry_cbor bytea NOT NULL,
  leaf_hash bytea NOT NULL UNIQUE CHECK (octet_length(leaf_hash) = 32),
  appended_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS transparency_log.tree_head (
  tree_size bigint PRIMARY KEY CHECK (tree_size > 0),
  root_hash bytea NOT NULL CHECK (octet_length(root_hash) = 32),
  previous_finalized_tree_head_hash bytea NOT NULL CHECK (octet_length(previous_finalized_tree_head_hash) = 32),
  signed_tree_head_cbor bytea NOT NULL,
  tree_head_hash bytea NOT NULL UNIQUE CHECK (octet_length(tree_head_hash) = 32),
  issued_at timestamptz NOT NULL,
  finalized_at timestamptz
);

CREATE TABLE IF NOT EXISTS transparency_log.witness_signature (
  tree_size bigint NOT NULL REFERENCES transparency_log.tree_head(tree_size),
  witness_key_id bytea NOT NULL CHECK (octet_length(witness_key_id) = 32),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tree_size, witness_key_id)
);

INSERT INTO transparency_log.schema_migration(version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
