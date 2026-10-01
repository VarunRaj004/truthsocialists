ALTER TABLE ida.membership_update
    DROP CONSTRAINT IF EXISTS membership_update_epoch_leaf_index_key;

INSERT INTO ida.schema_migration(version) VALUES (2)
ON CONFLICT (version) DO NOTHING;
