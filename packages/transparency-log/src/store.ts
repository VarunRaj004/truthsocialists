import type { Pool, PoolClient } from "pg";
import { decodeCanonical, logLeafHash } from "@cyber-cipher/protocol-core";
import type { FinalizedTreeHead } from "./heads.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export interface TransparencyStoreConfig { tenantId: string; tenantSlug: string }

export class TransparencyLogStore {
  constructor(readonly pool: Pool, readonly config: TransparencyStoreConfig) {
    if (!UUID_PATTERN.test(config.tenantId)) throw new TypeError("tenantId must be a UUID");
    if (!SLUG_PATTERN.test(config.tenantSlug)) throw new TypeError("invalid tenant slug");
  }

  async initializeTenant(): Promise<void> {
    await this.pool.query(
      `INSERT INTO transparency_log.tenant_context(singleton, tenant_id, tenant_slug)
       VALUES (true, $1::uuid, $2)
       ON CONFLICT (singleton) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, tenant_slug = EXCLUDED.tenant_slug
       WHERE transparency_log.tenant_context.tenant_id = EXCLUDED.tenant_id
         AND transparency_log.tenant_context.tenant_slug = EXCLUDED.tenant_slug`,
      [this.config.tenantId, this.config.tenantSlug],
    );
    await this.assertTenant(this.pool);
  }

  async append(canonicalEntryCbor: Uint8Array): Promise<number> {
    decodeCanonical(canonicalEntryCbor);
    const leafHash = logLeafHash(canonicalEntryCbor);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      await this.assertTenant(client, true);
      const existing = await client.query<{ leaf_index: string }>(
        "SELECT leaf_index FROM transparency_log.log_leaf WHERE leaf_hash = $1",
        [Buffer.from(leafHash)],
      );
      if (existing.rows[0]) { await client.query("COMMIT"); return Number(existing.rows[0].leaf_index); }
      const result = await client.query<{ leaf_index: string }>(
        `INSERT INTO transparency_log.log_leaf(leaf_index, entry_cbor, leaf_hash)
         SELECT COALESCE(MAX(leaf_index) + 1, 0), $1, $2 FROM transparency_log.log_leaf
         RETURNING leaf_index`,
        [Buffer.from(canonicalEntryCbor), Buffer.from(leafHash)],
      );
      await client.query("COMMIT");
      return Number(result.rows[0]!.leaf_index);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async download(start = 0, limit = 10_000): Promise<Uint8Array[]> {
    if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new RangeError("invalid log range");
    await this.assertTenant(this.pool);
    const result = await this.pool.query<{ entry_cbor: Buffer }>(
      "SELECT entry_cbor FROM transparency_log.log_leaf WHERE leaf_index >= $1 ORDER BY leaf_index LIMIT $2",
      [start, limit],
    );
    return result.rows.map((row) => new Uint8Array(row.entry_cbor));
  }

  async saveHead(head: FinalizedTreeHead): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await this.assertTenant(client, true);
      await client.query(
        `INSERT INTO transparency_log.tree_head(
          tree_size, root_hash, previous_finalized_tree_head_hash, signed_tree_head_cbor,
          tree_head_hash, issued_at, finalized_at)
         VALUES ($1,$2,$3,$4,$5,to_timestamp($6::double precision / 1000.0),CASE WHEN $7 THEN clock_timestamp() END)`,
        [head.body.treeSize.toString(), Buffer.from(head.body.rootHash), Buffer.from(head.body.previousFinalizedTreeHeadHash),
          Buffer.from(head.signedTreeHeadCbor), Buffer.from(head.treeHeadHash), head.body.timestamp.toString(), head.final],
      );
      for (const witness of head.witnessSignatures) {
        await client.query(
          "INSERT INTO transparency_log.witness_signature(tree_size,witness_key_id,signature) VALUES ($1,$2,$3)",
          [head.body.treeSize.toString(), Buffer.from(witness.witnessKeyId), Buffer.from(witness.signature)],
        );
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  }

  private async assertTenant(queryable: Pick<Pool, "query"> | Pick<PoolClient, "query">, lock = false): Promise<void> {
    const result = await queryable.query<{ tenant_id: string; tenant_slug: string }>(
      `SELECT tenant_id::text, tenant_slug FROM transparency_log.tenant_context WHERE singleton = true${lock ? " FOR UPDATE" : ""}`,
    );
    const row = result.rows[0];
    if (!row || row.tenant_id !== this.config.tenantId || row.tenant_slug !== this.config.tenantSlug) throw new Error("transparency log tenant mismatch");
  }
}
