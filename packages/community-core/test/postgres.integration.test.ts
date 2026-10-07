import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { applyCommunityMigrations } from "../src/index.js";
const databaseUrl = process.env.TEST_DATABASE_URL;
test("community schema enforces one append-only vote per complaint nullifier", { skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false }, async () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  try {
    const db = await pool.query<{ current_database: string }>("SELECT current_database()"); assert.match(db.rows[0]!.current_database, /(?:^|_)test$/);
    await pool.query("DROP SCHEMA IF EXISTS community CASCADE"); await applyCommunityMigrations(pool); const complaintId = randomUUID();
    const values = [complaintId, "123", 0, Buffer.alloc(32), JSON.stringify(["1"]), JSON.stringify({ proof: {} }), Buffer.alloc(32)];
    await pool.query("INSERT INTO community.vote(complaint_id,vote_nullifier,choice,artifact_id,public_signals,proof_envelope,proof_hash,accepted_at) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,now())", values);
    await assert.rejects(() => pool.query("INSERT INTO community.vote(complaint_id,vote_nullifier,choice,artifact_id,public_signals,proof_envelope,proof_hash,accepted_at) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,now())", values), /duplicate key/);
    await assert.rejects(() => pool.query("DELETE FROM community.vote WHERE complaint_id=$1", [complaintId]), /append-only/);
  } finally { await pool.end(); }
});
