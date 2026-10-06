import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { applyHandlerMigrations } from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
test("handler schema enforces append-only attributable access events", { skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false }, async () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  try {
    const database = await pool.query<{ current_database: string }>("SELECT current_database()"); assert.match(database.rows[0]!.current_database, /(?:^|_)test$/);
    await pool.query("DROP SCHEMA IF EXISTS handler_workflow CASCADE"); await applyHandlerMigrations(pool);
    const complaintId = randomUUID(); const org = randomUUID(); const actor = randomUUID();
    await pool.query(`INSERT INTO handler_workflow.case_record(complaint_id,organization_id,ciphertext_uri,ciphertext_hash,handler_key_id,state,accepted_at,acknowledgement_due_at,assignment_due_at,finding_due_at)
      VALUES($1,$2,'sha256://cipher',$3,$4,'SUBMITTED',now(),now()+interval '24 hours',now()+interval '72 hours',now()+interval '14 days')`, [complaintId, org, Buffer.alloc(32), Buffer.alloc(32)]);
    const eventId = randomUUID();
    await pool.query(`INSERT INTO handler_workflow.case_access_event(access_event_id,complaint_id,actor_id,action,decision,reason_code,event_cbor,signature,occurred_at)
      VALUES($1,$2,$3,'READ_CASE','DENIED','NOT_ASSIGNED',$4,$5,now())`, [eventId, complaintId, actor, Buffer.from([0xa0]), Buffer.alloc(64)]);
    await assert.rejects(() => pool.query("DELETE FROM handler_workflow.case_access_event WHERE access_event_id=$1", [eventId]), /append-only/);
    assert.equal((await pool.query("SELECT count(*)::text AS count FROM handler_workflow.case_access_event")).rows[0].count, "1");
  } finally { await pool.end(); }
});
