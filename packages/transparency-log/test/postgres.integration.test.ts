import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";
import { encodeCanonical } from "@cyber-cipher/protocol-core";
import { applyTransparencyLogMigrations, TransparencyLogStore } from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

test("PostgreSQL transparency storage is tenant-bound, append-only, and idempotent", {
  skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false,
}, async () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  try {
    const database = await pool.query<{ current_database: string }>("SELECT current_database()");
    assert.match(database.rows[0]!.current_database, /(?:^|_)test$/);
    await pool.query("DROP SCHEMA IF EXISTS transparency_log CASCADE");
    await applyTransparencyLogMigrations(pool);
    const store = new TransparencyLogStore(pool, {
      tenantId: "11111111-1111-4111-8111-111111111111",
      tenantSlug: "university-a",
    });
    await store.initializeTenant();
    const first = encodeCanonical(new Map([[1n, 1n]]));
    const second = encodeCanonical(new Map([[1n, 2n]]));
    assert.equal(await store.append(first), 0);
    assert.equal(await store.append(first), 0);
    assert.equal(await store.append(second), 1);
    assert.deepEqual(await store.download(), [first, second]);
    const rows = await pool.query<{ count: string }>("SELECT count(*) FROM transparency_log.log_leaf");
    assert.equal(rows.rows[0]!.count, "2");
  } finally { await pool.end(); }
});
