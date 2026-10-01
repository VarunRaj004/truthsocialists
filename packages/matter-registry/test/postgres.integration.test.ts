import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import {
  applyMatterRegistryMigrations,
  generateMatterRsaKeyMaterial,
  MatterRegistryError,
  PostgresMatterRegistry,
} from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

function input(key: ReturnType<typeof generateMatterRsaKeyMaterial>, matterId: string, version: number) {
  return {
    matterId,
    version,
    title: `Synthetic matter version ${version}`,
    opensAt: new Date("2026-10-03T00:00:00.000Z"),
    closesAt: new Date("2026-10-04T00:00:00.000Z"),
    rsaSpkiDer: key.publicKeySpkiDer,
    matterKeyId: key.matterKeyId,
    complaintArtifactId: new Uint8Array(32).fill(0x11 + version),
    voteArtifactId: new Uint8Array(32).fill(0x21 + version),
    handlerOrgId: "33333333-3333-4333-8333-333333333333",
    handlerKeyId: new Uint8Array(32).fill(0x31 + version),
  };
}

test(
  "PostgreSQL matter registry enforces tenant, version, publication, and retirement invariants",
  { skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false },
  async () => {
    const pool = new Pool({ connectionString: databaseUrl, max: 4 });
    try {
      const database = await pool.query<{ current_database: string }>("SELECT current_database()");
      assert.match(database.rows[0]!.current_database, /(?:^|_)test$/);
      await pool.query("DROP SCHEMA IF EXISTS matter_registry CASCADE");
      await applyMatterRegistryMigrations(pool);

      const publishedAt = new Date("2026-10-01T00:00:00.000Z");
      const registry = new PostgresMatterRegistry(pool, {
        tenantId: "11111111-1111-4111-8111-111111111111",
        tenantSlug: "university-a",
        now: () => new Date(publishedAt),
      });
      await registry.initializeTenant();
      const matterId = randomUUID();
      const first = await registry.publish(input(generateMatterRsaKeyMaterial(), matterId, 1));
      assert.equal(first.state, "PUBLISHED");
      assert.equal(first.version, 1);

      await assert.rejects(
        registry.publish(input(generateMatterRsaKeyMaterial(), matterId, 3)),
        (error: unknown) =>
          error instanceof MatterRegistryError && error.code === "VERSION_SEQUENCE",
      );
      const second = await registry.publish(input(generateMatterRsaKeyMaterial(), matterId, 2));
      assert.equal(second.version, 2);
      assert.deepEqual(
        (await registry.listPublic(new Date("2026-10-03T12:00:00.000Z"))).map((matter) => matter.state),
        ["OPEN", "OPEN"],
      );

      await assert.rejects(
        registry.retire(
          matterId,
          1,
          new Uint8Array(32).fill(0x41),
          new Date("2026-10-03T23:59:59.999Z"),
        ),
        (error: unknown) =>
          error instanceof MatterRegistryError && error.code === "MATTER_NOT_CLOSED",
      );
      const retired = await registry.retire(
        matterId,
        1,
        new Uint8Array(32).fill(0x41),
        new Date("2026-10-04T00:00:00.000Z"),
      );
      assert.equal(retired.state, "RETIRED");
      assert.deepEqual(retired.retirementEvidence, new Uint8Array(32).fill(0x41));

      const wrongTenant = new PostgresMatterRegistry(pool, {
        tenantId: "22222222-2222-4222-8222-222222222222",
        tenantSlug: "university-b",
      });
      await assert.rejects(
        wrongTenant.initializeTenant(),
        (error: unknown) =>
          error instanceof MatterRegistryError && error.code === "TENANT_MISMATCH",
      );

      const columns = await pool.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'matter_registry' AND table_name = 'matter'`,
      );
      assert.equal(columns.rows.some((row) => /private|pkcs8|kek/i.test(row.column_name)), false);
    } finally {
      await pool.end();
    }
  },
);
