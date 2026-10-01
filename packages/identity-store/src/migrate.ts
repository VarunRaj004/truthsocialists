import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

const migrationUrl = new URL("../../sql/001_identity_membership.sql", import.meta.url);

export async function applyIdentityMigrations(pool: Pool): Promise<void> {
  const sql = await readFile(migrationUrl, "utf8");
  await pool.query(sql);
}
