import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

const migrationUrls = [
  new URL("../../sql/001_identity_membership.sql", import.meta.url),
  new URL("../../sql/002_checkpoint_publication.sql", import.meta.url),
];

export async function applyIdentityMigrations(pool: Pool): Promise<void> {
  for (const migrationUrl of migrationUrls) {
    const sql = await readFile(migrationUrl, "utf8");
    await pool.query(sql);
  }
}
