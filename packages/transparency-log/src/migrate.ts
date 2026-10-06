import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

export async function applyTransparencyLogMigrations(pool: Pool): Promise<void> {
  const migration = new URL("../../sql/001_transparency_log.sql", import.meta.url);
  await pool.query(await readFile(migration, "utf8"));
}
