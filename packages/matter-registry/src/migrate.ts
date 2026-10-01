import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

const migrationUrls = [new URL("../../sql/001_matter_registry.sql", import.meta.url)];

export async function applyMatterRegistryMigrations(pool: Pool): Promise<void> {
  for (const migrationUrl of migrationUrls) {
    await pool.query(await readFile(migrationUrl, "utf8"));
  }
}
