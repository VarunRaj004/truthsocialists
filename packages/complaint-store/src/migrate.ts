import { readFile } from "node:fs/promises";
import type { Pool } from "pg";

const migrations = [
  new URL("../../sql/001_complaint_acceptance.sql", import.meta.url),
  new URL("../../sql/002_submission_idempotency.sql", import.meta.url),
];

export async function applyComplaintMigrations(pool: Pool): Promise<void> {
  for (const migration of migrations) {
    await pool.query(await readFile(migration, "utf8"));
  }
}
