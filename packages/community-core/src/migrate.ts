import { readFile } from "node:fs/promises";
import type { Pool } from "pg";
export async function applyCommunityMigrations(pool: Pool): Promise<void> { await pool.query(await readFile(new URL("../../sql/001_community.sql", import.meta.url), "utf8")); }
