import { spawnSync } from "node:child_process";
import { ensureCircom } from "./toolchain.mjs";

const binary = await ensureCircom();
const result = spawnSync(binary, ["--version"], { encoding: "utf8" });
if (result.status !== 0) throw new Error(result.stderr || "pinned Circom binary did not execute");
if (!result.stdout.includes("2.2.3")) throw new Error(`unexpected Circom version: ${result.stdout.trim()}`);
process.stdout.write(`${result.stdout.trim()} (${binary})\n`);
