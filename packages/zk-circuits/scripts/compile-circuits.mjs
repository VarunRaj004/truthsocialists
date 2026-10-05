import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ensureCircom, packageRoot } from "./toolchain.mjs";

const binary = await ensureCircom();
const buildRoot = path.join(packageRoot, "build", "circuits");
const includeRoot = path.join(packageRoot, "node_modules");
const snarkjsCli = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("snarkjs"))),
  "build",
  "cli.cjs",
);
await rm(buildRoot, { recursive: true, force: true });
await mkdir(buildRoot, { recursive: true });

const counts = {};
for (const circuit of ["complaint", "vote"]) {
  const output = path.join(buildRoot, circuit);
  await mkdir(output, { recursive: true });
  const source = path.join(packageRoot, "circuits", `${circuit}.circom`);
  const result = spawnSync(
    binary,
    [source, "--r1cs", "--wasm", "--sym", "--inspect", "--O2", "--sanity_check", "2", "-l", includeRoot, "-o", output],
    { cwd: packageRoot, encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`Circom failed for ${circuit}:\n${result.stdout}\n${result.stderr}`);
  }
  await copyFile(
    path.join(output, `${circuit}_js`, "witness_calculator.js"),
    path.join(output, `${circuit}_js`, "witness_calculator.cjs"),
  );
  const info = spawnSync(
    process.execPath,
    [snarkjsCli, "r1cs", "info", path.join(output, `${circuit}.r1cs`)],
    { cwd: packageRoot, encoding: "utf8" },
  );
  if (info.status !== 0) {
    throw new Error(`snarkjs r1cs info failed: ${info.error?.message ?? info.stderr ?? info.stdout}`);
  }
  const match = /# of Constraints:\s*(\d+)/i.exec(`${info.stdout}\n${info.stderr}`);
  if (!match) throw new Error(`unable to parse constraint count for ${circuit}`);
  counts[circuit] = Number(match[1]);
}

const lockPath = path.join(packageRoot, "constraints.lock.json");
try {
  const expected = JSON.parse(await readFile(lockPath, "utf8"));
  for (const circuit of Object.keys(counts)) {
    if (counts[circuit] !== expected[circuit]) {
      throw new Error(`${circuit} constraint count changed: expected ${expected[circuit]}, got ${counts[circuit]}`);
    }
  }
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
await writeFile(path.join(buildRoot, "constraint-counts.json"), `${JSON.stringify(counts, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(counts)}\n`);
