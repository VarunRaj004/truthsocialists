import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { packageRoot, repositoryRoot } from "./toolchain.mjs";

const [command, circuit, argument, extra] = process.argv.slice(2);
if (!["complaint", "vote"].includes(circuit)) throw new TypeError("circuit must be complaint or vote");

const snarkjsCli = path.join(path.dirname(fileURLToPath(import.meta.resolve("snarkjs"))), "build", "cli.cjs");
const ceremonyRoot = path.join(repositoryRoot, "tmp", "ceremony");
const phase2Root = path.join(ceremonyRoot, "phase2", circuit);
const r1cs = path.join(packageRoot, "build", "circuits", circuit, `${circuit}.r1cs`);
const ptau = path.join(ceremonyRoot, "powersOfTau28_hez_final_14.ptau");
await mkdir(phase2Root, { recursive: true });

function zkey(index) {
  return path.join(phase2Root, `${circuit}_${String(index).padStart(4, "0")}.zkey`);
}

function run(args, capture = false) {
  const result = spawnSync(process.execPath, [snarkjsCli, ...args], {
    cwd: packageRoot,
    encoding: capture ? "utf8" : undefined,
    stdio: capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) throw new Error(`snarkjs ${args.slice(0, 2).join(" ")} failed`);
  return capture ? `${result.stdout}\n${result.stderr}` : "";
}

async function requireFile(file, label) {
  try {
    await stat(file);
  } catch {
    throw new Error(`${label} is missing: ${file}`);
  }
}

if (command === "init") {
  await requireFile(r1cs, "compiled R1CS");
  await requireFile(ptau, "verified phase-one transcript");
  run(["groth16", "setup", r1cs, ptau, zkey(0)]);
  process.stdout.write(`${zkey(0)}\n`);
} else if (command === "contribute") {
  const index = Number(argument);
  if (!Number.isInteger(index) || index < 1 || index > 3) throw new RangeError("contribution index must be 1, 2, or 3");
  if (!extra?.trim()) throw new TypeError("a public contributor name is required");
  await requireFile(zkey(index - 1), "previous contribution");
  run(["zkey", "contribute", zkey(index - 1), zkey(index), `-n=${extra}`, "-v"]);
  process.stdout.write(`${zkey(index)}\n`);
} else if (command === "verify") {
  const index = argument === undefined ? 3 : Number(argument);
  if (!Number.isInteger(index) || index < 0 || index > 3) throw new RangeError("invalid index");
  await requireFile(zkey(index), "phase-two key");
  const output = run(["zkey", "verify", r1cs, ptau, zkey(index)], true);
  if (!output.includes("ZKey Ok!")) throw new Error("snarkjs did not report ZKey Ok!");
  const verificationLog = path.join(phase2Root, `${circuit}_${String(index).padStart(4, "0")}.verify.txt`);
  await writeFile(verificationLog, output.replaceAll("\r\n", "\n"));
  process.stdout.write(`${verificationLog}\n`);
} else if (command === "beacon") {
  const iterations = extra === undefined ? 10 : Number(extra);
  if (!/^[0-9a-f]{64}$/i.test(argument ?? "")) throw new TypeError("beacon must be exactly 32 hex bytes");
  if (!Number.isInteger(iterations) || iterations < 10 || iterations > 30) throw new RangeError("beacon exponent must be 10..30");
  await requireFile(zkey(3), "third independent contribution");
  const final = path.join(phase2Root, `${circuit}_final.zkey`);
  run(["zkey", "beacon", zkey(3), final, argument, String(iterations), "-n=Cyber Cipher public final beacon"]);
  process.stdout.write(`${final}\n`);
} else if (command === "export") {
  const final = path.join(phase2Root, `${circuit}_final.zkey`);
  await requireFile(final, "final beacon key");
  const output = run(["zkey", "verify", r1cs, ptau, final], true);
  if (!output.includes("ZKey Ok!")) throw new Error("final zkey verification failed");
  const verificationLog = path.join(phase2Root, `${circuit}_final.verify.txt`);
  await writeFile(verificationLog, output.replaceAll("\r\n", "\n"));
  const verificationKey = path.join(phase2Root, `${circuit}_verification_key.json`);
  run(["zkey", "export", "verificationkey", final, verificationKey]);
  const summary = {
    finalZkeySha256: createHash("sha256").update(await readFile(final)).digest("hex"),
    verificationKeySha256: createHash("sha256").update(await readFile(verificationKey)).digest("hex"),
    verificationTranscriptSha256: createHash("sha256").update(await readFile(verificationLog)).digest("hex"),
  };
  await writeFile(path.join(phase2Root, `${circuit}_final.hashes.json`), `${JSON.stringify(summary, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(summary)}\n`);
} else {
  throw new TypeError("command must be init, contribute, verify, beacon, or export");
}
