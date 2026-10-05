import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { packageRoot, repositoryRoot } from "./toolchain.mjs";
import {
  encodeArtifactManifest,
} from "../dist/src/artifacts.js";
import { hexToBytes, sha256, utf8 } from "@cyber-cipher/protocol-core";

const lock = JSON.parse(await readFile(path.join(packageRoot, "ceremony.lock.json"), "utf8"));
const ptau = path.join(repositoryRoot, "tmp", "ceremony", lock.phase1.fileName);
const outputRoot = path.join(repositoryRoot, "tmp", "zk-development-keys");
const snarkjsCli = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("snarkjs"))),
  "build",
  "cli.cjs",
);

async function digest(file, algorithm) {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function exists(file) {
  try {
    await stat(file);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function sourceBundleHash(circuit) {
  const files = ["domains.circom", "active_membership.circom", `${circuit}.circom`].sort();
  const hash = createHash("sha256");
  for (const name of files) {
    const nameBytes = Buffer.from(name, "utf8");
    const contents = await readFile(path.join(packageRoot, "circuits", name));
    const lengths = Buffer.alloc(8);
    lengths.writeUInt32BE(nameBytes.length, 0);
    lengths.writeUInt32BE(contents.length, 4);
    hash.update(lengths).update(nameBytes).update(contents);
  }
  return new Uint8Array(hash.digest());
}

function run(args) {
  const result = spawnSync(process.execPath, [snarkjsCli, ...args], {
    cwd: packageRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`snarkjs ${args.slice(0, 2).join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  }
}

if (!(await exists(ptau))) {
  throw new Error(`Powers-of-Tau file missing; run ceremony:verify-phase1 first: ${ptau}`);
}
for (const [algorithm, expected] of [["blake2b512", lock.phase1.blake2b512], ["sha256", lock.phase1.sha256]]) {
  const actual = await digest(ptau, algorithm);
  if (actual !== expected) throw new Error(`${algorithm} mismatch for development setup input`);
}

await mkdir(outputRoot, { recursive: true });
for (const circuit of ["complaint", "vote"]) {
  const circuitRoot = path.join(outputRoot, circuit);
  await mkdir(circuitRoot, { recursive: true });
  const r1cs = path.join(packageRoot, "build", "circuits", circuit, `${circuit}.r1cs`);
  if (!(await exists(r1cs))) throw new Error(`compiled circuit missing: ${r1cs}`);
  const initial = path.join(circuitRoot, `${circuit}_0000.zkey`);
  const final = path.join(circuitRoot, `${circuit}_development.zkey`);
  const verificationKey = path.join(circuitRoot, `${circuit}_verification_key.json`);
  if (!(await exists(final))) {
    await rm(initial, { force: true });
    run(["groth16", "setup", r1cs, ptau, initial]);
    run([
      "zkey",
      "contribute",
      initial,
      final,
      "-n=INSECURE LOCAL DEVELOPMENT CONTRIBUTION",
      `-e=${randomBytes(64).toString("hex")}`,
    ]);
  }
  run(["zkey", "verify", r1cs, ptau, final]);
  run(["zkey", "export", "verificationkey", final, verificationKey]);
  const metadata = {
    productionEligible: false,
    warning: "Single-machine development key. Never deploy or publish as a production ceremony artifact.",
    circuit,
    ptauSha256: lock.phase1.sha256,
    r1csSha256: await digest(r1cs, "sha256"),
    provingKeySha256: await digest(final, "sha256"),
    verificationKeySha256: await digest(verificationKey, "sha256"),
  };
  const wasm = path.join(packageRoot, "build", "circuits", circuit, `${circuit}_js`, `${circuit}.wasm`);
  const phaseTwoStatement = utf8(
    `DEVELOPMENT-ONLY/single-machine/${circuit}/${metadata.provingKeySha256}`,
  );
  const manifest = encodeArtifactManifest({
    circuitName: circuit,
    circuitVersion: 1n,
    treeDepth: 16n,
    proofSystem: "groth16",
    curve: "bn254",
    compiler: "circom 2.2.3 --O2 --sanity_check 2",
    dependencies: new Map([
      ["circomlib", "2.0.5"],
      ["snarkjs", "0.7.6"],
      ["profile", "development-only"],
    ]),
    sourceHash: await sourceBundleHash(circuit),
    r1csHash: hexToBytes(metadata.r1csSha256),
    wasmHash: hexToBytes(await digest(wasm, "sha256")),
    provingKeyHash: hexToBytes(metadata.provingKeySha256),
    verificationKeyHash: hexToBytes(metadata.verificationKeySha256),
    powersOfTauHash: hexToBytes(lock.phase1.sha256),
    phaseTwoTranscriptHash: sha256(phaseTwoStatement),
    builtAt: 0n,
  });
  metadata.artifactId = manifest.artifactIdHex;
  await writeFile(path.join(circuitRoot, `${circuit}_artifact_manifest.cbor`), manifest.bytes);
  await writeFile(path.join(circuitRoot, "DEVELOPMENT_ONLY.json"), `${JSON.stringify(metadata, null, 2)}\n`);
  process.stdout.write(`${circuit}: ${metadata.artifactId}\n`);
}
