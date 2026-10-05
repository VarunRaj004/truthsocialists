import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { hexToBytes, sha256, utf8 } from "@cyber-cipher/protocol-core";
import { encodeArtifactManifest } from "../dist/src/artifacts.js";
import { assertProductionPhaseTwoTranscript } from "../dist/src/ceremony.js";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  VOTE_PUBLIC_SIGNAL_NAMES,
} from "../dist/src/signals.js";
import { packageRoot, repositoryRoot } from "./toolchain.mjs";

const [circuit, builtAtValue] = process.argv.slice(2);
if (!["complaint", "vote"].includes(circuit)) throw new TypeError("circuit must be complaint or vote");
if (!/^(?:0|[1-9][0-9]*)$/.test(builtAtValue ?? "")) {
  throw new TypeError("builtAt must be an explicit Unix timestamp in seconds");
}
const builtAt = BigInt(builtAtValue);
const lock = JSON.parse(await readFile(path.join(packageRoot, "ceremony.lock.json"), "utf8"));
const phase2Root = path.join(repositoryRoot, "tmp", "ceremony", "phase2", circuit);
const buildRoot = path.join(packageRoot, "build", "circuits", circuit);
const r1cs = path.join(buildRoot, `${circuit}.r1cs`);
const wasm = path.join(buildRoot, `${circuit}_js`, `${circuit}.wasm`);
const zkey = path.join(phase2Root, `${circuit}_final.zkey`);
const verificationKey = path.join(phase2Root, `${circuit}_verification_key.json`);
const ptau = path.join(repositoryRoot, "tmp", "ceremony", lock.phase1.fileName);
const snarkjsCli = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("snarkjs"))),
  "build",
  "cli.cjs",
);

async function digest(file, algorithm = "sha256") {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function sourceBundleHash() {
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

const verification = spawnSync(process.execPath, [snarkjsCli, "zkey", "verify", r1cs, ptau, zkey], {
  cwd: packageRoot,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
if (verification.status !== 0) throw new Error(`final zkey verification failed: ${verification.stderr}`);
const transcript = `${verification.stdout}\n${verification.stderr}`.replaceAll("\r\n", "\n");
const contributions = assertProductionPhaseTwoTranscript(transcript);
const exported = spawnSync(
  process.execPath,
  [snarkjsCli, "zkey", "export", "verificationkey", zkey, verificationKey],
  { cwd: packageRoot, encoding: "utf8" },
);
if (exported.status !== 0) throw new Error(`verification-key export failed: ${exported.stderr}`);

const manifest = encodeArtifactManifest({
  circuitName: circuit,
  circuitVersion: 1n,
  treeDepth: 16n,
  proofSystem: "groth16",
  curve: "bn254",
  compiler: "circom 2.2.3 --O2 --sanity_check 2",
  dependencies: new Map([["circomlib", "2.0.5"], ["snarkjs", "0.7.6"]]),
  sourceHash: await sourceBundleHash(),
  r1csHash: hexToBytes(await digest(r1cs)),
  wasmHash: hexToBytes(await digest(wasm)),
  provingKeyHash: hexToBytes(await digest(zkey)),
  verificationKeyHash: hexToBytes(await digest(verificationKey)),
  powersOfTauHash: hexToBytes(await digest(ptau)),
  phaseTwoTranscriptHash: sha256(utf8(transcript)),
  builtAt,
});
const output = path.join(repositoryRoot, "tmp", "published-zk-artifacts", circuit, manifest.artifactIdHex);
await mkdir(output, { recursive: true });
await Promise.all([
  copyFile(r1cs, path.join(output, `${circuit}.r1cs`)),
  copyFile(wasm, path.join(output, `${circuit}.wasm`)),
  copyFile(zkey, path.join(output, `${circuit}_final.zkey`)),
  copyFile(verificationKey, path.join(output, `${circuit}_verification_key.json`)),
]);
await writeFile(path.join(output, "artifact-manifest.cbor"), manifest.bytes);
await writeFile(path.join(output, "phase2-verification.txt"), transcript);
await writeFile(path.join(output, "publication.json"), `${JSON.stringify({
  cryptographicChecksPassed: true,
  productionEligibility: "requires-operator-attestations-and-mobile-acceptance",
  artifactId: manifest.artifactIdHex,
  circuit,
  circuitVersion: 1,
  publicSignalNames: circuit === "complaint" ? COMPLAINT_PUBLIC_SIGNAL_NAMES : VOTE_PUBLIC_SIGNAL_NAMES,
  contributions,
  builtAt: builtAt.toString(),
  manifestSha256: createHash("sha256").update(manifest.bytes).digest("hex"),
}, null, 2)}\n`);
process.stdout.write(`${output}\n`);
