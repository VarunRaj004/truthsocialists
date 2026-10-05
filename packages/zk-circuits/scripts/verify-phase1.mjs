import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { packageRoot, repositoryRoot } from "./toolchain.mjs";

const ceremony = JSON.parse(await readFile(path.join(packageRoot, "ceremony.lock.json"), "utf8"));
const directory = path.join(repositoryRoot, "tmp", "ceremony");
const destination = path.join(directory, ceremony.phase1.fileName);
const temporary = `${destination}.tmp`;

async function digest(file, algorithm) {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function download() {
  await mkdir(directory, { recursive: true });
  let lastError;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const response = await fetch(ceremony.phase1.url, { redirect: "follow" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      await writeFile(temporary, new Uint8Array(await response.arrayBuffer()));
      await rename(temporary, destination);
      return;
    } catch (error) {
      lastError = error;
      await rm(temporary, { force: true });
      if (attempt < 4) await new Promise((resolve) => setTimeout(resolve, 1_000 * 2 ** (attempt - 1)));
    }
  }
  throw new Error(`unable to download Powers of Tau transcript`, { cause: lastError });
}

try {
  await stat(destination);
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
  await download();
}

const blake2b512 = await digest(destination, "blake2b512");
if (blake2b512 !== ceremony.phase1.blake2b512) {
  throw new Error(`Powers of Tau BLAKE2b-512 mismatch: ${blake2b512}`);
}
const sha256 = await digest(destination, "sha256");
if (sha256 !== ceremony.phase1.sha256) {
  throw new Error(`Powers of Tau SHA-256 mismatch: ${sha256}`);
}
const snarkjsCli = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("snarkjs"))),
  "build",
  "cli.cjs",
);
const output = await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [snarkjsCli, "powersoftau", "verify", destination], {
    cwd: packageRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let transcript = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      transcript += chunk;
      process.stdout.write(chunk);
    });
  }
  child.once("error", reject);
  child.once("close", (code) => {
    if (code === 0) resolve(transcript.replaceAll("\r\n", "\n"));
    else reject(new Error(`snarkjs Powers-of-Tau verification exited with code ${code}`));
  });
});
if (!output.includes("Powers Of tau file OK!")) {
  throw new Error("snarkjs completed without the Powers Of tau file OK marker");
}
await writeFile(path.join(directory, "phase1-verification.txt"), output);
process.stdout.write(`${JSON.stringify({ path: destination, blake2b512, sha256 })}\n`);
