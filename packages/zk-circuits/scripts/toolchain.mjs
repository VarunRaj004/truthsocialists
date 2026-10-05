import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const repositoryRoot = path.resolve(packageRoot, "../..");

export async function toolchainLock() {
  return JSON.parse(await readFile(path.join(packageRoot, "toolchain.lock.json"), "utf8"));
}

function platformKey() {
  return `${process.platform}-${process.arch}`;
}

async function sha256File(filename) {
  return createHash("sha256").update(await readFile(filename)).digest("hex");
}

export async function ensureCircom() {
  if (process.env.CIRCOM_BIN) return path.resolve(process.env.CIRCOM_BIN);
  const lock = await toolchainLock();
  const asset = lock.circom.assets[platformKey()];
  if (!asset) {
    throw new Error(`no pinned Circom binary for ${platformKey()}; use the pinned build container or CIRCOM_BIN`);
  }
  const directory = path.join(repositoryRoot, "tmp", "circom", lock.circom.version, platformKey());
  const destination = path.join(directory, asset.name);
  await mkdir(directory, { recursive: true });
  try {
    if ((await sha256File(destination)) === asset.sha256) return destination;
    await rm(destination, { force: true });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const url = `https://github.com/iden3/circom/releases/download/v${lock.circom.version}/${asset.name}`;
  let bytes;
  let lastError;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await fetch(url, { redirect: "follow" });
      if (!response.ok) throw new Error(`Circom download failed with HTTP ${response.status}`);
      bytes = new Uint8Array(await response.arrayBuffer());
      break;
    } catch (error) {
      lastError = error;
      if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 1_000 * 2 ** attempt));
    }
  }
  if (bytes === undefined) throw new Error("Circom download failed after four attempts", { cause: lastError });
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== asset.sha256) throw new Error("downloaded Circom binary failed SHA-256 verification");
  await writeFile(destination, bytes, { mode: 0o755 });
  if (process.platform !== "win32") await chmod(destination, 0o755);
  return destination;
}
