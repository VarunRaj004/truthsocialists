import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import { bytesToHex, equalBytes, sha256 } from "@cyber-cipher/protocol-core";

export interface StoredCiphertext {
  readonly uri: string;
  readonly hash: Uint8Array;
  readonly size: number;
}

export interface CiphertextObjectStore {
  put(ciphertext: Uint8Array): Promise<StoredCiphertext>;
}

export class InMemoryCiphertextObjectStore implements CiphertextObjectStore {
  readonly objects = new Map<string, Uint8Array>();

  async put(ciphertext: Uint8Array): Promise<StoredCiphertext> {
    validateCiphertext(ciphertext);
    const hash = sha256(ciphertext);
    const key = bytesToHex(hash);
    const existing = this.objects.get(key);
    if (existing !== undefined && !equalBytes(existing, ciphertext)) throw new Error("ciphertext hash collision");
    this.objects.set(key, ciphertext.slice());
    return { uri: `object://sha256/${key}`, hash, size: ciphertext.length };
  }
}

export class FileCiphertextObjectStore implements CiphertextObjectStore {
  readonly #baseDirectory: string;

  constructor(baseDirectory: string) {
    if (!isAbsolute(baseDirectory)) throw new TypeError("ciphertext object-store path must be absolute");
    this.#baseDirectory = resolve(baseDirectory);
  }

  async put(ciphertext: Uint8Array): Promise<StoredCiphertext> {
    validateCiphertext(ciphertext);
    const hash = sha256(ciphertext);
    const key = bytesToHex(hash);
    const directory = join(this.#baseDirectory, key.slice(0, 2));
    const target = join(directory, `${key}.bin`);
    if (!target.startsWith(`${this.#baseDirectory}${sep}`)) throw new Error("object path escaped its tenant store");
    await mkdir(directory, { recursive: true });
    const temporary = join(directory, `.${key}.${bytesToHex(randomBytes(12))}.tmp`);
    try {
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(ciphertext);
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        await rename(temporary, target);
      } catch (error) {
        if (!isAlreadyExists(error)) throw error;
        await unlink(temporary).catch(() => undefined);
      }
      const stored = new Uint8Array(await readFile(target));
      if (!equalBytes(sha256(stored), hash) || !equalBytes(stored, ciphertext)) {
        throw new Error("durable ciphertext verification failed");
      }
      return { uri: `object://sha256/${key}`, hash, size: ciphertext.length };
    } catch (error) {
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }
}

function validateCiphertext(ciphertext: Uint8Array): void {
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 17 || ciphertext.length > 104_857_616) {
    throw new RangeError("ciphertext is outside the encrypted complaint limit");
  }
}

function isAlreadyExists(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST";
}
