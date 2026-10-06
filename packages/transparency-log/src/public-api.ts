import { encodeCanonical, type CborKey, type CborValue } from "@cyber-cipher/protocol-core";
import { encodeFinalizedTreeHead, type FinalizedTreeHead } from "./heads.js";

export interface PublicTransparencySource {
  entries(start: number, limit: number): Promise<Uint8Array[]>;
  latestFinalizedHead(): Promise<FinalizedTreeHead | undefined>;
  inclusionProof(index: number, treeSize?: number): Promise<Uint8Array[]>;
  consistencyProof(firstSize: number, secondSize?: number): Promise<Uint8Array[]>;
}

export interface PublicApiResponse { status: number; headers: Readonly<Record<string, string>>; body: Uint8Array }

const HEADERS = { "content-type": "application/cbor", "cache-control": "public, max-age=30", "x-content-type-options": "nosniff" };

function uintParameter(url: URL, name: string, fallback?: number): number {
  const raw = url.searchParams.get(name);
  if (raw === null && fallback !== undefined) return fallback;
  const value = raw === null ? Number.NaN : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${name} must be a non-negative integer`);
  return value;
}

function proofResponse(first: bigint, second: bigint, proof: Uint8Array[]): Uint8Array {
  return encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, first], [3n, second], [4n, proof]]));
}

export async function handlePublicLogRequest(source: PublicTransparencySource, requestUrl: string): Promise<PublicApiResponse> {
  try {
    const url = new URL(requestUrl, "https://public.invalid");
    if (url.pathname === "/log/v1/entries") {
      const start = uintParameter(url, "start", 0);
      const limit = Math.min(uintParameter(url, "limit", 1_000), 10_000);
      const values = await source.entries(start, limit);
      return { status: 200, headers: HEADERS, body: encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, BigInt(start)], [3n, values]])) };
    }
    if (url.pathname === "/log/v1/tree-heads/latest") {
      const head = await source.latestFinalizedHead();
      return head ? { status: 200, headers: HEADERS, body: encodeFinalizedTreeHead(head) }
        : { status: 404, headers: HEADERS, body: encodeCanonical(new Map([[1n, "no-finalized-head"]])) };
    }
    if (url.pathname === "/log/v1/proofs/inclusion") {
      const index = uintParameter(url, "index");
      const size = uintParameter(url, "treeSize");
      return { status: 200, headers: HEADERS, body: proofResponse(BigInt(index), BigInt(size), await source.inclusionProof(index, size)) };
    }
    if (url.pathname === "/log/v1/proofs/consistency") {
      const first = uintParameter(url, "firstSize");
      const second = uintParameter(url, "secondSize");
      return { status: 200, headers: HEADERS, body: proofResponse(BigInt(first), BigInt(second), await source.consistencyProof(first, second)) };
    }
    return { status: 404, headers: HEADERS, body: encodeCanonical(new Map([[1n, "not-found"]])) };
  } catch {
    return { status: 400, headers: HEADERS, body: encodeCanonical(new Map([[1n, "invalid-request"]])) };
  }
}
