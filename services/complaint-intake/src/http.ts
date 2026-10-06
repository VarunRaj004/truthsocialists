import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, type ServerOptions } from "node:https";
import { ComplaintStoreError } from "@cyber-cipher/complaint-store";
import type { ComplaintIntakeApplication, DurableProofSessionIssuer } from "./application.js";
import { encodeComplaintResponse, encodeErrorResponse, encodeProofSessionResponse } from "./wire.js";

const MAX_REQUEST_BYTES = 105 * 1024 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface ComplaintHttpConfig {
  proofSessions: Pick<DurableProofSessionIssuer, "issue">;
  intake: Pick<ComplaintIntakeApplication, "submit">;
}

export function createComplaintHttpServer(config: ComplaintHttpConfig): Server {
  return createServer(handler(config));
}

export function createComplaintHttpsServer(options: ServerOptions, config: ComplaintHttpConfig): Server {
  return createHttpsServer(options, handler(config));
}

function handler(config: ComplaintHttpConfig) {
  return (request: IncomingMessage, response: ServerResponse): void => {
    void route(config, request, response).catch((error: unknown) => {
      const conflict = error instanceof ComplaintStoreError && error.code === "IDEMPOTENCY_CONFLICT";
      const replay = error instanceof ComplaintStoreError &&
        (error.code === "ENTITLEMENT_SPENT" || error.code === "NULLIFIER_USED" || error.code === "PROOF_SESSION_CONSUMED");
      send(response, conflict || replay ? 409 : 400, encodeErrorResponse(
        conflict ? "IDEMPOTENCY_CONFLICT" : replay ? error.code : "REQUEST_REJECTED",
      ));
    });
  };
}

async function route(config: ComplaintHttpConfig, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", "https://complaints.invalid");
  if (request.method === "POST" && url.pathname === "/complaints/v1/proof-sessions") {
    if (request.headers["content-length"] !== undefined && request.headers["content-length"] !== "0") {
      throw new TypeError("proof-session request body must be empty");
    }
    send(response, 201, encodeProofSessionResponse(await config.proofSessions.issue()));
    return;
  }
  if (request.method === "POST" && url.pathname === "/complaints/v1/complaints") {
    requireCbor(request);
    const key = requireIdempotencyKey(request);
    const body = await readBody(request);
    send(response, 201, encodeComplaintResponse(await config.intake.submit(key, body)));
    return;
  }
  send(response, 404, encodeErrorResponse("NOT_FOUND"));
}

function requireCbor(request: IncomingMessage): void {
  if (request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !== "application/cbor") {
    throw new TypeError("content type must be application/cbor");
  }
}

function requireIdempotencyKey(request: IncomingMessage): string {
  const value = request.headers["idempotency-key"];
  if (typeof value !== "string" || !UUID_V4.test(value)) {
    throw new TypeError("Idempotency-Key must be a UUIDv4");
  }
  return value.toLowerCase();
}

async function readBody(request: IncomingMessage): Promise<Uint8Array> {
  const declared = request.headers["content-length"];
  if (declared !== undefined && (!/^[0-9]+$/.test(declared) || Number(declared) > MAX_REQUEST_BYTES)) {
    throw new RangeError("request body is too large");
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BYTES) throw new RangeError("request body is too large");
    chunks.push(bytes);
  }
  if (total === 0) throw new TypeError("request body is empty");
  return new Uint8Array(Buffer.concat(chunks));
}

function send(response: ServerResponse, status: number, body: Uint8Array): void {
  if (response.headersSent) return;
  response.writeHead(status, {
    "content-type": "application/cbor",
    "content-length": body.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(body);
}

export function assertComplaintTransport(urlValue: string, allowTestOnionHttp = false): URL {
  const url = new URL(urlValue);
  const testOnion = allowTestOnionHttp && url.protocol === "http:" && url.hostname.endsWith(".onion");
  if (url.protocol !== "https:" && !testOnion) throw new Error("complaint submission requires direct TLS");
  if (url.username !== "" || url.password !== "") throw new Error("submission URL must not contain credentials");
  return url;
}
