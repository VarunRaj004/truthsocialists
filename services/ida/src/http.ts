import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { sha256 } from "@cyber-cipher/protocol-core";
import type { IdentityAuthorityOperations } from "./application.js";
import {
  decodeCompleteRecoveryRequest,
  decodeEnrollmentRequest,
  decodeRecoveryChallengeRequest,
  encodeCheckpointDeltasResponse,
  encodeEnrollmentResponse,
  encodeErrorResponse,
  encodeRecoveryChallengeResponse,
} from "./wire.js";

const MAX_BODY_BYTES = 64 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface EnrollmentSessionAuthorizer {
  syntheticIdentityFor(request: IncomingMessage): Promise<string | undefined>;
}

export interface HttpOperationResult {
  status: number;
  body: Uint8Array;
  cacheControl: string;
}

export interface IdempotencyCoordinator {
  execute(
    scope: string,
    key: string,
    requestBody: Uint8Array,
    operation: () => Promise<HttpOperationResult>,
  ): Promise<HttpOperationResult>;
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("idempotency key was reused with different request bytes");
    this.name = "IdempotencyConflictError";
  }
}

export class InMemoryIdempotencyCoordinator implements IdempotencyCoordinator {
  private readonly completed = new Map<string, { requestHash: string; result: HttpOperationResult }>();
  private readonly running = new Map<
    string,
    { requestHash: string; promise: Promise<HttpOperationResult> }
  >();

  async execute(
    scope: string,
    key: string,
    requestBody: Uint8Array,
    operation: () => Promise<HttpOperationResult>,
  ): Promise<HttpOperationResult> {
    const composite = `${scope}:${key.toLowerCase()}`;
    const requestHash = Buffer.from(sha256(requestBody)).toString("hex");
    const existing = this.completed.get(composite);
    if (existing !== undefined) {
      if (existing.requestHash !== requestHash) throw new IdempotencyConflictError();
      return cloneResult(existing.result);
    }
    const pending = this.running.get(composite);
    if (pending !== undefined) {
      if (pending.requestHash !== requestHash) throw new IdempotencyConflictError();
      return cloneResult(await pending.promise);
    }
    const promise = operation();
    this.running.set(composite, { requestHash, promise });
    try {
      const result = await promise;
      this.completed.set(composite, { requestHash, result: cloneResult(result) });
      return cloneResult(result);
    } finally {
      this.running.delete(composite);
    }
  }
}

function cloneResult(result: HttpOperationResult): HttpOperationResult {
  return { ...result, body: result.body.slice() };
}

export interface IdentityHttpConfig {
  tenantId: Uint8Array;
  operations: IdentityAuthorityOperations;
  enrollmentSessions: EnrollmentSessionAuthorizer;
  idempotency: IdempotencyCoordinator;
}

export function createIdentityHttpServer(config: IdentityHttpConfig): Server {
  if (config.tenantId.length !== 16) throw new TypeError("tenantId must be 16 bytes");
  return createServer((request, response) => {
    void route(config, request, response).catch((error: unknown) => {
      const status = error instanceof IdempotencyConflictError ? 409 : 400;
      send(response, {
        status,
        body: encodeErrorResponse(status === 409 ? "IDEMPOTENCY_CONFLICT" : "REQUEST_REJECTED"),
        cacheControl: "no-store",
      });
    });
  });
}

async function route(
  config: IdentityHttpConfig,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const url = new URL(request.url ?? "/", "http://ida.invalid");
  if (request.method === "POST" && url.pathname === "/ida/v1/enrollments") {
    requireCbor(request);
    const syntheticIdentityRef = await config.enrollmentSessions.syntheticIdentityFor(request);
    if (syntheticIdentityRef === undefined) {
      send(response, { status: 401, body: encodeErrorResponse("AUTHENTICATION_REQUIRED"), cacheControl: "no-store" });
      return;
    }
    const key = requireIdempotencyKey(request);
    const body = await readBody(request);
    const result = await config.idempotency.execute(`enroll:${syntheticIdentityRef}`, key, body, async () => {
      const input = decodeEnrollmentRequest(body);
      const enrolled = await config.operations.enroll({ ...input, syntheticIdentityRef });
      return { status: 201, body: encodeEnrollmentResponse(enrolled), cacheControl: "no-store" };
    });
    send(response, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/ida/v1/recovery/challenges") {
    requireCbor(request);
    const recoveryId = decodeRecoveryChallengeRequest(await readBody(request));
    const challenge = await config.operations.issueRecoveryChallenge(recoveryId);
    send(response, { status: 201, body: encodeRecoveryChallengeResponse(challenge), cacheControl: "no-store" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/ida/v1/recovery/complete") {
    requireCbor(request);
    const key = requireIdempotencyKey(request);
    const body = await readBody(request);
    const result = await config.idempotency.execute("recovery-complete", key, body, async () => {
      const recovered = await config.operations.completeRecovery(decodeCompleteRecoveryRequest(body));
      return { status: 200, body: encodeEnrollmentResponse(recovered), cacheControl: "no-store" };
    });
    send(response, result);
    return;
  }
  if (request.method === "GET" && url.pathname === "/public/v1/membership/checkpoints/current") {
    const checkpoint = await config.operations.currentCheckpoint();
    if (checkpoint === undefined) {
      send(response, { status: 404, body: encodeErrorResponse("CHECKPOINT_NOT_AVAILABLE"), cacheControl: "public, max-age=5" });
      return;
    }
    send(response, { status: 200, body: checkpoint.signedCheckpointCbor, cacheControl: "public, max-age=30" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/public/v1/membership/deltas") {
    const afterEpoch = parseUint(url.searchParams.get("afterEpoch"), "afterEpoch");
    const limitValue = url.searchParams.get("limit");
    const limit = limitValue === null ? 100 : Number(parseUint(limitValue, "limit"));
    const checkpoints = await config.operations.checkpointDeltas(afterEpoch, limit);
    send(response, {
      status: 200,
      body: encodeCheckpointDeltasResponse(config.tenantId, checkpoints),
      cacheControl: "public, max-age=30",
    });
    return;
  }
  send(response, { status: 404, body: encodeErrorResponse("NOT_FOUND"), cacheControl: "no-store" });
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
  return value;
}

async function readBody(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_BODY_BYTES) throw new RangeError("request body is too large");
    chunks.push(bytes);
  }
  if (total === 0) throw new TypeError("request body is empty");
  return new Uint8Array(Buffer.concat(chunks));
}

function parseUint(value: string | null, name: string): bigint {
  if (value === null || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new TypeError(`${name} is invalid`);
  return BigInt(value);
}

function send(response: ServerResponse, result: HttpOperationResult): void {
  if (response.headersSent) return;
  response.writeHead(result.status, {
    "content-type": "application/cbor",
    "content-length": result.body.length,
    "cache-control": result.cacheControl,
    "x-content-type-options": "nosniff",
  });
  response.end(result.body);
}
