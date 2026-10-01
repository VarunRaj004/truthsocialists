import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { sha256 } from "@cyber-cipher/protocol-core";
import {
  IdempotencyConflictError as StoreIdempotencyConflictError,
  IdentityStoreError,
} from "@cyber-cipher/identity-store";
import type { IdentityAuthorityOperations } from "./application.js";
import type {
  BlindEntitlementIssuanceOperations,
  PublicMatterRepository,
} from "./issuance.js";
import {
  decodeBlindIssuanceRequest,
  decodeCompleteRecoveryRequest,
  decodeEnrollmentRequest,
  decodeRecoveryChallengeRequest,
  encodeCheckpointDeltasResponse,
  encodeEnrollmentResponse,
  encodeErrorResponse,
  encodePublicMattersResponse,
  encodeRecoveryChallengeResponse,
} from "./wire.js";

const MAX_BODY_BYTES = 64 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BLIND_ISSUANCE_PATH = /^\/ida\/v1\/matters\/([0-9a-f-]{36})\/([1-9][0-9]*)\/blind-issuance$/i;

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
  blindIssuance?: BlindEntitlementIssuanceOperations;
  matters?: PublicMatterRepository;
  idempotency?: IdempotencyCoordinator;
}

export function createIdentityHttpServer(config: IdentityHttpConfig): Server {
  if (config.tenantId.length !== 16) throw new TypeError("tenantId must be 16 bytes");
  return createServer((request, response) => {
    void route(config, request, response).catch((error: unknown) => {
      const status =
        error instanceof IdempotencyConflictError || error instanceof StoreIdempotencyConflictError
          ? 409
          : error instanceof IdentityStoreError && error.code === "ALREADY_ISSUED"
            ? 409
          : 400;
      send(response, {
        status,
        body: encodeErrorResponse(
          error instanceof IdentityStoreError && error.code === "ALREADY_ISSUED"
            ? "ENTITLEMENT_ALREADY_ISSUED"
            : status === 409
              ? "IDEMPOTENCY_CONFLICT"
              : "REQUEST_REJECTED",
        ),
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
  const issuanceMatch = BLIND_ISSUANCE_PATH.exec(url.pathname);
  if (request.method === "POST" && url.pathname === "/ida/v1/enrollments") {
    requireCbor(request);
    const syntheticIdentityRef = await config.enrollmentSessions.syntheticIdentityFor(request);
    if (syntheticIdentityRef === undefined) {
      send(response, { status: 401, body: encodeErrorResponse("AUTHENTICATION_REQUIRED"), cacheControl: "no-store" });
      return;
    }
    const key = requireIdempotencyKey(request);
    const body = await readBody(request);
    const input = decodeEnrollmentRequest(body);
    const command = { ...input, syntheticIdentityRef };
    const result =
      config.operations.enrollIdempotent === undefined
        ? await requireFallbackIdempotency(config).execute(
            `enroll:${syntheticIdentityRef}`,
            key,
            body,
            async () => ({
              status: 201,
              body: encodeEnrollmentResponse(await config.operations.enroll(command)),
              cacheControl: "no-store",
            }),
          )
        : {
            status: 201,
            body: await config.operations.enrollIdempotent(command, key, body),
            cacheControl: "no-store",
          };
    send(response, result);
    return;
  }
  if (request.method === "POST" && issuanceMatch !== null) {
    if (config.blindIssuance === undefined) {
      send(response, { status: 404, body: encodeErrorResponse("NOT_FOUND"), cacheControl: "no-store" });
      return;
    }
    requireCbor(request);
    const syntheticIdentityRef = await config.enrollmentSessions.syntheticIdentityFor(request);
    if (syntheticIdentityRef === undefined) {
      send(response, { status: 401, body: encodeErrorResponse("AUTHENTICATION_REQUIRED"), cacheControl: "no-store" });
      return;
    }
    const matterId = issuanceMatch[1]!;
    if (!UUID_V4.test(matterId)) throw new TypeError("matterId must be a UUIDv4");
    const matterVersion = Number(parseUint(issuanceMatch[2]!, "matterVersion"));
    if (!Number.isSafeInteger(matterVersion) || matterVersion > 0xffff_ffff) {
      throw new RangeError("matterVersion is invalid");
    }
    const key = requireIdempotencyKey(request);
    const body = await readBody(request);
    const wire = decodeBlindIssuanceRequest(body);
    const responseBody = await config.blindIssuance.issueIdempotent(
      { ...wire, syntheticIdentityRef, matterId, matterVersion },
      key,
      body,
    );
    send(response, { status: 201, body: responseBody, cacheControl: "no-store" });
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
    const command = decodeCompleteRecoveryRequest(body);
    const result =
      config.operations.completeRecoveryIdempotent === undefined
        ? await requireFallbackIdempotency(config).execute(
            "recovery-complete",
            key,
            body,
            async () => ({
              status: 200,
              body: encodeEnrollmentResponse(await config.operations.completeRecovery(command)),
              cacheControl: "no-store",
            }),
          )
        : {
            status: 200,
            body: await config.operations.completeRecoveryIdempotent(command, key, body),
            cacheControl: "no-store",
          };
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
  if (request.method === "GET" && url.pathname === "/public/v1/matters") {
    if (config.matters === undefined) {
      send(response, { status: 404, body: encodeErrorResponse("NOT_FOUND"), cacheControl: "no-store" });
      return;
    }
    send(response, {
      status: 200,
      body: encodePublicMattersResponse(await config.matters.listPublic()),
      cacheControl: "public, max-age=30",
    });
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

function requireFallbackIdempotency(config: IdentityHttpConfig): IdempotencyCoordinator {
  if (config.idempotency === undefined) {
    throw new Error("an idempotency coordinator is required for operations without durable support");
  }
  return config.idempotency;
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
