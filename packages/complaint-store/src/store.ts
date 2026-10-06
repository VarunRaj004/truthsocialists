import { timingSafeEqual } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
  assertBytesLength,
  ed25519SpkiFromRaw,
  encodeCanonical,
  encodeFieldElement,
  keyIdFromSpkiDer,
  logEntry,
  logLeafHash,
  receiptBody,
  sha256,
  signedObject,
  signingInput,
  verifyEd25519Raw,
} from "@cyber-cipher/protocol-core";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_SERIALIZATION_RETRIES = 3;

export type ComplaintStoreErrorCode =
  | "TENANT_MISMATCH"
  | "MATTER_NOT_OPEN"
  | "PROOF_SESSION_NOT_FOUND"
  | "PROOF_SESSION_CONSUMED"
  | "PROOF_SESSION_EXPIRED"
  | "LEASE_MISMATCH"
  | "ENTITLEMENT_SPENT"
  | "NULLIFIER_USED"
  | "IDEMPOTENCY_CONFLICT";

export class ComplaintStoreError extends Error {
  constructor(readonly code: ComplaintStoreErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ComplaintStoreError";
  }
}

export interface ComplaintStoreConfig {
  tenantId: string;
  tenantSlug: string;
}

export interface ComplaintMatterInput {
  matterId: string;
  version: number;
  opensAt: Date;
  closesAt: Date;
  matterKeyId: Uint8Array;
  rsaSpkiDer: Uint8Array;
  complaintArtifactId: Uint8Array;
  handlerOrgId: string;
  handlerKeyId: Uint8Array;
}

export interface PersistProofSessionInput {
  challengeId: Uint8Array;
  epoch: bigint;
  membershipRoot: bigint;
  signedLeaseCbor: Uint8Array;
  issuedAt: Date;
  expiresAt: Date;
}

export interface ReceiptSigner {
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface LockedComplaintAuthorization {
  readonly matter: ComplaintMatterInput;
  readonly signedLeaseCbor: Uint8Array;
  readonly epoch: bigint;
  readonly membershipRoot: bigint;
}

export interface AcceptComplaintInput {
  idempotencyKey: string;
  requestHash: Uint8Array;
  complaintId: string;
  eventId: string;
  matterId: string;
  matterVersion: number;
  challengeId: Uint8Array;
  signedLeaseHash: Uint8Array;
  serial: Uint8Array;
  nullifier: bigint;
  complaintCommitment: Uint8Array;
  ciphertextUri: string;
  ciphertextHash: Uint8Array;
  ciphertextSize: number;
  aeadNonce: Uint8Array;
  hpkeEnc: Uint8Array;
  wrappedDek: Uint8Array;
  handlerKeyId: Uint8Array;
  receiptId: Uint8Array;
  receiptNonce: Uint8Array;
  acceptedAt: Date;
  receiptSigner: ReceiptSigner;
  /** Side-effect free: serializable retries may invoke this verifier again. */
  authorize(locked: LockedComplaintAuthorization): void | Promise<void>;
}

export interface AcceptedComplaint {
  complaintId: string;
  receiptId: Uint8Array;
  signedReceiptCbor: Uint8Array;
  logEntryHash: Uint8Array;
  acceptedAt: Date;
}

interface MatterRow {
  matter_id: string;
  version: string;
  opens_at: Date;
  closes_at: Date;
  matter_key_id: Buffer;
  rsa_spki_der: Buffer;
  complaint_artifact_id: Buffer;
  handler_org_id: string;
  handler_key_id: Buffer;
}

interface ProofSessionRow {
  epoch: string;
  membership_root: string;
  signed_lease_cbor: Buffer;
  signed_lease_hash: Buffer;
  consumed_at: Date | null;
  expired: boolean;
}

interface IdempotencyRow {
  request_hash: Buffer;
  complaint_id: string | null;
  receipt_id: Buffer | null;
  signed_receipt_cbor: Buffer | null;
  log_entry_hash: Buffer | null;
  accepted_at: Date | null;
}

function uuid(name: string, value: string, v4 = false): string {
  if (!(v4 ? UUID_V4_PATTERN : UUID_PATTERN).test(value)) {
    throw new TypeError(`${name} must be a canonical ${v4 ? "UUIDv4" : "UUID"}`);
  }
  return value.toLowerCase();
}

function validDate(name: string, value: Date): Date {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError(`${name} is invalid`);
  return new Date(value.getTime());
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function matterFromRow(row: MatterRow): ComplaintMatterInput {
  return {
    matterId: row.matter_id,
    version: Number(row.version),
    opensAt: new Date(row.opens_at),
    closesAt: new Date(row.closes_at),
    matterKeyId: new Uint8Array(row.matter_key_id),
    rsaSpkiDer: new Uint8Array(row.rsa_spki_der),
    complaintArtifactId: new Uint8Array(row.complaint_artifact_id),
    handlerOrgId: row.handler_org_id,
    handlerKeyId: new Uint8Array(row.handler_key_id),
  };
}

function isSerializationFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "40001";
}

export class PostgresComplaintStore {
  readonly tenantId: string;
  readonly tenantSlug: string;

  constructor(private readonly pool: Pool, config: ComplaintStoreConfig) {
    this.tenantId = uuid("tenantId", config.tenantId);
    if (!TENANT_SLUG_PATTERN.test(config.tenantSlug)) throw new TypeError("tenantSlug is invalid");
    this.tenantSlug = config.tenantSlug;
  }

  async initializeTenant(): Promise<void> {
    await this.serializable(async (client) => {
      await client.query(
        `INSERT INTO complaint_store.tenant_context(singleton, tenant_id, tenant_slug)
         VALUES (true, $1::uuid, $2) ON CONFLICT (singleton) DO NOTHING`,
        [this.tenantId, this.tenantSlug],
      );
      await this.assertTenant(client, true);
    });
  }

  async publishMatter(input: ComplaintMatterInput): Promise<void> {
    const value = this.validateMatter(input);
    await this.serializable(async (client) => {
      await this.assertTenant(client);
      await client.query(
        `INSERT INTO complaint_store.matter(
           matter_id, version, opens_at, closes_at, matter_key_id, rsa_spki_der,
           complaint_artifact_id, handler_org_id, handler_key_id
         ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8::uuid,$9)`,
        [value.matterId, value.version, value.opensAt, value.closesAt,
         Buffer.from(value.matterKeyId), Buffer.from(value.rsaSpkiDer),
         Buffer.from(value.complaintArtifactId), value.handlerOrgId, Buffer.from(value.handlerKeyId)],
      );
    });
  }

  async persistProofSession(input: PersistProofSessionInput): Promise<void> {
    assertBytesLength("challengeId", input.challengeId, 16);
    encodeFieldElement(input.membershipRoot);
    if (input.epoch < 0n) throw new RangeError("proof-session epoch must be non-negative");
    if (input.signedLeaseCbor.length === 0 || input.signedLeaseCbor.length > 4096) {
      throw new RangeError("signed proof lease has an invalid size");
    }
    const issuedAt = validDate("issuedAt", input.issuedAt);
    const expiresAt = validDate("expiresAt", input.expiresAt);
    const lifetime = expiresAt.getTime() - issuedAt.getTime();
    if (lifetime <= 0 || lifetime > 60_000) throw new RangeError("proof-session lifetime must be 1-60 seconds");
    await this.serializable(async (client) => {
      await this.assertTenant(client);
      await client.query(
        `INSERT INTO complaint_store.proof_session(
           challenge_id, epoch, membership_root, signed_lease_cbor,
           signed_lease_hash, issued_at, expires_at
         ) VALUES ($1,$2,$3::numeric,$4,$5,$6,$7)`,
        [Buffer.from(input.challengeId), input.epoch.toString(), input.membershipRoot.toString(),
         Buffer.from(input.signedLeaseCbor), Buffer.from(sha256(input.signedLeaseCbor)), issuedAt, expiresAt],
      );
    });
  }

  async acceptComplaint(input: AcceptComplaintInput): Promise<AcceptedComplaint> {
    const value = this.validateAcceptance(input);
    return this.serializable(async (client) => {
      await this.assertTenant(client);
      await client.query(
        `DELETE FROM complaint_store.submission_idempotency
         WHERE idempotency_key=$1::uuid AND expires_at <= $2`,
        [value.idempotencyKey, value.acceptedAt],
      );
      const claimed = await client.query(
        `INSERT INTO complaint_store.submission_idempotency(idempotency_key,request_hash,created_at,expires_at)
         VALUES ($1::uuid,$2,$3,$3 + interval '24 hours')
         ON CONFLICT DO NOTHING RETURNING idempotency_key`,
        [value.idempotencyKey, Buffer.from(value.requestHash), value.acceptedAt],
      );
      if (claimed.rowCount !== 1) {
        const replay = await client.query<IdempotencyRow>(
          `SELECT i.request_hash,i.complaint_id,r.receipt_id,r.signed_receipt_cbor,
                  c.initial_log_entry_hash AS log_entry_hash,c.accepted_at
           FROM complaint_store.submission_idempotency i
           LEFT JOIN complaint_store.complaint_record c ON c.complaint_id=i.complaint_id
           LEFT JOIN complaint_store.receipt_record r ON r.complaint_id=i.complaint_id
           WHERE i.idempotency_key=$1::uuid FOR UPDATE OF i`,
          [value.idempotencyKey],
        );
        const prior = replay.rows[0];
        if (prior === undefined || !equal(new Uint8Array(prior.request_hash), value.requestHash)) {
          throw new ComplaintStoreError("IDEMPOTENCY_CONFLICT", "idempotency key was reused with different request bytes");
        }
        if (
          prior.complaint_id === null || prior.receipt_id === null || prior.signed_receipt_cbor === null ||
          prior.log_entry_hash === null || prior.accepted_at === null
        ) {
          throw new Error("idempotency record is incomplete");
        }
        return {
          complaintId: prior.complaint_id,
          receiptId: new Uint8Array(prior.receipt_id),
          signedReceiptCbor: new Uint8Array(prior.signed_receipt_cbor),
          logEntryHash: new Uint8Array(prior.log_entry_hash),
          acceptedAt: new Date(prior.accepted_at),
        };
      }
      const matterResult = await client.query<MatterRow>(
        `SELECT * FROM complaint_store.matter
         WHERE matter_id=$1::uuid AND version=$2 FOR UPDATE`,
        [value.matterId, value.matterVersion],
      );
      const matterRow = matterResult.rows[0];
      if (matterRow === undefined || value.acceptedAt < matterRow.opens_at || value.acceptedAt >= matterRow.closes_at) {
        throw new ComplaintStoreError("MATTER_NOT_OPEN", "matter is not open for complaint submission");
      }
      const matter = matterFromRow(matterRow);
      if (!equal(matter.handlerKeyId, value.handlerKeyId)) {
        throw new TypeError("handler key does not match the published matter");
      }
      const sessionResult = await client.query<ProofSessionRow>(
        `SELECT epoch::text, membership_root::text, signed_lease_cbor, signed_lease_hash,
                consumed_at, (expires_at < $2) AS expired
         FROM complaint_store.proof_session WHERE challenge_id=$1 FOR UPDATE`,
        [Buffer.from(value.challengeId), value.acceptedAt],
      );
      const session = sessionResult.rows[0];
      if (session === undefined) throw new ComplaintStoreError("PROOF_SESSION_NOT_FOUND", "proof session is unknown");
      if (session.consumed_at !== null) throw new ComplaintStoreError("PROOF_SESSION_CONSUMED", "proof session is consumed");
      if (session.expired) throw new ComplaintStoreError("PROOF_SESSION_EXPIRED", "proof session has expired");
      if (!equal(new Uint8Array(session.signed_lease_hash), value.signedLeaseHash)) {
        throw new ComplaintStoreError("LEASE_MISMATCH", "proof-session lease hash does not match");
      }
      await value.authorize({
        matter,
        signedLeaseCbor: new Uint8Array(session.signed_lease_cbor),
        epoch: BigInt(session.epoch),
        membershipRoot: BigInt(session.membership_root),
      });
      const spent = await client.query(
        `INSERT INTO complaint_store.spent_entitlement(matter_key_id,serial,spent_at)
         VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING serial`,
        [Buffer.from(matter.matterKeyId), Buffer.from(value.serial), value.acceptedAt],
      );
      if (spent.rowCount !== 1) throw new ComplaintStoreError("ENTITLEMENT_SPENT", "entitlement serial was already spent");
      const nullifier = await client.query(
        `INSERT INTO complaint_store.used_nullifier(matter_id,matter_version,nullifier,used_at)
         VALUES ($1::uuid,$2,$3::numeric,$4) ON CONFLICT DO NOTHING RETURNING nullifier`,
        [value.matterId, value.matterVersion, value.nullifier.toString(), value.acceptedAt],
      );
      if (nullifier.rowCount !== 1) throw new ComplaintStoreError("NULLIFIER_USED", "complaint nullifier was already used");

      const occurredAt = BigInt(value.acceptedAt.getTime());
      const eventCbor = encodeCanonical(logEntry({
        eventId: uuidBytes(value.eventId),
        eventType: 1n,
        complaintId: uuidBytes(value.complaintId),
        matterId: uuidBytes(value.matterId),
        matterVersion: BigInt(value.matterVersion),
        eventCommitment: value.complaintCommitment,
        occurredAt,
        actorClass: 1n,
      }));
      const logEntryHash = logLeafHash(eventCbor);
      await client.query(
        `INSERT INTO complaint_store.complaint_record(
           complaint_id,matter_id,matter_version,commitment,ciphertext_uri,
           ciphertext_hash,ciphertext_size,aead_nonce,hpke_enc,wrapped_dek,
           handler_org_id,handler_key_id,accepted_at,initial_log_entry_hash
         ) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11::uuid,$12,$13,$14)`,
        [value.complaintId, value.matterId, value.matterVersion, Buffer.from(value.complaintCommitment),
         value.ciphertextUri, Buffer.from(value.ciphertextHash), value.ciphertextSize,
         Buffer.from(value.aeadNonce), Buffer.from(value.hpkeEnc), Buffer.from(value.wrappedDek),
         matter.handlerOrgId, Buffer.from(value.handlerKeyId), value.acceptedAt, Buffer.from(logEntryHash)],
      );
      await client.query(
        `INSERT INTO complaint_store.log_outbox(
           event_id,complaint_id,canonical_event_cbor,log_entry_hash,created_at
         ) VALUES ($1::uuid,$2::uuid,$3,$4,$5)`,
        [value.eventId, value.complaintId, Buffer.from(eventCbor), Buffer.from(logEntryHash), value.acceptedAt],
      );
      const signedReceiptCbor = await this.signReceipt(value, logEntryHash);
      await client.query(
        `INSERT INTO complaint_store.receipt_record(receipt_id,complaint_id,signed_receipt_cbor,issued_at)
         VALUES ($1,$2::uuid,$3,$4)`,
        [Buffer.from(value.receiptId), value.complaintId, Buffer.from(signedReceiptCbor), value.acceptedAt],
      );
      await client.query(
        "UPDATE complaint_store.proof_session SET consumed_at=$2 WHERE challenge_id=$1",
        [Buffer.from(value.challengeId), value.acceptedAt],
      );
      await client.query(
        `UPDATE complaint_store.submission_idempotency SET complaint_id=$2::uuid
         WHERE idempotency_key=$1::uuid`,
        [value.idempotencyKey, value.complaintId],
      );
      return {
        complaintId: value.complaintId,
        receiptId: value.receiptId.slice(),
        signedReceiptCbor,
        logEntryHash,
        acceptedAt: new Date(value.acceptedAt),
      };
    });
  }

  private validateMatter(input: ComplaintMatterInput): ComplaintMatterInput {
    const matterId = uuid("matterId", input.matterId, true);
    const handlerOrgId = uuid("handlerOrgId", input.handlerOrgId);
    if (!Number.isSafeInteger(input.version) || input.version < 1 || input.version > 0xffff_ffff) {
      throw new RangeError("matterVersion is invalid");
    }
    const opensAt = validDate("opensAt", input.opensAt);
    const closesAt = validDate("closesAt", input.closesAt);
    if (closesAt <= opensAt) throw new RangeError("matter close time must follow open time");
    assertBytesLength("matterKeyId", input.matterKeyId, 32);
    if (input.rsaSpkiDer.length === 0) throw new TypeError("RSA SPKI must not be empty");
    assertBytesLength("complaintArtifactId", input.complaintArtifactId, 32);
    assertBytesLength("handlerKeyId", input.handlerKeyId, 32);
    return { ...input, matterId, handlerOrgId, opensAt, closesAt };
  }

  private validateAcceptance(input: AcceptComplaintInput): AcceptComplaintInput {
    const idempotencyKey = uuid("idempotencyKey", input.idempotencyKey, true);
    assertBytesLength("requestHash", input.requestHash, 32);
    const complaintId = uuid("complaintId", input.complaintId, true);
    const eventId = uuid("eventId", input.eventId, true);
    const matterId = uuid("matterId", input.matterId, true);
    if (!Number.isSafeInteger(input.matterVersion) || input.matterVersion < 1 || input.matterVersion > 0xffff_ffff) {
      throw new RangeError("matterVersion is invalid");
    }
    assertBytesLength("challengeId", input.challengeId, 16);
    assertBytesLength("signedLeaseHash", input.signedLeaseHash, 32);
    assertBytesLength("serial", input.serial, 16);
    encodeFieldElement(input.nullifier);
    assertBytesLength("complaintCommitment", input.complaintCommitment, 32);
    assertBytesLength("ciphertextHash", input.ciphertextHash, 32);
    assertBytesLength("aeadNonce", input.aeadNonce, 12);
    assertBytesLength("hpkeEnc", input.hpkeEnc, 32);
    assertBytesLength("wrappedDek", input.wrappedDek, 48);
    assertBytesLength("handlerKeyId", input.handlerKeyId, 32);
    assertBytesLength("receiptId", input.receiptId, 16);
    assertBytesLength("receiptNonce", input.receiptNonce, 32);
    if (!input.ciphertextUri.startsWith("object://") || input.ciphertextUri.length > 2048) {
      throw new TypeError("ciphertextUri must be a bounded object URI");
    }
    if (!Number.isSafeInteger(input.ciphertextSize) || input.ciphertextSize < 17 || input.ciphertextSize > 104_857_616) {
      throw new RangeError("ciphertextSize is outside the encrypted complaint limit");
    }
    return { ...input, idempotencyKey, complaintId, eventId, matterId, acceptedAt: validDate("acceptedAt", input.acceptedAt) };
  }

  private async signReceipt(input: AcceptComplaintInput, logEntryHash: Uint8Array): Promise<Uint8Array> {
    assertBytesLength("receipt public key", input.receiptSigner.publicKey, 32);
    const spki = ed25519SpkiFromRaw(input.receiptSigner.publicKey);
    const body = receiptBody({
      receiptId: input.receiptId,
      receiptNonce: input.receiptNonce,
      complaintId: uuidBytes(input.complaintId),
      matterId: uuidBytes(input.matterId),
      matterVersion: BigInt(input.matterVersion),
      complaintCommitment: input.complaintCommitment,
      acceptedAt: BigInt(input.acceptedAt.getTime()),
      logEntryHash,
      receiptKeyId: keyIdFromSpkiDer(spki),
    });
    const bodyCbor = encodeCanonical(body);
    const message = signingInput("receipt", bodyCbor);
    const signature = assertBytesLength("receipt signature", await input.receiptSigner.sign(message), 64);
    if (!verifyEd25519Raw(input.receiptSigner.publicKey, message, signature)) {
      throw new Error("receipt signer returned an invalid signature");
    }
    return encodeCanonical(signedObject(body, signature));
  }

  private async assertTenant(client: PoolClient, lock = false): Promise<void> {
    const result = await client.query<{ tenant_id: string; tenant_slug: string }>(
      `SELECT tenant_id::text,tenant_slug FROM complaint_store.tenant_context
       WHERE singleton=true${lock ? " FOR UPDATE" : ""}`,
    );
    const row = result.rows[0];
    if (row === undefined || row.tenant_id !== this.tenantId || row.tenant_slug !== this.tenantSlug) {
      throw new ComplaintStoreError("TENANT_MISMATCH", "complaint database tenant binding does not match");
    }
  }

  private async serializable<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    for (let retry = 0; retry < MAX_SERIALIZATION_RETRIES; retry += 1) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const value = await work(client);
        await client.query("COMMIT");
        return value;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        if (isSerializationFailure(error) && retry + 1 < MAX_SERIALIZATION_RETRIES) continue;
        throw error;
      } finally {
        client.release();
      }
    }
    throw new Error("unreachable serialization retry state");
  }
}

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}
