import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { sha256, verifyReceipt } from "@cyber-cipher/protocol-core";
import {
  applyComplaintMigrations,
  ComplaintStoreError,
  PostgresComplaintStore,
  type AcceptComplaintInput,
  type ReceiptSigner,
} from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

function receiptSigner(): ReceiptSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ format: "der", type: "spki" }));
  return {
    publicKey: spki.slice(-32),
    sign: (message) => new Uint8Array(sign(null, message, keys.privateKey)),
  };
}

test("PostgreSQL accepts every complaint effect atomically", {
  skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false,
}, async () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  try {
    const database = await pool.query<{ current_database: string }>("SELECT current_database()");
    assert.match(database.rows[0]!.current_database, /(?:^|_)test$/);
    await pool.query("DROP SCHEMA IF EXISTS complaint_store CASCADE");
    await applyComplaintMigrations(pool);
    const store = new PostgresComplaintStore(pool, {
      tenantId: "11111111-1111-4111-8111-111111111111",
      tenantSlug: "university-a",
    });
    await store.initializeTenant();
    const now = new Date("2026-10-06T06:00:00.000Z");
    const matterId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const matterKeyId = new Uint8Array(32).fill(0x11);
    const handlerKeyId = new Uint8Array(32).fill(0x22);
    await store.publishMatter({
      matterId,
      version: 1,
      opensAt: new Date(now.getTime() - 60_000),
      closesAt: new Date(now.getTime() + 60_000),
      matterKeyId,
      rsaSpkiDer: new Uint8Array([0x30, 0x01]),
      complaintArtifactId: new Uint8Array(32).fill(0x33),
      handlerOrgId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      handlerKeyId,
    });
    const challengeId = new Uint8Array(16).fill(0x41);
    const signedLeaseCbor = new Uint8Array([0xa1, 0x01, 0x01]);
    await store.persistProofSession({
      challengeId,
      epoch: 7n,
      membershipRoot: 123n,
      signedLeaseCbor,
      issuedAt: new Date(now.getTime() - 1_000),
      expiresAt: new Date(now.getTime() + 59_000),
    });
    const signer = receiptSigner();
    const input: AcceptComplaintInput = {
      idempotencyKey: randomUUID(),
      requestHash: new Uint8Array(32).fill(0x50),
      complaintId: randomUUID(),
      eventId: randomUUID(),
      matterId,
      matterVersion: 1,
      challengeId,
      signedLeaseHash: sha256(signedLeaseCbor),
      serial: new Uint8Array(16).fill(0x51),
      nullifier: 456n,
      complaintCommitment: new Uint8Array(32).fill(0x61),
      ciphertextUri: "object://complaints/ciphertext-1",
      ciphertextHash: new Uint8Array(32).fill(0x71),
      ciphertextSize: 1024,
      aeadNonce: new Uint8Array(12).fill(0x72),
      hpkeEnc: new Uint8Array(32).fill(0x73),
      wrappedDek: new Uint8Array(48).fill(0x74),
      handlerKeyId,
      receiptId: new Uint8Array(16).fill(0x75),
      receiptNonce: new Uint8Array(32).fill(0x76),
      acceptedAt: now,
      receiptSigner: signer,
      authorize: (locked) => {
        assert.equal(locked.epoch, 7n);
        assert.equal(locked.membershipRoot, 123n);
        assert.deepEqual(locked.signedLeaseCbor, signedLeaseCbor);
        assert.deepEqual(locked.matter.matterKeyId, matterKeyId);
      },
    };
    const accepted = await store.acceptComplaint(input);
    verifyReceipt(accepted.signedReceiptCbor, signer.publicKey, {
      complaintId: uuidBytes(input.complaintId),
      matterId: uuidBytes(matterId),
      matterVersion: 1n,
      complaintCommitment: input.complaintCommitment,
    });
    const counts = await pool.query<{ complaints: string; receipts: string; outbox: string; spent: string; nullifiers: string }>(
      `SELECT
        (SELECT count(*) FROM complaint_store.complaint_record)::text complaints,
        (SELECT count(*) FROM complaint_store.receipt_record)::text receipts,
        (SELECT count(*) FROM complaint_store.log_outbox)::text outbox,
        (SELECT count(*) FROM complaint_store.spent_entitlement)::text spent,
        (SELECT count(*) FROM complaint_store.used_nullifier)::text nullifiers`,
    );
    assert.deepEqual(counts.rows[0], { complaints: "1", receipts: "1", outbox: "1", spent: "1", nullifiers: "1" });
    const replay = await store.acceptComplaint({
      ...input,
      authorize: () => { assert.fail("idempotent replay must not reauthorize"); },
    });
    assert.deepEqual(replay.signedReceiptCbor, accepted.signedReceiptCbor);
    await assert.rejects(store.acceptComplaint({
      ...input,
      requestHash: new Uint8Array(32).fill(0x99),
    }), (error: unknown) => error instanceof ComplaintStoreError && error.code === "IDEMPOTENCY_CONFLICT");

    const rejectedChallenge = new Uint8Array(16).fill(0x42);
    const rejectedLease = new Uint8Array([0xa1, 0x01, 0x02]);
    await store.persistProofSession({
      challengeId: rejectedChallenge,
      epoch: 7n,
      membershipRoot: 123n,
      signedLeaseCbor: rejectedLease,
      issuedAt: new Date(now.getTime() - 1_000),
      expiresAt: new Date(now.getTime() + 59_000),
    });
    await assert.rejects(store.acceptComplaint({
      ...input,
      idempotencyKey: randomUUID(),
      requestHash: new Uint8Array(32).fill(0x53),
      complaintId: randomUUID(),
      eventId: randomUUID(),
      challengeId: rejectedChallenge,
      signedLeaseHash: sha256(rejectedLease),
      serial: new Uint8Array(16).fill(0x52),
      nullifier: 457n,
      receiptId: new Uint8Array(16).fill(0x77),
      authorize: () => { throw new Error("invalid Groth16 proof"); },
    }), /invalid Groth16 proof/);
    const rollback = await pool.query<{ consumed: boolean; spent: string }>(
      `SELECT consumed_at IS NOT NULL AS consumed,
       (SELECT count(*)::text FROM complaint_store.spent_entitlement WHERE serial=$2) AS spent
       FROM complaint_store.proof_session WHERE challenge_id=$1`,
      [Buffer.from(rejectedChallenge), Buffer.from(new Uint8Array(16).fill(0x52))],
    );
    assert.deepEqual(rollback.rows[0], { consumed: false, spent: "0" });
    await assert.rejects(store.acceptComplaint({ ...input, idempotencyKey: randomUUID() }), (error: unknown) =>
      error instanceof ComplaintStoreError && error.code === "PROOF_SESSION_CONSUMED");
  } finally {
    await pool.end();
  }
});

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}
