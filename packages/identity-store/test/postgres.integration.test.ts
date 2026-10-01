import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { verifyMembershipCheckpoint } from "@cyber-cipher/protocol-core";
import { deviceHash, personHash, type CheckpointSigner } from "@cyber-cipher/membership-core";
import {
  applyIdentityMigrations,
  IdentityStoreError,
  PostgresCheckpointPublisher,
  PostgresIdentityStore,
} from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

function checkpointSigner(): CheckpointSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ type: "spki", format: "der" }));
  return {
    publicKey: spki.slice(-32),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(sign(null, message, keys.privateKey));
    },
  };
}

test(
  "PostgreSQL serializes enrollment allocation and recovery rotation",
  { skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false },
  async () => {
    const pool = new Pool({ connectionString: databaseUrl, max: 8 });
    try {
      const database = await pool.query<{ current_database: string }>("SELECT current_database()");
      assert.match(
        database.rows[0]!.current_database,
        /(?:^|_)test$/,
        "integration tests refuse to reset a database whose name does not end in 'test'",
      );
      await pool.query("DROP SCHEMA IF EXISTS ida CASCADE");
      await applyIdentityMigrations(pool);

      const tenantId = "11111111-1111-4111-8111-111111111111";
      const store = new PostgresIdentityStore(pool, { tenantId, tenantSlug: "university-a" });
      await store.initializeTenant();

      const firstRecoveryId = new Uint8Array(16).fill(0x11);
      const firstEnrollmentId = randomUUID();
      const firstAnchor = personHash(101n);
      const [first, second] = await Promise.all([
        store.enrollSynthetic({
          enrollmentId: firstEnrollmentId,
          syntheticIdentityRef: "synthetic:student-0001",
          personAnchor: firstAnchor,
          deviceHash: deviceHash(201n),
          recoveryId: firstRecoveryId,
          recoveryPublicKey: new Uint8Array(32).fill(0x21),
        }),
        store.enrollSynthetic({
          enrollmentId: randomUUID(),
          syntheticIdentityRef: "synthetic:student-0002",
          personAnchor: personHash(102n),
          deviceHash: deviceHash(202n),
          recoveryId: new Uint8Array(16).fill(0x12),
          recoveryPublicKey: new Uint8Array(32).fill(0x22),
        }),
      ]);
      assert.deepEqual(new Set([first.activeLeafIndex, second.activeLeafIndex]), new Set([0, 1]));
      assert.equal((await store.membershipState()).nextLeafIndex, 2);

      const wrongTenant = new PostgresIdentityStore(pool, {
        tenantId: "22222222-2222-4222-8222-222222222222",
        tenantSlug: "university-b",
      });
      await assert.rejects(
        wrongTenant.initializeTenant(),
        (error: unknown) => error instanceof IdentityStoreError && error.code === "TENANT_MISMATCH",
      );

      const challengeId = new Uint8Array(16).fill(0x31);
      const issuedAt = new Date();
      await store.issueRecoveryChallenge(firstRecoveryId, async (locked) => {
        assert.equal(locked.enrollmentId, firstEnrollmentId);
        assert.equal(locked.recoveryGeneration, 1);
        return {
          challengeId,
          signedChallengeCbor: new Uint8Array([0xa1, 0x01, 0x02]),
          issuedAt,
          expiresAt: new Date(issuedAt.getTime() + 300_000),
        };
      });

      await assert.rejects(
        store.completeRecoveryAtomic({
          challengeId,
          newDeviceHash: deviceHash(301n),
          newRecoveryId: new Uint8Array(16).fill(0x41),
          newRecoveryPublicKey: new Uint8Array(32).fill(0x51),
          authorize: async () => {
            throw new Error("invalid recovery signature");
          },
        }),
        (error: unknown) =>
          error instanceof IdentityStoreError && error.code === "AUTHORIZATION_REJECTED",
      );
      const attempts = await pool.query<{ attempts: number }>(
        "SELECT attempts FROM ida.recovery_challenge WHERE challenge_id = $1",
        [Buffer.from(challengeId)],
      );
      assert.equal(attempts.rows[0]!.attempts, 1);
      assert.equal((await store.enrollment(firstEnrollmentId))!.recoveryGeneration, 1);

      const authorize = async (locked: {
        recoveryGeneration: number;
        personAnchor: bigint;
        signedChallengeCbor: Uint8Array;
      }): Promise<void> => {
        assert.equal(locked.recoveryGeneration, 1);
        assert.equal(locked.personAnchor, firstAnchor);
        assert.deepEqual(locked.signedChallengeCbor, new Uint8Array([0xa1, 0x01, 0x02]));
        await new Promise((resolve) => setTimeout(resolve, 40));
      };
      const completions = await Promise.allSettled([
        store.completeRecoveryAtomic({
          challengeId,
          newDeviceHash: deviceHash(401n),
          newRecoveryId: new Uint8Array(16).fill(0x61),
          newRecoveryPublicKey: new Uint8Array(32).fill(0x71),
          authorize,
        }),
        store.completeRecoveryAtomic({
          challengeId,
          newDeviceHash: deviceHash(402n),
          newRecoveryId: new Uint8Array(16).fill(0x62),
          newRecoveryPublicKey: new Uint8Array(32).fill(0x72),
          authorize,
        }),
      ]);
      assert.equal(completions.filter((result) => result.status === "fulfilled").length, 1);
      const failure = completions.find((result) => result.status === "rejected");
      assert.ok(failure?.status === "rejected");
      assert.ok(failure.reason instanceof IdentityStoreError);
      assert.equal(failure.reason.code, "CHALLENGE_CONSUMED");

      const rotated = await store.enrollment(firstEnrollmentId);
      assert.ok(rotated);
      assert.equal(rotated.personAnchor, firstAnchor);
      assert.equal(rotated.recoveryGeneration, 2);
      assert.equal(rotated.activeLeafIndex, 2);
      assert.equal((await store.membershipState()).nextLeafIndex, 3);

      const leaves = await pool.query<{ leaf_index: number; state: string }>(
        "SELECT leaf_index, state FROM ida.membership_leaf ORDER BY leaf_index",
      );
      assert.deepEqual(leaves.rows, [
        { leaf_index: 0, state: "REVOKED" },
        { leaf_index: 1, state: "ACTIVE" },
        { leaf_index: 2, state: "ACTIVE" },
      ]);
      assert.deepEqual(
        (await store.pendingUpdates()).map((update) => update.operation),
        ["ACTIVATE", "ACTIVATE", "REVOKE", "ACTIVATE"],
      );

      const signer = checkpointSigner();
      const publisher = new PostgresCheckpointPublisher(
        pool,
        tenantId,
        "university-a",
        signer,
      );
      const publishedAt = BigInt(Date.now());
      const checkpoint = await publisher.publishPending(publishedAt);
      assert.ok(checkpoint);
      const checkpointBody = verifyMembershipCheckpoint(
        checkpoint.signedCheckpointCbor,
        signer.publicKey,
        { previousCheckpointHash: new Uint8Array(32), minimumEpoch: 1n },
      );
      assert.equal(checkpointBody.epoch, 1n);
      assert.equal(checkpointBody.publishedAt, publishedAt);
      assert.equal((await store.membershipState()).currentEpoch, 1n);
      assert.equal((await store.pendingUpdates()).length, 0);
      assert.deepEqual((await publisher.latestCheckpoint())!.checkpointHash, checkpoint.checkpointHash);
      assert.equal((await publisher.checkpointsAfter(0n)).length, 1);
      assert.equal(await publisher.publishPending(publishedAt + 30_000n), undefined);
    } finally {
      await pool.end();
    }
  },
);
