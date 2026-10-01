import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import {
  encodeCanonical,
  integerMap,
  sha256,
  verifyMembershipCheckpoint,
} from "@cyber-cipher/protocol-core";
import { deviceHash, personHash, type CheckpointSigner } from "@cyber-cipher/membership-core";
import {
  applyIdentityMigrations,
  IdempotencyConflictError,
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

function enrollmentResponse(enrollment: { enrollmentId: string; activeLeafIndex: number }): Uint8Array {
  return encodeCanonical(
    integerMap([
      [1, enrollment.enrollmentId],
      [2, BigInt(enrollment.activeLeafIndex)],
    ]),
  );
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
      const enrollmentKey = randomUUID();
      const enrollmentHash = sha256(new Uint8Array([1, 2, 3]));
      const firstInput = {
        enrollmentId: firstEnrollmentId,
        syntheticIdentityRef: "synthetic:student-0001",
        personAnchor: firstAnchor,
        deviceHash: deviceHash(201n),
        recoveryId: firstRecoveryId,
        recoveryPublicKey: new Uint8Array(32).fill(0x21),
      };
      const [firstResult, second] = await Promise.all([
        store.enrollSyntheticIdempotent(firstInput, {
          scope: "enrollment",
          key: enrollmentKey,
          requestHash: enrollmentHash,
          encodeResponse: enrollmentResponse,
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
      assert.equal(firstResult.replayed, false);
      assert.ok(firstResult.value);
      const first = firstResult.value;
      assert.deepEqual(new Set([first.activeLeafIndex, second.activeLeafIndex]), new Set([0, 1]));
      assert.equal((await store.membershipState()).nextLeafIndex, 2);
      const enrollmentReplay = await store.enrollSyntheticIdempotent(firstInput, {
        scope: "enrollment",
        key: enrollmentKey,
        requestHash: enrollmentHash,
        encodeResponse: enrollmentResponse,
      });
      assert.equal(enrollmentReplay.replayed, true);
      assert.deepEqual(enrollmentReplay.responseCbor, firstResult.responseCbor);
      assert.equal((await store.membershipState()).nextLeafIndex, 2);
      await assert.rejects(
        store.enrollSyntheticIdempotent(firstInput, {
          scope: "enrollment",
          key: enrollmentKey,
          requestHash: sha256(new Uint8Array([9, 9, 9])),
          encodeResponse: enrollmentResponse,
        }),
        IdempotencyConflictError,
      );

      const issuanceKey = randomUUID();
      const issuanceHash = sha256(new Uint8Array([0x21, 0x22]));
      const issuanceInput = {
        syntheticIdentityRef: firstInput.syntheticIdentityRef,
        matterId: randomUUID(),
        matterVersion: 1,
        matterKeyId: new Uint8Array(32).fill(0x31),
        sign: async () => new Uint8Array(384).fill(0x32),
      };
      const encodeIssuance = (signature: Uint8Array) =>
        encodeCanonical(integerMap([[1, signature]]));
      const issued = await store.issueBlindEntitlementIdempotent(issuanceInput, {
        scope: "blind-issuance",
        key: issuanceKey,
        requestHash: issuanceHash,
        encodeResponse: encodeIssuance,
      });
      assert.equal(issued.replayed, false);
      const issuanceReplay = await store.issueBlindEntitlementIdempotent(issuanceInput, {
        scope: "blind-issuance",
        key: issuanceKey,
        requestHash: issuanceHash,
        encodeResponse: encodeIssuance,
      });
      assert.equal(issuanceReplay.replayed, true);
      assert.deepEqual(issuanceReplay.responseCbor, issued.responseCbor);
      await assert.rejects(
        store.issueBlindEntitlementIdempotent(issuanceInput, {
          scope: "blind-issuance",
          key: randomUUID(),
          requestHash: issuanceHash,
          encodeResponse: encodeIssuance,
        }),
        (error: unknown) =>
          error instanceof IdentityStoreError && error.code === "ALREADY_ISSUED",
      );
      const issuanceColumns = await pool.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'ida' AND table_name = 'matter_issuance'`,
      );
      assert.deepEqual(
        issuanceColumns.rows.map((row) => row.column_name).sort(),
        ["completed_at", "enrollment_id", "matter_id", "matter_version"],
      );

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
        store.completeRecoveryAtomicIdempotent(
          {
            challengeId,
            newDeviceHash: deviceHash(301n),
            newRecoveryId: new Uint8Array(16).fill(0x41),
            newRecoveryPublicKey: new Uint8Array(32).fill(0x51),
            authorize: async () => {
              throw new Error("invalid recovery signature");
            },
          },
          {
            scope: "recovery-complete",
            key: randomUUID(),
            requestHash: sha256(new Uint8Array([4, 5, 6])),
            encodeResponse: enrollmentResponse,
          },
        ),
        (error: unknown) =>
          error instanceof IdentityStoreError && error.code === "AUTHORIZATION_REJECTED",
      );
      const attempts = await pool.query<{ attempts: number }>(
        "SELECT attempts FROM ida.recovery_challenge WHERE challenge_id = $1",
        [Buffer.from(challengeId)],
      );
      assert.equal(attempts.rows[0]!.attempts, 1);
      assert.equal((await store.enrollment(firstEnrollmentId))!.recoveryGeneration, 1);
      assert.equal(
        (
          await pool.query<{ count: string }>(
            "SELECT count(*)::text AS count FROM ida.idempotency_record WHERE scope = 'recovery-complete'",
          )
        ).rows[0]!.count,
        "0",
      );

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

      const secondChallengeId = new Uint8Array(16).fill(0x32);
      const secondIssuedAt = new Date();
      await store.issueRecoveryChallenge(rotated.recoveryId, async () => ({
        challengeId: secondChallengeId,
        signedChallengeCbor: new Uint8Array([0xa1, 0x01, 0x03]),
        issuedAt: secondIssuedAt,
        expiresAt: new Date(secondIssuedAt.getTime() + 300_000),
      }));
      const recoveryKey = randomUUID();
      const recoveryHash = sha256(new Uint8Array([7, 8, 9]));
      const secondRecoveryInput = {
        challengeId: secondChallengeId,
        newDeviceHash: deviceHash(501n),
        newRecoveryId: new Uint8Array(16).fill(0x63),
        newRecoveryPublicKey: new Uint8Array(32).fill(0x73),
        authorize: async () => undefined,
      };
      const recovered = await store.completeRecoveryAtomicIdempotent(secondRecoveryInput, {
        scope: "recovery-complete",
        key: recoveryKey,
        requestHash: recoveryHash,
        encodeResponse: enrollmentResponse,
      });
      assert.equal(recovered.replayed, false);
      assert.equal(recovered.value?.recoveryGeneration, 3);
      assert.equal(recovered.value?.activeLeafIndex, 3);
      const recoveryReplay = await store.completeRecoveryAtomicIdempotent(secondRecoveryInput, {
        scope: "recovery-complete",
        key: recoveryKey,
        requestHash: recoveryHash,
        encodeResponse: enrollmentResponse,
      });
      assert.equal(recoveryReplay.replayed, true);
      assert.deepEqual(recoveryReplay.responseCbor, recovered.responseCbor);
      assert.deepEqual(
        await store.idempotentResponse("recovery-complete", recoveryKey, recoveryHash),
        recovered.responseCbor,
      );
      assert.equal((await store.membershipState()).nextLeafIndex, 4);
      await assert.rejects(
        store.completeRecoveryAtomicIdempotent(secondRecoveryInput, {
          scope: "recovery-complete",
          key: recoveryKey,
          requestHash: sha256(new Uint8Array([8, 8, 8])),
          encodeResponse: enrollmentResponse,
        }),
        IdempotencyConflictError,
      );

      const leaves = await pool.query<{ leaf_index: number; state: string }>(
        "SELECT leaf_index, state FROM ida.membership_leaf ORDER BY leaf_index",
      );
      assert.deepEqual(leaves.rows, [
        { leaf_index: 0, state: "REVOKED" },
        { leaf_index: 1, state: "ACTIVE" },
        { leaf_index: 2, state: "REVOKED" },
        { leaf_index: 3, state: "ACTIVE" },
      ]);
      assert.deepEqual(
        (await store.pendingUpdates()).map((update) => update.operation),
        ["ACTIVATE", "ACTIVATE", "REVOKE", "ACTIVATE", "REVOKE", "ACTIVATE"],
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
