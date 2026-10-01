import assert from "node:assert/strict";
import { once } from "node:events";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { Pool } from "pg";
import {
  assertExactIntegerKeys,
  decodeCanonical,
  encodeCanonical,
  integerMap,
  sha256,
} from "@cyber-cipher/protocol-core";
import {
  deviceHash,
  MembershipCheckpointClient,
  personHash,
  recoveryPublicKey,
  scalarToBytes,
  signRecoveryAuthorization,
  type CheckpointSigner,
} from "@cyber-cipher/membership-core";
import {
  applyIdentityMigrations,
  PostgresCheckpointPublisher,
  PostgresIdentityStore,
} from "@cyber-cipher/identity-store";
import {
  createIdentityHttpServer,
  createInstitutionalSessionToken,
  decodeCheckpointDeltasResponse,
  IdentityAuthorityApplication,
  SignedInstitutionalSessionAuthorizer,
  type InstitutionalSessionSigner,
} from "../src/index.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

function ed25519Signer(): CheckpointSigner & InstitutionalSessionSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ type: "spki", format: "der" }));
  return {
    publicKey: spki.slice(-32),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(sign(null, message, keys.privateKey));
    },
  };
}

function uuidBytes(uuid: string): Uint8Array {
  return new Uint8Array(Buffer.from(uuid.replaceAll("-", ""), "hex"));
}

test(
  "signed session enrolls and recovers through HTTP with verified membership witnesses",
  { skip: databaseUrl === undefined ? "TEST_DATABASE_URL is not configured" : false },
  async () => {
    const pool = new Pool({ connectionString: databaseUrl, max: 8 });
    let server: ReturnType<typeof createIdentityHttpServer> | undefined;
    try {
      const database = await pool.query<{ current_database: string }>("SELECT current_database()");
      assert.match(
        database.rows[0]!.current_database,
        /(?:^|_)test$/,
        "end-to-end tests refuse to reset a database whose name does not end in 'test'",
      );
      await pool.query("DROP SCHEMA IF EXISTS ida CASCADE");
      await applyIdentityMigrations(pool);

      const tenantUuid = "11111111-1111-4111-8111-111111111111";
      const tenantId = uuidBytes(tenantUuid);
      const store = new PostgresIdentityStore(pool, {
        tenantId: tenantUuid,
        tenantSlug: "university-a",
      });
      await store.initializeTenant();

      const checkpointSigner = ed25519Signer();
      const challengeSigner = ed25519Signer();
      const sessionSigner = ed25519Signer();
      const publisher = new PostgresCheckpointPublisher(
        pool,
        tenantUuid,
        "university-a",
        checkpointSigner,
      );
      const now = BigInt(Date.now());
      const application = new IdentityAuthorityApplication(store, publisher, {
        tenantId,
        challengeSigner,
        checkpointPublicKey: checkpointSigner.publicKey,
        now: () => now,
      });
      const sessions = new SignedInstitutionalSessionAuthorizer({
        tenantId,
        issuer: "university-a",
        audience: "cyber-cipher-ida",
        publicKey: sessionSigner.publicKey,
        now: () => now,
      });
      server = createIdentityHttpServer({ tenantId, operations: application, enrollmentSessions: sessions });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const address = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${address.port}`;

      const token = await createInstitutionalSessionToken(
        {
          tenantId,
          sessionId: uuidBytes(randomUUID()),
          syntheticIdentityRef: "synthetic:student-e2e-0001",
          issuer: "university-a",
          audience: "cyber-cipher-ida",
          issuedAt: now,
          expiresAt: now + 10n * 60n * 1000n,
        },
        sessionSigner,
      );
      const recoverySeed = new Uint8Array(16).fill(0x40);
      const recoveryId = new Uint8Array(16).fill(0x41);
      const enrollmentBody = encodeCanonical(
        integerMap([
          [1, randomUUID()],
          [2, scalarToBytes(personHash(7001n))],
          [3, scalarToBytes(deviceHash(8001n))],
          [4, recoveryId],
          [5, recoveryPublicKey(recoverySeed, recoveryId)],
        ]),
      );
      const idempotencyKey = randomUUID();
      const enroll = () =>
        fetch(`${baseUrl}/ida/v1/enrollments`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/cbor",
            "idempotency-key": idempotencyKey,
          },
          body: Buffer.from(enrollmentBody),
        });
      const first = await enroll();
      assert.equal(first.status, 201);
      const firstResponse = new Uint8Array(await first.arrayBuffer());
      const decodedEnrollment = decodeCanonical(firstResponse);
      assertExactIntegerKeys(decodedEnrollment, [1n, 2n, 3n, 4n]);
      assert.equal(decodedEnrollment.get(3n), 0n);

      const replay = await enroll();
      assert.equal(replay.status, 201);
      assert.deepEqual(new Uint8Array(await replay.arrayBuffer()), firstResponse);
      assert.equal((await store.membershipState()).nextLeafIndex, 1);

      const checkpoint = await publisher.publishPending(now + 30_000n);
      assert.ok(checkpoint);
      const deltaResponse = await fetch(`${baseUrl}/public/v1/membership/deltas?afterEpoch=0`);
      assert.equal(deltaResponse.status, 200);
      const decodedDeltas = decodeCheckpointDeltasResponse(
        new Uint8Array(await deltaResponse.arrayBuffer()),
      );
      assert.deepEqual(decodedDeltas.tenantId, tenantId);
      assert.equal(decodedDeltas.checkpoints.length, 1);

      const membershipClient = new MembershipCheckpointClient(tenantId, checkpointSigner.publicKey);
      membershipClient.applyChain(decodedDeltas.checkpoints);
      const witness = membershipClient.witness(0);
      assert.equal(witness.epoch, 1n);
      assert.equal(membershipClient.verifyWitness(witness), true);

      const challengeResponse = await fetch(`${baseUrl}/ida/v1/recovery/challenges`, {
        method: "POST",
        headers: { "content-type": "application/cbor" },
        body: Buffer.from(encodeCanonical(integerMap([[1, recoveryId]]))),
      });
      assert.equal(challengeResponse.status, 201);
      const decodedChallenge = decodeCanonical(
        new Uint8Array(await challengeResponse.arrayBuffer()),
      );
      assertExactIntegerKeys(decodedChallenge, [1n, 2n, 3n, 4n]);
      const signedChallengeCbor = decodedChallenge.get(3n);
      assert.ok(signedChallengeCbor instanceof Uint8Array);

      const newDeviceHash = scalarToBytes(deviceHash(8002n));
      const newRecoverySeed = new Uint8Array(16).fill(0x50);
      const newRecoveryId = new Uint8Array(16).fill(0x51);
      const newRecoveryPublicKey = recoveryPublicKey(newRecoverySeed, newRecoveryId);
      const authorizationSignature = signRecoveryAuthorization(recoverySeed, recoveryId, {
        tenantId,
        signedChallengeHash: sha256(signedChallengeCbor),
        personAnchor: scalarToBytes(personHash(7001n)),
        newDeviceHash,
        newRecoveryId,
        newRecoveryPublicKey,
        expectedRecoveryGeneration: 1n,
      });
      const recoveryBody = encodeCanonical(
        integerMap([
          [1, signedChallengeCbor],
          [2, authorizationSignature],
          [3, newDeviceHash],
          [4, newRecoveryId],
          [5, newRecoveryPublicKey],
        ]),
      );
      const recoveryResponse = await fetch(`${baseUrl}/ida/v1/recovery/complete`, {
        method: "POST",
        headers: {
          "content-type": "application/cbor",
          "idempotency-key": randomUUID(),
        },
        body: Buffer.from(recoveryBody),
      });
      assert.equal(recoveryResponse.status, 200);
      const decodedRecovery = decodeCanonical(new Uint8Array(await recoveryResponse.arrayBuffer()));
      assertExactIntegerKeys(decodedRecovery, [1n, 2n, 3n, 4n]);
      assert.equal(decodedRecovery.get(3n), 1n);
      assert.equal(decodedRecovery.get(4n), 2n);

      const recoveryCheckpoint = await publisher.publishPending(now + 60_000n);
      assert.ok(recoveryCheckpoint);
      const recoveryDeltasResponse = await fetch(
        `${baseUrl}/public/v1/membership/deltas?afterEpoch=1`,
      );
      assert.equal(recoveryDeltasResponse.status, 200);
      const recoveryDeltas = decodeCheckpointDeltasResponse(
        new Uint8Array(await recoveryDeltasResponse.arrayBuffer()),
      );
      membershipClient.applyChain(recoveryDeltas.checkpoints);
      assert.equal(membershipClient.verifyWitness(witness), false);
      assert.throws(() => membershipClient.witness(0), /not active/);
      const recoveredWitness = membershipClient.witness(1);
      assert.equal(recoveredWitness.epoch, 2n);
      assert.equal(membershipClient.verifyWitness(recoveredWitness), true);
    } finally {
      if (server !== undefined) {
        server.close();
        await once(server, "close");
      }
      await pool.end();
    }
  },
);
