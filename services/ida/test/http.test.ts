import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { decodeCanonical, encodeCanonical, integerMap } from "@cyber-cipher/protocol-core";
import type { PersistentEnrollment } from "@cyber-cipher/identity-store";
import {
  InMemoryIdempotencyCoordinator,
  createIdentityHttpServer,
  decodeBlindIssuanceResponse,
  encodeBlindIssuanceResponse,
  type EnrollmentCommand,
  type IdentityAuthorityOperations,
} from "../src/index.js";
import type { PublishedMatter } from "@cyber-cipher/matter-registry";

test("HTTP enrollment takes identity from the trusted session and replays identical idempotent requests", async () => {
  let calls = 0;
  let receivedIdentity: string | undefined;
  const operations: IdentityAuthorityOperations = {
    async enroll(command: EnrollmentCommand): Promise<PersistentEnrollment> {
      calls += 1;
      receivedIdentity = command.syntheticIdentityRef;
      return {
        enrollmentId: command.enrollmentId,
        syntheticIdentityRef: command.syntheticIdentityRef,
        personAnchor: 1n,
        activeDeviceHash: 2n,
        activeLeafIndex: 0,
        recoveryId: command.recoveryId,
        recoveryPublicKey: command.recoveryPublicKey,
        recoveryGeneration: 1,
        active: true,
        rowVersion: 1n,
      };
    },
    async issueRecoveryChallenge() {
      throw new Error("not used");
    },
    async completeRecovery() {
      throw new Error("not used");
    },
    async currentCheckpoint() {
      return undefined;
    },
    async checkpointDeltas() {
      return [];
    },
  };
  const server = createIdentityHttpServer({
    tenantId: new Uint8Array(16).fill(0x11),
    operations,
    enrollmentSessions: {
      async syntheticIdentityFor() {
        return "synthetic:authenticated-student";
      },
    },
    idempotency: new InMemoryIdempotencyCoordinator(),
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${address.port}/ida/v1/enrollments`;
    const key = randomUUID();
    const body = encodeCanonical(
      integerMap([
        [1, randomUUID()],
        [2, new Uint8Array(32).fill(0x21)],
        [3, new Uint8Array(32).fill(0x22)],
        [4, new Uint8Array(16).fill(0x23)],
        [5, new Uint8Array(32).fill(0x24)],
      ]),
    );
    const send = (requestBody: Uint8Array) =>
      fetch(url, {
        method: "POST",
        headers: { "content-type": "application/cbor", "idempotency-key": key },
        body: Buffer.from(requestBody),
      });
    const first = await send(body);
    assert.equal(first.status, 201);
    assert.ok(decodeCanonical(new Uint8Array(await first.arrayBuffer())) instanceof Map);
    const replay = await send(body);
    assert.equal(replay.status, 201);
    assert.equal(calls, 1);
    assert.equal(receivedIdentity, "synthetic:authenticated-student");

    const changed = body.slice();
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    const conflict = await send(changed);
    assert.equal(conflict.status, 409);
    assert.equal(calls, 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("HTTP enrollment prefers durable application idempotency without an in-memory coordinator", async () => {
  let durableCalls = 0;
  let receivedKey: string | undefined;
  let receivedSubject: string | undefined;
  const expectedResponse = encodeCanonical(integerMap([[1, 1n], [2, "durable"]]));
  const operations: IdentityAuthorityOperations = {
    async enroll() {
      throw new Error("non-idempotent enrollment must not run");
    },
    async enrollIdempotent(command, key) {
      durableCalls += 1;
      receivedKey = key;
      receivedSubject = command.syntheticIdentityRef;
      return expectedResponse;
    },
    async issueRecoveryChallenge() {
      throw new Error("not used");
    },
    async completeRecovery() {
      throw new Error("not used");
    },
    async currentCheckpoint() {
      return undefined;
    },
    async checkpointDeltas() {
      return [];
    },
  };
  const server = createIdentityHttpServer({
    tenantId: new Uint8Array(16).fill(0x41),
    operations,
    enrollmentSessions: {
      async syntheticIdentityFor() {
        return "synthetic:durable-student";
      },
    },
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address() as AddressInfo;
    const key = randomUUID();
    const response = await fetch(`http://127.0.0.1:${address.port}/ida/v1/enrollments`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "idempotency-key": key },
      body: Buffer.from(
        encodeCanonical(
          integerMap([
            [1, randomUUID()],
            [2, new Uint8Array(32).fill(0x42)],
            [3, new Uint8Array(32).fill(0x43)],
            [4, new Uint8Array(16).fill(0x44)],
            [5, new Uint8Array(32).fill(0x45)],
          ]),
        ),
      ),
    });
    assert.equal(response.status, 201);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), expectedResponse);
    assert.equal(durableCalls, 1);
    assert.equal(receivedKey, key);
    assert.equal(receivedSubject, "synthetic:durable-student");
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("HTTP enrollment rejects absent identified sessions before reading enrollment fields", async () => {
  const server = createIdentityHttpServer({
    tenantId: new Uint8Array(16).fill(0x31),
    operations: {
      async enroll() {
        assert.fail("unauthenticated enrollment must not reach the application");
      },
      async issueRecoveryChallenge() {
        throw new Error("not used");
      },
      async completeRecovery() {
        throw new Error("not used");
      },
      async currentCheckpoint() {
        return undefined;
      },
      async checkpointDeltas() {
        return [];
      },
    },
    enrollmentSessions: {
      async syntheticIdentityFor() {
        return undefined;
      },
    },
    idempotency: new InMemoryIdempotencyCoordinator(),
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${address.port}/ida/v1/enrollments`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "idempotency-key": randomUUID() },
      body: Buffer.from([0xa0]),
    });
    assert.equal(response.status, 401);
  } finally {
    server.close();
    await once(server, "close");
  }
});

test("HTTP exposes public matter metadata and binds blind issuance to the identified session", async () => {
  const matterId = randomUUID();
  const matterKeyId = new Uint8Array(32).fill(0x61);
  const blindSignature = new Uint8Array(384).fill(0x62);
  const matter: PublishedMatter = {
    matterId,
    version: 1,
    title: "Public safety matter",
    opensAt: new Date("2026-10-02T00:00:00.000Z"),
    closesAt: new Date("2026-10-03T00:00:00.000Z"),
    publishedAt: new Date("2026-10-01T00:00:00.000Z"),
    rsaSpkiDer: new Uint8Array([0x30]),
    matterKeyId,
    complaintArtifactId: new Uint8Array(32).fill(0x63),
    voteArtifactId: new Uint8Array(32).fill(0x64),
    handlerOrgId: randomUUID(),
    handlerKeyId: new Uint8Array(32).fill(0x65),
    state: "PUBLISHED",
  };
  let receivedSubject: string | undefined;
  const operations: IdentityAuthorityOperations = {
    async enroll() { throw new Error("not used"); },
    async issueRecoveryChallenge() { throw new Error("not used"); },
    async completeRecovery() { throw new Error("not used"); },
    async currentCheckpoint() { return undefined; },
    async checkpointDeltas() { return []; },
  };
  const server = createIdentityHttpServer({
    tenantId: new Uint8Array(16).fill(0x60),
    operations,
    enrollmentSessions: {
      async syntheticIdentityFor() {
        return "synthetic:student-http";
      },
    },
    blindIssuance: {
      async issueIdempotent(command) {
        receivedSubject = command.syntheticIdentityRef;
        assert.equal(command.matterId, matterId);
        assert.equal(command.matterVersion, 1);
        assert.deepEqual(command.matterKeyId, matterKeyId);
        return encodeBlindIssuanceResponse({
          matterId,
          matterVersion: 1,
          matterKeyId,
          blindSignature,
        });
      },
    },
    matters: {
      async publicMatter() { return matter; },
      async listPublic() { return [matter]; },
    },
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const publicResponse = await fetch(`${base}/public/v1/matters`);
    assert.equal(publicResponse.status, 200);
    const publicCbor = decodeCanonical(new Uint8Array(await publicResponse.arrayBuffer()));
    assert.ok(publicCbor instanceof Map);

    const issuanceBody = encodeCanonical(
      integerMap([[1, matterKeyId], [2, new Uint8Array(384).fill(0x66)]]),
    );
    const issuanceResponse = await fetch(
      `${base}/ida/v1/matters/${matterId}/1/blind-issuance`,
      {
        method: "POST",
        headers: {
          "content-type": "application/cbor",
          "idempotency-key": randomUUID(),
        },
        body: Buffer.from(issuanceBody),
      },
    );
    assert.equal(issuanceResponse.status, 201);
    assert.deepEqual(
      decodeBlindIssuanceResponse(new Uint8Array(await issuanceResponse.arrayBuffer())).blindSignature,
      blindSignature,
    );
    assert.equal(receivedSubject, "synthetic:student-http");
  } finally {
    server.close();
    await once(server, "close");
  }
});
