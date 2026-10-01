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
  type EnrollmentCommand,
  type IdentityAuthorityOperations,
} from "../src/index.js";

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
