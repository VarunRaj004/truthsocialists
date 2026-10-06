import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { ProofLeasePurpose, verifyProofLease } from "@cyber-cipher/protocol-core";
import {
  ComplaintProofSessionService,
  InMemoryProofSessionStore,
  type ComplaintRandomSource,
} from "../src/index.js";

class CountingRandom implements ComplaintRandomSource {
  #value = 0;
  bytes(length: number): Uint8Array {
    this.#value += 1;
    return new Uint8Array(length).fill(this.#value);
  }
}

function fixture() {
  const keys = generateKeyPairSync("ed25519");
  const store = new InMemoryProofSessionStore();
  const service = new ComplaintProofSessionService(keys.privateKey, store, new CountingRandom());
  return {
    service,
    store,
    tenantId: new Uint8Array(16).fill(0x11),
    checkpoint: { epoch: 42n, root: new Uint8Array(32).fill(0x22) },
    now: 1_791_158_400_000n,
  };
}

test("issues a signed complaint lease for exactly sixty seconds", () => {
  const { service, tenantId, checkpoint, now } = fixture();
  const issued = service.issue(tenantId, checkpoint, now);
  assert.equal(issued.expiresAt - issued.issuedAt, 60_000n);
  const verified = verifyProofLease(issued.signedLeaseCbor, service.publicKeyRaw(), {
    now: now + 30_000n,
    purpose: ProofLeasePurpose.Complaint,
    currentEpoch: checkpoint.epoch,
    currentRoot: checkpoint.root,
  });
  assert.deepEqual(verified.challengeId, issued.challengeId);
});

test("rejects stale roots, expiration, and cross-tenant lease use", () => {
  const { service, tenantId, checkpoint, now } = fixture();
  const issued = service.issue(tenantId, checkpoint, now);
  assert.throws(() => service.verifyUsable(tenantId, issued.signedLeaseCbor, {
    epoch: checkpoint.epoch + 1n,
    root: new Uint8Array(32).fill(0x33),
  }, now + 1n), /current/);
  assert.throws(() => service.verifyUsable(tenantId, issued.signedLeaseCbor, checkpoint, now + 60_001n), /expired/);
  assert.throws(() => service.verifyUsable(new Uint8Array(16).fill(0x44), issued.signedLeaseCbor, checkpoint, now + 1n), /another tenant/);
});

test("consumes only after success and rejects replay", async () => {
  const { service, store, tenantId, checkpoint, now } = fixture();
  const issued = service.issue(tenantId, checkpoint, now);
  await assert.rejects(
    service.submitWithLease(tenantId, issued.signedLeaseCbor, checkpoint, now + 1n, async () => {
      throw new Error("submission transaction rolled back");
    }),
    /rolled back/,
  );
  assert.equal(store.record(issued.challengeId)!.consumedAt, undefined);
  assert.equal(await service.submitWithLease(
    tenantId,
    issued.signedLeaseCbor,
    checkpoint,
    now + 2n,
    async () => "accepted",
  ), "accepted");
  assert.equal(store.record(issued.challengeId)!.consumedAt, now + 2n);
  await assert.rejects(
    service.submitWithLease(tenantId, issued.signedLeaseCbor, checkpoint, now + 3n, async () => "duplicate"),
    /consumed/,
  );
});

test("prevents concurrent use of one challenge", async () => {
  const { service, tenantId, checkpoint, now } = fixture();
  const issued = service.issue(tenantId, checkpoint, now);
  let release!: () => void;
  const hold = new Promise<void>((resolve) => { release = resolve; });
  const first = service.submitWithLease(tenantId, issued.signedLeaseCbor, checkpoint, now + 1n, async () => {
    await hold;
    return "first";
  });
  await assert.rejects(
    service.submitWithLease(tenantId, issued.signedLeaseCbor, checkpoint, now + 1n, async () => "second"),
    /already in use/,
  );
  release();
  assert.equal(await first, "first");
});
