import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  MatterRetirementWorker,
  type MatterRetirementRegistry,
  type PublishedMatter,
} from "../src/index.js";

test("retirement destroys the private key before publishing evidence", async () => {
  const matter: PublishedMatter = {
    matterId: randomUUID(),
    version: 1,
    title: "Closed matter",
    opensAt: new Date("2026-10-01T00:00:00.000Z"),
    closesAt: new Date("2026-10-02T00:00:00.000Z"),
    publishedAt: new Date("2026-09-30T00:00:00.000Z"),
    rsaSpkiDer: new Uint8Array([1]),
    matterKeyId: new Uint8Array(32).fill(0x11),
    complaintArtifactId: new Uint8Array(32).fill(0x12),
    voteArtifactId: new Uint8Array(32).fill(0x13),
    handlerOrgId: randomUUID(),
    handlerKeyId: new Uint8Array(32).fill(0x14),
    state: "CLOSED",
  };
  const order: string[] = [];
  const registry: MatterRetirementRegistry = {
    async retirementCandidates() {
      return [matter];
    },
    async retire(matterId, version, evidence) {
      order.push("retire");
      assert.equal(matterId, matter.matterId);
      assert.equal(version, 1);
      assert.deepEqual(evidence, new Uint8Array(32).fill(0x51));
      return { ...matter, state: "RETIRED" };
    },
  };
  const worker = new MatterRetirementWorker(
    registry,
    {
      async destroy(candidate) {
        order.push("destroy");
        assert.equal(candidate.matterKeyId, matter.matterKeyId);
        return new Uint8Array(32).fill(0x51);
      },
    },
    60_000,
    () => new Date("2026-10-02T00:01:00.000Z"),
  );
  assert.equal(await worker.runOnce(), 1);
  assert.deepEqual(order, ["destroy", "retire"]);
});
