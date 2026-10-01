import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { personHash, scalarToBytes } from "@cyber-cipher/membership-core";
import {
  finalizeBlindEntitlement,
  generateMatterRsaKeyMaterial,
  prepareBlindEntitlement,
  verifyBlindEntitlement,
  type PublishedMatter,
} from "@cyber-cipher/matter-registry";
import { encodeCanonical, integerMap } from "@cyber-cipher/protocol-core";
import {
  BlindEntitlementIssuanceApplication,
  decodeBlindIssuanceResponse,
  type BlindIssuanceRepository,
} from "../src/index.js";

test("identified issuance returns an unlinkable RFC 9474 token and zeroes loaded key bytes", async () => {
  const key = generateMatterRsaKeyMaterial();
  const matterId = randomUUID();
  const matter: PublishedMatter = {
    matterId,
    version: 1,
    title: "Campus safety",
    opensAt: new Date("2026-10-02T00:00:00.000Z"),
    closesAt: new Date("2026-10-03T00:00:00.000Z"),
    publishedAt: new Date("2026-10-01T00:00:00.000Z"),
    rsaSpkiDer: key.publicKeySpkiDer,
    matterKeyId: key.matterKeyId,
    complaintArtifactId: new Uint8Array(32).fill(0x31),
    voteArtifactId: new Uint8Array(32).fill(0x32),
    handlerOrgId: randomUUID(),
    handlerKeyId: new Uint8Array(32).fill(0x33),
    state: "PUBLISHED",
  };
  const entitlement = {
    matterKeyId: key.matterKeyId,
    serial: new Uint8Array(16).fill(0x41),
    personCommitment: scalarToBytes(personHash(1001n)),
  };
  const client = await prepareBlindEntitlement(key.publicKeySpkiDer, entitlement);
  const body = encodeCanonical(
    integerMap([[1, key.matterKeyId], [2, client.blindedMessage]]),
  );
  let durableFact: { subject: string; matterId: string; version: number } | undefined;
  let loadedKey: Uint8Array | undefined;
  let storedResponse: Uint8Array | undefined;
  const identities: BlindIssuanceRepository = {
    async idempotentResponse() {
      return storedResponse;
    },
    async issueBlindEntitlementIdempotent(input, idempotency) {
      durableFact = {
        subject: input.syntheticIdentityRef,
        matterId: input.matterId,
        version: input.matterVersion,
      };
      const signature = await input.sign();
      storedResponse = idempotency.encodeResponse(signature);
      return {
        value: signature,
        responseCbor: storedResponse,
        replayed: false,
      };
    },
  };
  let matterReads = 0;
  const application = new BlindEntitlementIssuanceApplication(
    identities,
    {
      async publicMatter() {
        matterReads += 1;
        return matter;
      },
      async listPublic() {
        return [matter];
      },
    },
    {
      async load() {
        loadedKey = key.privateKeyPkcs8Der.slice();
        return loadedKey;
      },
    },
    () => new Date("2026-10-01T12:00:00.000Z"),
  );
  const command = {
    syntheticIdentityRef: "synthetic:student-001",
    matterId,
    matterVersion: 1,
    matterKeyId: key.matterKeyId,
    blindedMessage: client.blindedMessage,
  };
  const idempotencyKey = randomUUID();
  const encoded = await application.issueIdempotent(command, idempotencyKey, body);
  const response = decodeBlindIssuanceResponse(encoded);
  const token = await finalizeBlindEntitlement(
    key.publicKeySpkiDer,
    client,
    response.blindSignature,
  );
  assert.equal(await verifyBlindEntitlement(key.publicKeySpkiDer, token), true);
  assert.deepEqual(durableFact, {
    subject: "synthetic:student-001",
    matterId,
    version: 1,
  });
  assert.ok(loadedKey?.every((value) => value === 0));
  matter.state = "CLOSED";
  assert.deepEqual(
    await application.issueIdempotent(command, idempotencyKey, body),
    encoded,
  );
  assert.equal(matterReads, 1, "committed replay must not be rejected after matter close");
});
