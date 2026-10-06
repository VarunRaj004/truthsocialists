import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { PersistProofSessionInput } from "@cyber-cipher/complaint-store";
import {
  encodeCanonical,
  encodeFieldElement,
  integerMap,
  keyIdFromSpkiDer,
  proofLeaseBody,
  signedObject,
  signingInput,
} from "@cyber-cipher/protocol-core";
import {
  blindSignEntitlement,
  finalizeBlindEntitlement,
  generateMatterRsaKeyMaterial,
  prepareBlindEntitlement,
} from "@cyber-cipher/matter-registry";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  Groth16Verifier,
  complaintPublicSignals,
  entitlementPersonCommitment,
} from "@cyber-cipher/zk-circuits";
import {
  ComplaintAuthorizer,
  DurableProofSessionIssuer,
  FileCiphertextObjectStore,
  assertComplaintTransport,
  createComplaintHttpServer,
  decodeComplaintSubmission,
  encodeComplaintSubmission,
  type ComplaintSubmissionWire,
} from "../src/index.js";

test("file object store durably content-addresses and deduplicates ciphertext", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cyber-cipher-objects-"));
  try {
    const store = new FileCiphertextObjectStore(directory);
    const ciphertext = new Uint8Array(64).fill(0xa5);
    const first = await store.put(ciphertext);
    const second = await store.put(ciphertext);
    assert.equal(first.uri, second.uri);
    const key = first.uri.slice("object://sha256/".length);
    assert.deepEqual(new Uint8Array(await readFile(join(directory, key.slice(0, 2), `${key}.bin`))), ciphertext);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("complaint wire round-trips fixed fields and opaque Groth16 proof", () => {
  const value = wireFixture();
  const decoded = decodeComplaintSubmission(encodeComplaintSubmission(value));
  assert.deepEqual(decoded, value);
});

test("authorization verifies RSA entitlement before the allowlisted complaint proof", async () => {
  const rsa = generateMatterRsaKeyMaterial();
  const matterId = uuidBytes("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  const artifactId = new Uint8Array(32).fill(0x33);
  const challengeId = new Uint8Array(16).fill(0x44);
  const membershipRoot = 123n;
  const epoch = 7n;
  const leaseKeys = generateKeyPairSync("ed25519");
  const leasePublic = new Uint8Array(leaseKeys.publicKey.export({ format: "der", type: "spki" })).slice(-32);
  const leaseBody = proofLeaseBody({
    challengeId,
    purpose: 1n,
    epoch,
    membershipRoot: encodeFieldElement(membershipRoot),
    issuedAt: 1_000n,
    expiresAt: 61_000n,
    serverNonce: new Uint8Array(32).fill(0x45),
    signingKeyId: keyIdFromSpkiDer(new Uint8Array(leaseKeys.publicKey.export({ format: "der", type: "spki" }))),
  });
  const unsignedLeaseCbor = encodeCanonical(leaseBody);
  const signedLeaseCbor = encodeCanonical(signedObject(
    leaseBody,
    new Uint8Array(sign(null, signingInput("proof-lease", unsignedLeaseCbor), leaseKeys.privateKey)),
  ));
  const personSecret = 17n;
  const randomness = 19n;
  const serial = new Uint8Array(16).fill(0x46);
  const complaintCommitment = new Uint8Array(32).fill(0x47);
  const entitlement = {
    matterKeyId: rsa.matterKeyId,
    serial,
    personCommitment: encodeFieldElement(entitlementPersonCommitment(personSecret, randomness)),
  };
  const blind = await prepareBlindEntitlement(rsa.publicKeySpkiDer, entitlement);
  const token = await finalizeBlindEntitlement(
    rsa.publicKeySpkiDer,
    blind,
    await blindSignEntitlement(rsa.privateKeyPkcs8Der, blind.blindedMessage),
  );
  const signals = complaintPublicSignals({
    membershipRoot,
    epoch,
    matterId,
    matterVersion: 1n,
    serial,
    complaintCommitment,
    unsignedLeaseCbor,
    personSecret,
    entitlementRandomness: randomness,
  });
  let proofCalls = 0;
  const verifier = new Groth16Verifier({ async verify() { proofCalls += 1; return true; } });
  verifier.register({
    artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignalNames: COMPLAINT_PUBLIC_SIGNAL_NAMES,
    verificationKey: {},
  });
  const authorizer = new ComplaintAuthorizer(leasePublic, verifier);
  const request = {
    complaintId: uuidBytes(randomUUID()),
    matterId,
    matterVersion: 1,
    complaintCommitment,
    challengeId,
    entitlement: token,
    proof: { artifactId, circuitName: "complaint" as const, circuitVersion: 1, publicSignals: signals.map(String), proof: {} },
  };
  const locked = {
    matter: {
      matterId: uuidString(matterId), version: 1, opensAt: new Date(0), closesAt: new Date(100_000),
      matterKeyId: rsa.matterKeyId, rsaSpkiDer: rsa.publicKeySpkiDer, complaintArtifactId: artifactId,
      handlerOrgId: randomUUID(), handlerKeyId: new Uint8Array(32).fill(0x48),
    },
    signedLeaseCbor,
    epoch,
    membershipRoot,
  };
  await authorizer.authorize(locked, request, new Date(2_000));
  assert.equal(proofCalls, 1);
  const invalidSignature = request.entitlement.signature.slice();
  invalidSignature[0] = invalidSignature[0]! ^ 1;
  await assert.rejects(
    authorizer.authorize(locked, {
      ...request,
      entitlement: { ...request.entitlement, signature: invalidSignature },
    }, new Date(2_000)),
    /invalid RSA blind entitlement/,
  );
  assert.equal(proofCalls, 1, "Groth16 must not run after RSA rejection");
  await assert.rejects(
    authorizer.authorize(locked, { ...request, complaintCommitment: new Uint8Array(32).fill(0x99) }, new Date(2_000)),
    /invalid Groth16 complaint proof/,
  );
});

test("durable issuer persists an exact 60-second current-root lease", async () => {
  const keys = generateKeyPairSync("ed25519");
  let persisted: { expiresAt: Date; issuedAt: Date; membershipRoot: bigint } | undefined;
  const issuer = new DurableProofSessionIssuer(
    keys.privateKey,
    { async persistProofSession(input: PersistProofSessionInput) { persisted = input; } } as never,
    { async current() { return { epoch: 9n, root: 456n }; } },
    { bytes(length) { return new Uint8Array(length).fill(length); } },
    () => new Date(10_000),
  );
  const issued = await issuer.issue();
  assert.equal(issued.expiresAt - issued.issuedAt, 60_000n);
  assert.equal(persisted?.membershipRoot, 456n);
  assert.equal(persisted!.expiresAt.getTime() - persisted!.issuedAt.getTime(), 60_000);
});

test("HTTP boundary is anonymous, no-store, idempotent-keyed, and has explicit transport policy", async () => {
  let receivedKey: string | undefined;
  const server = createComplaintHttpServer({
    proofSessions: {
      async issue() {
        return { challengeId: new Uint8Array(16), signedLeaseCbor: new Uint8Array([1]), issuedAt: 1n, expiresAt: 60_001n };
      },
    },
    intake: {
      async submit(key) {
        receivedKey = key;
        return {
          complaintId: randomUUID(), receiptId: new Uint8Array(16), signedReceiptCbor: new Uint8Array([2]),
          logEntryHash: new Uint8Array(32), acceptedAt: new Date(1),
        };
      },
    },
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const port = (server.address() as AddressInfo).port;
    const session = await fetch(`http://127.0.0.1:${port}/complaints/v1/proof-sessions`, { method: "POST" });
    assert.equal(session.status, 201);
    assert.equal(session.headers.get("cache-control"), "no-store");
    const key = randomUUID();
    const accepted = await fetch(`http://127.0.0.1:${port}/complaints/v1/complaints`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "idempotency-key": key },
      body: Buffer.from([0xa0]),
    });
    assert.equal(accepted.status, 201);
    assert.equal(receivedKey, key);
    assert.throws(() => assertComplaintTransport("http://example.test/complaints"), /direct TLS/);
    assert.equal(assertComplaintTransport("https://example.test/complaints").protocol, "https:");
    assert.equal(assertComplaintTransport("http://testonly.onion/complaints", true).hostname, "testonly.onion");
  } finally {
    server.close();
    await once(server, "close");
  }
});

function wireFixture(): ComplaintSubmissionWire {
  return {
    complaintId: uuidBytes(randomUUID()), matterId: uuidBytes(randomUUID()), matterVersion: 1,
    signedLeaseCbor: new Uint8Array([0xa0]),
    entitlement: {
      entitlement: { matterKeyId: new Uint8Array(32).fill(1), serial: new Uint8Array(16).fill(2), personCommitment: new Uint8Array(32) },
      messageRandomizer: new Uint8Array(32).fill(3), signature: new Uint8Array(384).fill(4),
    },
    proof: { artifactId: new Uint8Array(32).fill(5), circuitName: "complaint", circuitVersion: 1, publicSignals: Array(8).fill("0"), proof: { pi_a: ["1"] } },
    complaintCommitment: new Uint8Array(32).fill(6), ciphertext: new Uint8Array(32).fill(7),
    aeadNonce: new Uint8Array(12).fill(8), hpkeEnc: new Uint8Array(32).fill(9), wrappedDek: new Uint8Array(48).fill(10),
    handlerKeyId: new Uint8Array(32).fill(11),
  };
}

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}

function uuidString(value: Uint8Array): string {
  const hex = Buffer.from(value).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
