import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  createInstitutionalSessionToken,
  verifyInstitutionalSessionToken,
  type InstitutionalSessionSigner,
} from "../src/index.js";

function signer(): InstitutionalSessionSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ type: "spki", format: "der" }));
  return {
    publicKey: spki.slice(-32),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(sign(null, message, keys.privateKey));
    },
  };
}

test("institutional session binds subject, tenant, issuer, audience, and lifetime", async () => {
  const sessionSigner = signer();
  const tenantId = new Uint8Array(16).fill(0x11);
  const claims = {
    tenantId,
    sessionId: new Uint8Array(16).fill(0x12),
    syntheticIdentityRef: "synthetic:student-0001",
    issuer: "university-a",
    audience: "cyber-cipher-ida",
    issuedAt: 1_790_294_400_000n,
    expiresAt: 1_790_295_000_000n,
  };
  const token = await createInstitutionalSessionToken(claims, sessionSigner);
  const verified = verifyInstitutionalSessionToken(token, {
    tenantId,
    issuer: claims.issuer,
    audience: claims.audience,
    publicKey: sessionSigner.publicKey,
    now: () => claims.issuedAt + 1n,
  });
  assert.equal(verified.syntheticIdentityRef, claims.syntheticIdentityRef);
  assert.deepEqual(verified.sessionId, claims.sessionId);

  assert.throws(
    () =>
      verifyInstitutionalSessionToken(token, {
        tenantId: new Uint8Array(16).fill(0x21),
        issuer: claims.issuer,
        audience: claims.audience,
        publicKey: sessionSigner.publicKey,
        now: () => claims.issuedAt + 1n,
      }),
    /another tenant/,
  );
  assert.throws(
    () =>
      verifyInstitutionalSessionToken(token, {
        tenantId,
        issuer: claims.issuer,
        audience: "another-service",
        publicKey: sessionSigner.publicKey,
        now: () => claims.issuedAt + 1n,
      }),
    /audience does not match/,
  );
  assert.throws(
    () =>
      verifyInstitutionalSessionToken(token, {
        tenantId,
        issuer: claims.issuer,
        audience: claims.audience,
        publicKey: sessionSigner.publicKey,
        now: () => claims.expiresAt + 1n,
      }),
    /expired/,
  );
});

test("institutional session rejects signature changes and excessive lifetime", async () => {
  const sessionSigner = signer();
  const tenantId = new Uint8Array(16).fill(0x31);
  const issuedAt = 1_790_294_400_000n;
  const claims = {
    tenantId,
    sessionId: new Uint8Array(16).fill(0x32),
    syntheticIdentityRef: "synthetic:student-0002",
    issuer: "university-a",
    audience: "cyber-cipher-ida",
    issuedAt,
    expiresAt: issuedAt + 60_000n,
  };
  const token = await createInstitutionalSessionToken(claims, sessionSigner);
  const encoded = Buffer.from(token.slice("cc1.".length), "base64url");
  encoded[encoded.length - 1] = encoded[encoded.length - 1]! ^ 1;
  const modified = `cc1.${encoded.toString("base64url")}`;
  assert.throws(
    () =>
      verifyInstitutionalSessionToken(modified, {
        tenantId,
        issuer: claims.issuer,
        audience: claims.audience,
        publicKey: sessionSigner.publicKey,
        now: () => issuedAt + 1n,
      }),
    /signature is invalid/,
  );

  await assert.rejects(
    createInstitutionalSessionToken(
      { ...claims, expiresAt: issuedAt + 15n * 60n * 1000n + 1n },
      sessionSigner,
    ),
    /lifetime exceeds fifteen minutes/,
  );
});
