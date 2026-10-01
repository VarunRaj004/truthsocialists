import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { personHash, scalarToBytes } from "@cyber-cipher/membership-core";
import {
  blindSignEntitlement,
  finalizeBlindEntitlement,
  generateMatterRsaKeyMaterial,
  prepareBlindEntitlement,
  verifyBlindEntitlement,
} from "../src/index.js";

test("RFC 9474 randomized blind entitlement completes without exposing the message", async () => {
  const key = generateMatterRsaKeyMaterial();
  const entitlement = {
    matterKeyId: key.matterKeyId,
    serial: new Uint8Array(16).fill(0x21),
    personCommitment: scalarToBytes(personHash(901n)),
  };
  const client = await prepareBlindEntitlement(key.publicKeySpkiDer, entitlement);
  assert.equal(client.messageRandomizer.length, 32);
  assert.equal(client.blindedMessage.length, 384);

  const blindSignature = await blindSignEntitlement(
    key.privateKeyPkcs8Der,
    client.blindedMessage,
  );
  const token = await finalizeBlindEntitlement(key.publicKeySpkiDer, client, blindSignature);
  assert.equal(await verifyBlindEntitlement(key.publicKeySpkiDer, token), true);

  token.entitlement.serial[0] = token.entitlement.serial[0]! ^ 1;
  assert.equal(await verifyBlindEntitlement(key.publicKeySpkiDer, token), false);
});

test("blind signer rejects a cross-profile RSA key", async () => {
  const wrong = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65_537 });
  const pkcs8 = new Uint8Array(wrong.privateKey.export({ format: "der", type: "pkcs8" }));
  await assert.rejects(
    blindSignEntitlement(pkcs8, new Uint8Array(384).fill(1)),
    /RSA-3072/,
  );
});
