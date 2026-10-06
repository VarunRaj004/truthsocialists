import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import test from "node:test";
import {
  concatBytes, generateHpkeX25519KeyPair, sha256, wrapHandlerDek, type HandlerDekContext,
} from "@cyber-cipher/protocol-core";
import {
  AnonymousMailboxService, HandlerKeyVault, HandlerWorkflow, MailboxDirection,
  WebAuthnStaffRegistry, createMailboxSecrets, mailboxHpkePrivateKey, mailboxMessageHash,
  openMailboxMessage, openMailboxRecoveryBundle, sealMailboxMessage, sealMailboxRecoveryBundle,
  signMailboxChallenge, signTransferRecord, verifyAccessEvent, verifyTransferRecord, withAssignedCaseDek, type ActionSigner, type StaffCredential,
} from "../src/index.js";

function actionSigner(): ActionSigner {
  const keys = generateKeyPairSync("ed25519"); const spki = new Uint8Array(keys.publicKey.export({ format: "der", type: "spki" }));
  return { publicKey: spki.slice(-32), sign: (message) => new Uint8Array(sign(null, message, keys.privateKey)) };
}
function staff(id: string, org: string, roles: StaffCredential["roles"]): StaffCredential {
  return { staffId: id, organizationId: org, roles, credentialId: new Uint8Array(16), publicKeySpkiDer: new Uint8Array([1]), signCount: 0 };
}

test("WebAuthn binds staff authentication to challenge, RP, origin, UV, and counter", () => {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const credentialId = new Uint8Array(randomBytes(16)); const staffId = randomUUID();
  const registry = new WebAuthnStaffRegistry("handler.example", "https://handler.example");
  registry.enroll({ staffId, organizationId: randomUUID(), roles: new Set(["HANDLER"]), credentialId,
    publicKeySpkiDer: new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" })), signCount: 0 });
  const challenge = registry.challenge(staffId, 1_000);
  const clientDataJson = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: Buffer.from(challenge).toString("base64url"), origin: "https://handler.example" }));
  const count = new Uint8Array(4); new DataView(count.buffer).setUint32(0, 1);
  const authenticatorData = concatBytes(sha256(new TextEncoder().encode("handler.example")), Uint8Array.of(0x05), count);
  const assertion = { credentialId, clientDataJson, authenticatorData,
    signature: new Uint8Array(sign("sha256", concatBytes(authenticatorData, sha256(clientDataJson)), pair.privateKey)) };
  assert.equal(registry.authenticate(assertion, 1_001).staffId, staffId);
  assert.throws(() => registry.authenticate(assertion, 1_002), /rejected/);
});

test("only assigned staff can open a case and both decisions are signed", async () => {
  const signer = actionSigner(); const workflow = new HandlerWorkflow(signer); const org = randomUUID();
  const supervisor = staff(randomUUID(), org, new Set(["SUPERVISOR"])); const handler = staff(randomUUID(), org, new Set(["HANDLER"])); const outsider = staff(randomUUID(), org, new Set(["HANDLER"]));
  let value = workflow.registerCase({ complaintId: randomUUID(), organizationId: org, ciphertextUri: "sha256://cipher", ciphertextHash: new Uint8Array(32), handlerKeyId: new Uint8Array(32), acceptedAt: 1_000 });
  value = await workflow.transition(supervisor, value.complaintId, "ACKNOWLEDGED", "RECEIVED", value.rowVersion, 2_000);
  value = await workflow.assign(supervisor, value.complaintId, handler.staffId, value.rowVersion, 3_000);
  await assert.rejects(() => workflow.openCase(outsider, value.complaintId, 4_000), /denied/);
  assert.equal((await workflow.openCase(handler, value.complaintId, 5_000)).assignedStaffId, handler.staffId);
  assert.deepEqual(workflow.accessEvents().slice(-2).map((item) => item.decision), ["DENIED", "ALLOWED"]);
  assert.equal(workflow.accessEvents().every((event) => verifyAccessEvent(event, signer.publicKey)), true);
  const deniedEvent = workflow.accessEvents().find((item) => item.decision === "DENIED")!;
  assert.equal(verifyAccessEvent({ ...deniedEvent, decision: "ALLOWED" }, signer.publicKey), false);
  value = await workflow.transition(handler, value.complaintId, "UNDER_REVIEW", "STARTED", value.rowVersion, 6_000);
  value = await workflow.transition(handler, value.complaintId, "RESOLVED", "SUBSTANTIATED", value.rowVersion, 7_000);
  assert.equal(value.appealUntil, 7_000 + 1_209_600_000);
  const suppressed = await workflow.setSuppressed(supervisor, value.complaintId, true, "LEGAL_REVIEW", 8_000);
  assert.equal(suppressed.state, "RESOLVED"); assert.equal(suppressed.publicSuppressed, true);
});

test("cross-organization transfer rewraps only the same DEK", async () => {
  const oldKeys = await generateHpkeX25519KeyPair(); const newKeys = await generateHpkeX25519KeyPair(); const vault = new HandlerKeyVault();
  const oldOrg = randomUUID(); const newOrg = randomUUID(); const oldId = sha256(oldKeys.publicKey); const newId = sha256(newKeys.publicKey);
  vault.register({ organizationId: oldOrg, keyId: oldId, publicKey: oldKeys.publicKey, privateKey: oldKeys.privateKey });
  vault.register({ organizationId: newOrg, keyId: newId, publicKey: newKeys.publicKey });
  const base = { matterId: new Uint8Array(16).fill(1), matterVersion: 1n, complaintId: new Uint8Array(16).fill(2), complaintCommitment: new Uint8Array(32).fill(3) };
  const oldContext: HandlerDekContext = { ...base, handlerKeyId: oldId }; const newContext: HandlerDekContext = { ...base, handlerKeyId: newId };
  const dek = new Uint8Array(randomBytes(32)); const envelope = await wrapHandlerDek(oldKeys.publicKey, dek, oldContext);
  const workflow = new HandlerWorkflow(actionSigner()); const supervisor = staff(randomUUID(), oldOrg, new Set(["SUPERVISOR"])); const assigned = staff(randomUUID(), oldOrg, new Set(["HANDLER"])); const outsider = staff(randomUUID(), oldOrg, new Set(["HANDLER"]));
  let caseValue = workflow.registerCase({ complaintId: randomUUID(), organizationId: oldOrg, ciphertextUri: "sha256://cipher", ciphertextHash: new Uint8Array(32), handlerKeyId: oldId, acceptedAt: 1_000 });
  caseValue = await workflow.transition(supervisor, caseValue.complaintId, "ACKNOWLEDGED", "RECEIVED", caseValue.rowVersion, 2_000);
  caseValue = await workflow.assign(supervisor, caseValue.complaintId, assigned.staffId, caseValue.rowVersion, 3_000);
  await assert.rejects(() => withAssignedCaseDek(workflow, vault, outsider, caseValue.complaintId, envelope, oldContext, async () => true, 4_000), /denied/);
  assert.equal(await withAssignedCaseDek(workflow, vault, assigned, caseValue.complaintId, envelope, oldContext, async (value) => Buffer.from(value).equals(Buffer.from(dek)), 5_000), true);
  const transfer = await vault.rewrap(staff(randomUUID(), oldOrg, new Set(["SUPERVISOR"])), oldId, newId, envelope, oldContext, newContext);
  const opened = await import("@cyber-cipher/protocol-core").then(({ unwrapHandlerDek }) => unwrapHandlerDek(newKeys.privateKey, transfer.newEnvelope, newContext));
  assert.deepEqual(opened, dek);
  const signer = actionSigner();
  const record = await signTransferRecord(signer, { complaintId: randomUUID(), ciphertextHash: new Uint8Array(32).fill(9), actorId: randomUUID(), reasonCode: "JURISDICTION", occurredAt: 1_800_000_000n, transfer });
  assert.equal(verifyTransferRecord(record, signer.publicKey), true);
  assert.equal(verifyTransferRecord({ ...record, reasonCode: "ALTERED" }, signer.publicKey), false);
  await assert.rejects(() => vault.rewrap(staff(randomUUID(), oldOrg, new Set(["HANDLER"])), oldId, newId, envelope, oldContext, newContext), /supervisor/);
});

test("anonymous mailbox authenticates once, encrypts both directions, and detects deletion/reordering", async () => {
  const secrets = createMailboxSecrets(); const service = new AnonymousMailboxService();
  const handler = await generateHpkeX25519KeyPair(); const handlerId = sha256(handler.publicKey); service.register(secrets, handlerId);
  const challenge = service.challenge(secrets.mailboxId, 1_000); const signature = signMailboxChallenge(secrets, challenge);
  const token = service.authenticate(challenge, signature, 1_001);
  assert.throws(() => service.authenticate(challenge, signature, 1_002), /rejected/);
  const first = await sealMailboxMessage({ mailboxId: secrets.mailboxId, messageNumber: 1n, direction: MailboxDirection.UserToHandler, previousMessageHash: new Uint8Array(32), recipientKeyId: handlerId }, handler.publicKey, new TextEncoder().encode("status?"));
  service.postFromUser(token, first, 1_003); assert.equal(new TextDecoder().decode(await openMailboxMessage(first, handler.privateKey)), "status?");
  const mailboxPrivate = mailboxHpkePrivateKey(secrets);
  const second = await sealMailboxMessage({ mailboxId: secrets.mailboxId, messageNumber: 2n, direction: MailboxDirection.HandlerToUser, previousMessageHash: mailboxMessageHash(first), recipientKeyId: sha256(secrets.hpkePublicKey) }, secrets.hpkePublicKey, new TextEncoder().encode("under review"));
  service.postFromHandler(secrets.mailboxId, second); assert.equal(new TextDecoder().decode(await openMailboxMessage(second, mailboxPrivate)), "under review");
  const broken = { ...second, messageNumber: 3n, previousMessageHash: new Uint8Array(32) };
  assert.throws(() => service.postFromHandler(secrets.mailboxId, broken), /chain/);
  mailboxPrivate.fill(0);
});

test("mailbox recovery bundle restores keys and rejects the old recovery seed", () => {
  const secrets = createMailboxSecrets(); const recoverySeed = new Uint8Array(randomBytes(16)); const wrong = new Uint8Array(randomBytes(16));
  const tenantId = new Uint8Array(16).fill(7); const recoveryId = new Uint8Array(16).fill(8);
  const sealed = sealMailboxRecoveryBundle(recoverySeed, tenantId, recoveryId, 1n, secrets);
  const restored = openMailboxRecoveryBundle(recoverySeed, tenantId, recoveryId, 1n, sealed);
  assert.deepEqual(restored.authPublicKey, secrets.authPublicKey); assert.deepEqual(restored.hpkePublicKey, secrets.hpkePublicKey);
  assert.throws(() => openMailboxRecoveryBundle(wrong, tenantId, recoveryId, 1n, sealed));
});
