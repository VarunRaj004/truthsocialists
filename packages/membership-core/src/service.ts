import {
  assertBytesLength,
  bytesToHex,
  encodeCanonical,
  integerMap,
  keyIdFromSpkiDer,
  ed25519SpkiFromRaw,
  membershipCheckpointBody,
  sha256,
  signedObject,
  signingInput,
  verifyEd25519Raw,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import { emptyLeaf, memberLeaf, scalarFromBytes, scalarToBytes } from "./poseidon.js";
import { SparseMembershipTree, type MembershipProof } from "./tree.js";

export const MembershipOperationType = {
  Activate: 1n,
  Revoke: 2n,
} as const;

export interface TenantScope {
  tenantId: Uint8Array;
  tenantSlug: string;
}

export interface CheckpointSigner {
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface EnrollmentInput {
  enrollmentId: string;
  syntheticIdentityRef: string;
  personAnchor: Uint8Array;
  deviceHash: Uint8Array;
  recoveryId: Uint8Array;
  recoveryPublicKey: Uint8Array;
}

export interface EnrollmentRecord {
  readonly enrollmentId: string;
  readonly syntheticIdentityRef: string;
  readonly personAnchor: bigint;
  deviceHash: bigint;
  leafIndex: number;
  recoveryId: Uint8Array;
  recoveryPublicKey: Uint8Array;
  recoveryGeneration: number;
  active: boolean;
  updatedEpoch?: bigint;
}

interface PendingOperation {
  type: bigint;
  index: number;
  leaf: bigint;
}

export interface MembershipWitness {
  tenantId: Uint8Array;
  epoch: bigint;
  root: bigint;
  leaf: bigint;
  proof: MembershipProof;
}

export interface PublishedCheckpoint {
  tenantId: Uint8Array;
  epoch: bigint;
  root: bigint;
  deltaCbor: Uint8Array;
  signedCheckpointCbor: Uint8Array;
  checkpointHash: Uint8Array;
}

export interface VerifiedRecoveryRotationInput {
  enrollmentId: string;
  expectedRecoveryGeneration: number;
  newDeviceHash: Uint8Array;
  newRecoveryId: Uint8Array;
  newRecoveryPublicKey: Uint8Array;
}

function cloneBytes(value: Uint8Array): Uint8Array {
  return value.slice();
}

function validateScope(scope: TenantScope): TenantScope {
  assertBytesLength("tenantId", scope.tenantId, 16);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(scope.tenantSlug)) {
    throw new TypeError("tenantSlug must be a lowercase DNS-style label");
  }
  return { tenantId: cloneBytes(scope.tenantId), tenantSlug: scope.tenantSlug };
}

export class TenantMembershipService {
  private readonly tenantScope: TenantScope;
  private readonly tree: SparseMembershipTree;
  private readonly signingKeyId: Uint8Array;
  private readonly checkpointPublicKey: Uint8Array;
  private readonly signer: CheckpointSigner;
  private readonly enrollments = new Map<string, EnrollmentRecord>();
  private readonly identities = new Set<string>();
  private readonly recoveryIds = new Map<string, string>();
  private readonly pending: PendingOperation[] = [];
  private nextLeafIndex = 0;
  private epoch = 0n;
  private previousCheckpointHash: Uint8Array = new Uint8Array(32);
  private currentCheckpoint?: PublishedCheckpoint;

  constructor(scope: TenantScope, signer: CheckpointSigner, depth = 16) {
    this.tenantScope = validateScope(scope);
    assertBytesLength("checkpoint Ed25519 public key", signer.publicKey, 32);
    this.signer = signer;
    this.checkpointPublicKey = cloneBytes(signer.publicKey);
    this.signingKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(this.checkpointPublicKey));
    this.tree = new SparseMembershipTree(depth);
  }

  enroll(input: EnrollmentInput): EnrollmentRecord {
    if (!input.syntheticIdentityRef.startsWith("synthetic:")) {
      throw new TypeError("prototype enrollment accepts synthetic identities only");
    }
    if (this.enrollments.has(input.enrollmentId)) throw new Error("enrollment ID already exists");
    if (this.identities.has(input.syntheticIdentityRef)) throw new Error("synthetic identity already enrolled");
    const recoveryKey = bytesToHex(assertBytesLength("recoveryId", input.recoveryId, 16));
    if (this.recoveryIds.has(recoveryKey)) throw new Error("recovery ID already exists");
    if (this.nextLeafIndex >= this.tree.capacity) throw new Error("membership tree is full");
    const anchor = scalarFromBytes("personAnchor", input.personAnchor);
    const device = scalarFromBytes("deviceHash", input.deviceHash);
    assertBytesLength("recoveryPublicKey", input.recoveryPublicKey, 32);
    const index = this.nextLeafIndex;
    const leaf = memberLeaf(anchor, device);
    const record: EnrollmentRecord = {
      enrollmentId: input.enrollmentId,
      syntheticIdentityRef: input.syntheticIdentityRef,
      personAnchor: anchor,
      deviceHash: device,
      leafIndex: index,
      recoveryId: cloneBytes(input.recoveryId),
      recoveryPublicKey: cloneBytes(input.recoveryPublicKey),
      recoveryGeneration: 1,
      active: true,
    };
    this.tree.setLeaf(index, leaf);
    this.nextLeafIndex += 1;
    this.enrollments.set(input.enrollmentId, record);
    this.identities.add(input.syntheticIdentityRef);
    this.recoveryIds.set(recoveryKey, input.enrollmentId);
    this.pending.push({ type: MembershipOperationType.Activate, index, leaf });
    return this.cloneRecord(record);
  }

  revoke(enrollmentId: string): void {
    const record = this.requireActive(enrollmentId);
    this.tree.setLeaf(record.leafIndex, emptyLeaf());
    record.active = false;
    this.pending.push({
      type: MembershipOperationType.Revoke,
      index: record.leafIndex,
      leaf: emptyLeaf(),
    });
  }

  rotateAfterVerifiedRecovery(input: VerifiedRecoveryRotationInput): EnrollmentRecord {
    const record = this.requireActive(input.enrollmentId);
    if (record.recoveryGeneration !== input.expectedRecoveryGeneration) {
      throw new Error("recovery generation is stale");
    }
    if (this.nextLeafIndex >= this.tree.capacity) throw new Error("membership tree is full");
    const newDevice = scalarFromBytes("newDeviceHash", input.newDeviceHash);
    const newRecoveryId = assertBytesLength("newRecoveryId", input.newRecoveryId, 16);
    const newRecoveryPublicKey = assertBytesLength(
      "newRecoveryPublicKey",
      input.newRecoveryPublicKey,
      32,
    );
    const newRecoveryKey = bytesToHex(newRecoveryId);
    if (this.recoveryIds.has(newRecoveryKey)) throw new Error("new recovery ID already exists");

    const oldIndex = record.leafIndex;
    const newIndex = this.nextLeafIndex;
    const newLeaf = memberLeaf(record.personAnchor, newDevice);
    this.tree.setLeaf(oldIndex, emptyLeaf());
    this.tree.setLeaf(newIndex, newLeaf);
    this.nextLeafIndex += 1;
    this.recoveryIds.delete(bytesToHex(record.recoveryId));
    this.recoveryIds.set(newRecoveryKey, record.enrollmentId);
    record.deviceHash = newDevice;
    record.leafIndex = newIndex;
    record.recoveryId = cloneBytes(newRecoveryId);
    record.recoveryPublicKey = cloneBytes(newRecoveryPublicKey);
    record.recoveryGeneration += 1;
    this.pending.push(
      { type: MembershipOperationType.Revoke, index: oldIndex, leaf: emptyLeaf() },
      { type: MembershipOperationType.Activate, index: newIndex, leaf: newLeaf },
    );
    return this.cloneRecord(record);
  }

  witness(enrollmentId: string): MembershipWitness {
    if (this.pending.length !== 0) {
      throw new Error("membership changes must be checkpointed before issuing a current witness");
    }
    const record = this.requireActive(enrollmentId);
    const leaf = memberLeaf(record.personAnchor, record.deviceHash);
    return {
      tenantId: cloneBytes(this.tenantScope.tenantId),
      epoch: this.epoch,
      root: this.tree.root,
      leaf,
      proof: this.tree.proof(record.leafIndex),
    };
  }

  async publishCheckpoint(publishedAt: bigint): Promise<PublishedCheckpoint | undefined> {
    if (this.pending.length === 0) return undefined;
    if (publishedAt < 0n || publishedAt > 0xffff_ffff_ffff_ffffn) {
      throw new RangeError("checkpoint timestamp is outside uint64 range");
    }
    const nextEpoch = this.epoch + 1n;
    const operations = this.pending.map((operation, sequence) =>
      integerMap([
        [1, BigInt(sequence)],
        [2, operation.type],
        [3, BigInt(operation.index)],
        [4, scalarToBytes(operation.leaf)],
      ]),
    );
    const delta = integerMap([
      [1, 1n],
      [2, this.tenantScope.tenantId],
      [3, nextEpoch],
      [4, operations as readonly CborValue[]],
    ]);
    const deltaCbor = encodeCanonical(delta);
    const body = membershipCheckpointBody({
      epoch: nextEpoch,
      root: scalarToBytes(this.tree.root),
      previousCheckpointHash: this.previousCheckpointHash,
      publishedAt,
      updateBatchHash: sha256(deltaCbor),
      signingKeyId: this.signingKeyId,
    });
    const bodyBytes = encodeCanonical(body);
    const checkpointSigningInput = signingInput("membership-checkpoint", bodyBytes);
    const signature = assertBytesLength(
      "checkpoint Ed25519 signature",
      await this.signer.sign(checkpointSigningInput),
      64,
    );
    if (!verifyEd25519Raw(this.checkpointPublicKey, checkpointSigningInput, signature)) {
      throw new Error("checkpoint signer returned a signature from the wrong key");
    }
    const signedCheckpointCbor = encodeCanonical(signedObject(body, signature));
    const checkpointHash = sha256(signedCheckpointCbor);
    const published: PublishedCheckpoint = {
      tenantId: cloneBytes(this.tenantScope.tenantId),
      epoch: nextEpoch,
      root: this.tree.root,
      deltaCbor,
      signedCheckpointCbor,
      checkpointHash,
    };
    this.epoch = nextEpoch;
    this.previousCheckpointHash = cloneBytes(checkpointHash);
    this.currentCheckpoint = this.cloneCheckpoint(published);
    for (const record of this.enrollments.values()) {
      if (this.pending.some((operation) => operation.index === record.leafIndex)) {
        record.updatedEpoch = nextEpoch;
      }
    }
    this.pending.length = 0;
    return this.cloneCheckpoint(published);
  }

  latestCheckpoint(): PublishedCheckpoint | undefined {
    if (this.currentCheckpoint === undefined) return undefined;
    return this.cloneCheckpoint(this.currentCheckpoint);
  }

  enrollment(enrollmentId: string): EnrollmentRecord | undefined {
    const record = this.enrollments.get(enrollmentId);
    return record === undefined ? undefined : this.cloneRecord(record);
  }

  tenant(): TenantScope {
    return { tenantId: cloneBytes(this.tenantScope.tenantId), tenantSlug: this.tenantScope.tenantSlug };
  }

  checkpointKeyId(): Uint8Array {
    return cloneBytes(this.signingKeyId);
  }

  currentRoot(): bigint {
    return this.tree.root;
  }

  verifyWitness(witness: MembershipWitness): boolean {
    if (bytesToHex(witness.tenantId) !== bytesToHex(this.tenantScope.tenantId)) return false;
    if (witness.epoch !== this.epoch || witness.root !== this.tree.root) return false;
    return this.tree.verify(witness.leaf, witness.proof, witness.root);
  }

  private requireActive(enrollmentId: string): EnrollmentRecord {
    const record = this.enrollments.get(enrollmentId);
    if (record === undefined) throw new Error("enrollment does not exist in this tenant");
    if (!record.active) throw new Error("enrollment is not active");
    return record;
  }

  private cloneRecord(record: EnrollmentRecord): EnrollmentRecord {
    const copy: EnrollmentRecord = {
      enrollmentId: record.enrollmentId,
      syntheticIdentityRef: record.syntheticIdentityRef,
      personAnchor: record.personAnchor,
      deviceHash: record.deviceHash,
      leafIndex: record.leafIndex,
      recoveryId: cloneBytes(record.recoveryId),
      recoveryPublicKey: cloneBytes(record.recoveryPublicKey),
      recoveryGeneration: record.recoveryGeneration,
      active: record.active,
    };
    if (record.updatedEpoch !== undefined) copy.updatedEpoch = record.updatedEpoch;
    return copy;
  }

  private cloneCheckpoint(checkpoint: PublishedCheckpoint): PublishedCheckpoint {
    return {
      ...checkpoint,
      tenantId: cloneBytes(checkpoint.tenantId),
      deltaCbor: cloneBytes(checkpoint.deltaCbor),
      signedCheckpointCbor: cloneBytes(checkpoint.signedCheckpointCbor),
      checkpointHash: cloneBytes(checkpoint.checkpointHash),
    };
  }
}

export class MembershipSaasRegistry {
  private readonly tenants = new Map<string, TenantMembershipService>();
  private readonly checkpointKeys = new Set<string>();

  register(service: TenantMembershipService): void {
    const tenantKey = bytesToHex(service.tenant().tenantId);
    const checkpointKey = bytesToHex(service.checkpointKeyId());
    if (this.tenants.has(tenantKey)) throw new Error("tenant membership service already registered");
    if (this.checkpointKeys.has(checkpointKey)) {
      throw new Error("checkpoint signing keys must not be reused across tenants");
    }
    this.tenants.set(tenantKey, service);
    this.checkpointKeys.add(checkpointKey);
  }

  forTenant(tenantId: Uint8Array): TenantMembershipService {
    const service = this.tenants.get(bytesToHex(assertBytesLength("tenantId", tenantId, 16)));
    if (service === undefined) throw new Error("unknown tenant");
    return service;
  }
}
