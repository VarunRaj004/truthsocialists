import {
  assertExactIntegerKeys,
  bytesToHex,
  decodeCanonical,
  sha256,
  verifyMembershipCheckpoint,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import { emptyLeaf, scalarFromBytes } from "./poseidon.js";
import { MembershipOperationType } from "./service.js";
import { SparseMembershipTree, type MembershipProof } from "./tree.js";

export interface MembershipCheckpointUpdate {
  deltaCbor: Uint8Array;
  signedCheckpointCbor: Uint8Array;
}

export interface AppliedMembershipCheckpoint {
  epoch: bigint;
  root: bigint;
  checkpointHash: Uint8Array;
  publishedAt: bigint;
}

export interface ClientMembershipWitness {
  epoch: bigint;
  root: bigint;
  leaf: bigint;
  proof: MembershipProof;
}

interface DecodedOperation {
  sequence: number;
  type: bigint;
  index: number;
  leaf: bigint;
}

interface DecodedDelta {
  tenantId: Uint8Array;
  epoch: bigint;
  operations: DecodedOperation[];
}

function uint(map: Map<CborKey, CborValue>, key: bigint, name: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint" || value < 0n) throw new TypeError(`${name} must be an unsigned integer`);
  return value;
}

function bytes(map: Map<CborKey, CborValue>, key: bigint, length: number, name: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${name} must be ${length} bytes`);
  }
  return value;
}

function safeIndex(value: bigint): number {
  if (value > 65_535n) throw new RangeError("membership leaf index is outside the depth-16 tree");
  return Number(value);
}

export function decodeMembershipDelta(encoded: Uint8Array): DecodedDelta {
  const decoded = decodeCanonical(encoded);
  assertExactIntegerKeys(decoded, [1n, 2n, 3n, 4n]);
  if (uint(decoded, 1n, "delta version") !== 1n) throw new Error("unsupported membership delta version");
  const tenantId = bytes(decoded, 2n, 16, "delta tenantId");
  const epoch = uint(decoded, 3n, "delta epoch");
  const rawOperations = decoded.get(4n);
  if (!Array.isArray(rawOperations)) throw new TypeError("delta operations must be an array");
  const operations = rawOperations.map((raw, sequence): DecodedOperation => {
    assertExactIntegerKeys(raw, [1n, 2n, 3n, 4n]);
    const encodedSequence = uint(raw, 1n, "operation sequence");
    if (encodedSequence !== BigInt(sequence)) throw new Error("membership delta sequence is not contiguous");
    const type = uint(raw, 2n, "operation type");
    if (type !== MembershipOperationType.Activate && type !== MembershipOperationType.Revoke) {
      throw new Error("membership delta operation type is unsupported");
    }
    const leaf = scalarFromBytes("operation leaf", bytes(raw, 4n, 32, "operation leaf"));
    if (type === MembershipOperationType.Revoke && leaf !== emptyLeaf()) {
      throw new Error("revocation must replace the leaf with the fixed empty value");
    }
    if (type === MembershipOperationType.Activate && leaf === emptyLeaf()) {
      throw new Error("activation cannot install the fixed empty value");
    }
    return {
      sequence,
      type,
      index: safeIndex(uint(raw, 3n, "operation index")),
      leaf,
    };
  });
  if (operations.length === 0) throw new Error("membership delta must contain an update");
  return { tenantId, epoch, operations };
}

export class MembershipCheckpointClient {
  private readonly tenantId: Uint8Array;
  private readonly checkpointPublicKey: Uint8Array;
  private leaves = new Map<number, bigint>();
  private tree = new SparseMembershipTree(16);
  private epoch = 0n;
  private previousCheckpointHash = new Uint8Array(32);
  private lastPublishedAt = 0n;

  constructor(tenantId: Uint8Array, checkpointPublicKey: Uint8Array) {
    if (tenantId.length !== 16) throw new TypeError("tenantId must be 16 bytes");
    if (checkpointPublicKey.length !== 32) throw new TypeError("checkpoint public key must be 32 bytes");
    this.tenantId = tenantId.slice();
    this.checkpointPublicKey = checkpointPublicKey.slice();
  }

  apply(update: MembershipCheckpointUpdate): AppliedMembershipCheckpoint {
    const body = verifyMembershipCheckpoint(update.signedCheckpointCbor, this.checkpointPublicKey, {
      previousCheckpointHash: this.previousCheckpointHash,
      minimumEpoch: this.epoch + 1n,
    });
    if (body.epoch !== this.epoch + 1n) throw new Error("membership checkpoint epoch is not contiguous");
    if (body.publishedAt < this.lastPublishedAt) {
      throw new Error("membership checkpoint publication time moved backwards");
    }
    if (bytesToHex(body.updateBatchHash) !== bytesToHex(sha256(update.deltaCbor))) {
      throw new Error("membership checkpoint does not bind the supplied delta");
    }
    const delta = decodeMembershipDelta(update.deltaCbor);
    if (bytesToHex(delta.tenantId) !== bytesToHex(this.tenantId)) {
      throw new Error("membership delta belongs to another tenant");
    }
    if (delta.epoch !== body.epoch) throw new Error("membership delta epoch does not match checkpoint");

    const nextLeaves = new Map(this.leaves);
    const nextTree = new SparseMembershipTree(16);
    for (const [index, leaf] of nextLeaves) nextTree.setLeaf(index, leaf);
    for (const operation of delta.operations) {
      nextTree.setLeaf(operation.index, operation.leaf);
      if (operation.leaf === emptyLeaf()) nextLeaves.delete(operation.index);
      else nextLeaves.set(operation.index, operation.leaf);
    }
    const checkpointRoot = scalarFromBytes("checkpoint root", body.root);
    if (nextTree.root !== checkpointRoot) {
      throw new Error("membership delta does not reproduce the signed checkpoint root");
    }

    const checkpointHash = sha256(update.signedCheckpointCbor);
    this.leaves = nextLeaves;
    this.tree = nextTree;
    this.epoch = body.epoch;
    this.previousCheckpointHash = checkpointHash.slice();
    this.lastPublishedAt = body.publishedAt;
    return {
      epoch: this.epoch,
      root: this.tree.root,
      checkpointHash: checkpointHash.slice(),
      publishedAt: this.lastPublishedAt,
    };
  }

  applyChain(updates: readonly MembershipCheckpointUpdate[]): AppliedMembershipCheckpoint[] {
    return updates.map((update) => this.apply(update));
  }

  witness(index: number): ClientMembershipWitness {
    const leaf = this.leaves.get(index);
    if (leaf === undefined) throw new Error("membership leaf is not active at the current checkpoint");
    return {
      epoch: this.epoch,
      root: this.tree.root,
      leaf,
      proof: this.tree.proof(index),
    };
  }

  current(): AppliedMembershipCheckpoint {
    return {
      epoch: this.epoch,
      root: this.tree.root,
      checkpointHash: this.previousCheckpointHash.slice(),
      publishedAt: this.lastPublishedAt,
    };
  }

  verifyWitness(witness: ClientMembershipWitness): boolean {
    return (
      witness.epoch === this.epoch &&
      witness.root === this.tree.root &&
      this.leaves.get(witness.proof.index) === witness.leaf &&
      this.tree.verify(witness.leaf, witness.proof, witness.root)
    );
  }
}
