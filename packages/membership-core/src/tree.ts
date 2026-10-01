import { BN254_SCALAR_MODULUS } from "@cyber-cipher/protocol-core";
import { emptyLeaf, merkleNode } from "./poseidon.js";

export interface MembershipProof {
  index: number;
  siblings: readonly bigint[];
  pathBits: readonly (0 | 1)[];
}

function assertDepth(depth: number): number {
  if (!Number.isInteger(depth) || depth < 1 || depth > 30) {
    throw new RangeError("tree depth must be an integer between 1 and 30");
  }
  return depth;
}

function assertLeafIndex(index: number, capacity: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= capacity) {
    throw new RangeError(`leaf index must be between 0 and ${capacity - 1}`);
  }
  return index;
}

function assertField(value: bigint): bigint {
  if (value < 0n || value >= BN254_SCALAR_MODULUS) {
    throw new RangeError("tree value is outside the BN254 scalar field");
  }
  return value;
}

export class SparseMembershipTree {
  readonly depth: number;
  readonly capacity: number;
  readonly emptyValues: readonly bigint[];
  private readonly levels: Map<number, bigint>[];

  constructor(depth = 16) {
    this.depth = assertDepth(depth);
    this.capacity = 2 ** this.depth;
    const defaults = [emptyLeaf()];
    for (let level = 0; level < this.depth; level += 1) {
      defaults.push(merkleNode(defaults[level]!, defaults[level]!));
    }
    this.emptyValues = defaults;
    this.levels = Array.from({ length: this.depth + 1 }, () => new Map<number, bigint>());
  }

  get root(): bigint {
    return this.node(this.depth, 0);
  }

  leaf(index: number): bigint {
    return this.node(0, assertLeafIndex(index, this.capacity));
  }

  setLeaf(index: number, value: bigint): void {
    let cursor = assertLeafIndex(index, this.capacity);
    this.store(0, cursor, assertField(value));
    for (let level = 0; level < this.depth; level += 1) {
      const parent = Math.floor(cursor / 2);
      const left = this.node(level, parent * 2);
      const right = this.node(level, parent * 2 + 1);
      this.store(level + 1, parent, merkleNode(left, right));
      cursor = parent;
    }
  }

  proof(index: number): MembershipProof {
    let cursor = assertLeafIndex(index, this.capacity);
    const siblings: bigint[] = [];
    const pathBits: (0 | 1)[] = [];
    for (let level = 0; level < this.depth; level += 1) {
      const bit = (cursor & 1) as 0 | 1;
      pathBits.push(bit);
      siblings.push(this.node(level, bit === 0 ? cursor + 1 : cursor - 1));
      cursor = Math.floor(cursor / 2);
    }
    return { index, siblings, pathBits };
  }

  verify(leaf: bigint, proof: MembershipProof, expectedRoot: bigint): boolean {
    if (proof.siblings.length !== this.depth || proof.pathBits.length !== this.depth) return false;
    if (!Number.isInteger(proof.index) || proof.index < 0 || proof.index >= this.capacity) return false;
    let current = assertField(leaf);
    let cursor = proof.index;
    for (let level = 0; level < this.depth; level += 1) {
      const sibling = assertField(proof.siblings[level]!);
      const bit = proof.pathBits[level];
      if (bit !== 0 && bit !== 1) return false;
      if (bit !== (cursor & 1)) return false;
      current = bit === 0 ? merkleNode(current, sibling) : merkleNode(sibling, current);
      cursor = Math.floor(cursor / 2);
    }
    return current === expectedRoot;
  }

  private node(level: number, index: number): bigint {
    return this.levels[level]!.get(index) ?? this.emptyValues[level]!;
  }

  private store(level: number, index: number, value: bigint): void {
    if (value === this.emptyValues[level]) this.levels[level]!.delete(index);
    else this.levels[level]!.set(index, value);
  }
}
