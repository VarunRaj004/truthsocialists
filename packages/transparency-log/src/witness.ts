import { equalBytes, sha256, verifyTreeHead } from "@cyber-cipher/protocol-core";
import { type Ed25519Signer, type SignedTreeHead, type WitnessSignature, keyIdForRawEd25519, signWitness, verifyWitnessSignature } from "./heads.js";
import { TransparencyTree, verifyConsistency } from "./merkle.js";

export class TransparencyWitness {
  readonly #tree = new TransparencyTree();
  #lastHeadHash = new Uint8Array(32);
  #lastSize = 0;
  #lastRoot = new Uint8Array(32);

  constructor(readonly signer: Ed25519Signer) {}
  get publicKey(): Uint8Array { return this.signer.publicKey.slice(); }

  async observe(
    head: SignedTreeHead,
    logPublicKey: Uint8Array,
    appendedEntries: readonly Uint8Array[],
    consistency: readonly Uint8Array[],
  ): Promise<WitnessSignature> {
    if (this.#lastSize === Number(head.body.treeSize) && equalBytes(this.#lastHeadHash, head.treeHeadHash)) {
      return signWitness(this.signer, head.treeHeadHash);
    }
    const body = verifyTreeHead(head.signedTreeHeadCbor, logPublicKey, {
      previousFinalizedTreeHeadHash: this.#lastHeadHash,
      minimumTreeSize: BigInt(this.#lastSize),
    });
    if (!equalBytes(sha256(head.signedTreeHeadCbor), head.treeHeadHash)) throw new Error("tree-head hash mismatch");
    if (Number(body.treeSize) !== this.#lastSize + appendedEntries.length) throw new Error("witness received an incomplete log suffix");
    if (this.#lastSize > 0 && !verifyConsistency(this.#lastSize, Number(body.treeSize), this.#lastRoot, body.rootHash, consistency)) {
      throw new Error("tree-head consistency proof is invalid");
    }
    for (const entry of appendedEntries) this.#tree.append(entry);
    if (!equalBytes(this.#tree.root(), body.rootHash)) throw new Error("tree-head root does not match supplied entries");
    this.#lastSize = Number(body.treeSize);
    this.#lastRoot = body.rootHash.slice();
    this.#lastHeadHash = head.treeHeadHash.slice();
    return signWitness(this.signer, head.treeHeadHash);
  }
}

export class WitnessQuorum {
  readonly #keys = new Map<string, Uint8Array>();
  constructor(publicKeys: readonly Uint8Array[]) {
    if (publicKeys.length !== 3) throw new Error("the prototype requires exactly three witnesses");
    for (const key of publicKeys) this.#keys.set(Buffer.from(keyIdForRawEd25519(key)).toString("hex"), key.slice());
    if (this.#keys.size !== 3) throw new Error("witness keys must be distinct");
  }

  validSignatures(treeHeadHash: Uint8Array, signatures: readonly WitnessSignature[]): number {
    const accepted = new Set<string>();
    for (const item of signatures) {
      const id = Buffer.from(item.witnessKeyId).toString("hex");
      const key = this.#keys.get(id);
      if (key && verifyWitnessSignature(item, treeHeadHash, key)) accepted.add(id);
    }
    return accepted.size;
  }

  isFinal(treeHeadHash: Uint8Array, signatures: readonly WitnessSignature[]): boolean {
    return this.validSignatures(treeHeadHash, signatures) >= 2;
  }
}

export interface ForkEvidence { treeSize: bigint; firstTreeHeadHash: Uint8Array; conflictingTreeHeadHash: Uint8Array }

export class TreeHeadGossip {
  readonly #heads = new Map<string, Uint8Array>();
  observe(head: SignedTreeHead): ForkEvidence | undefined {
    const key = head.body.treeSize.toString();
    const previous = this.#heads.get(key);
    if (previous && !equalBytes(previous, head.treeHeadHash)) {
      return { treeSize: head.body.treeSize, firstTreeHeadHash: previous.slice(), conflictingTreeHeadHash: head.treeHeadHash.slice() };
    }
    this.#heads.set(key, head.treeHeadHash.slice());
    return undefined;
  }
}
