import { type Ed25519Signer, type FinalizedTreeHead, type SignedTreeHead, type WitnessSignature, signTreeHead } from "./heads.js";
import { TransparencyTree } from "./merkle.js";
import { TransparencyWitness, WitnessQuorum } from "./witness.js";

export class TransparencyLogOperator {
  readonly #tree = new TransparencyTree();
  #lastPublishedSize = 0;
  #previousFinalizedHash = new Uint8Array(32);
  #pending: { head: SignedTreeHead; suffix: Uint8Array[]; consistency: Uint8Array[]; signatures: Map<string, WitnessSignature> } | undefined;

  constructor(readonly signer: Ed25519Signer, readonly witnesses: readonly TransparencyWitness[]) {
    if (witnesses.length !== 3) throw new Error("the prototype requires exactly three witnesses");
  }

  append(canonicalEntryCbor: Uint8Array): number {
    if (this.#pending) throw new Error("a non-final tree head must be resolved before appending");
    return this.#tree.append(canonicalEntryCbor);
  }
  get size(): number { return this.#tree.size; }
  entry(index: number): Uint8Array { return this.#tree.entry(index); }
  inclusion(index: number): Uint8Array[] { return this.#tree.inclusion(index); }

  async publish(timestamp: bigint, availableWitnesses: readonly number[] = [0, 1, 2]): Promise<FinalizedTreeHead> {
    if (this.#tree.size === 0) throw new Error("cannot publish an empty transparency log");
    if (!this.#pending && this.#tree.size === this.#lastPublishedSize) throw new Error("no new log entries to publish");
    if (!this.#pending) {
      const head = await signTreeHead(this.signer, {
        treeSize: BigInt(this.#tree.size), rootHash: this.#tree.root(), timestamp,
        previousFinalizedTreeHeadHash: this.#previousFinalizedHash,
      });
      this.#pending = {
        head,
        suffix: this.#tree.entries(this.#lastPublishedSize),
        consistency: this.#lastPublishedSize === 0 ? [] : this.#tree.consistency(this.#lastPublishedSize),
        signatures: new Map(),
      };
    }
    const pending = this.#pending;
    for (const index of new Set(availableWitnesses)) {
      const witness = this.witnesses[index];
      if (witness) {
        try {
          const signature = await witness.observe(pending.head, this.signer.publicKey, pending.suffix, pending.consistency);
          pending.signatures.set(Buffer.from(signature.witnessKeyId).toString("hex"), signature);
        } catch {
          // A stale, unavailable, or disagreeing witness contributes no signature.
          // Finality remains an explicit quorum result rather than an exception.
        }
      }
    }
    const signatures = [...pending.signatures.values()];
    const quorum = new WitnessQuorum(this.witnesses.map((item) => item.publicKey));
    const final = quorum.isFinal(pending.head.treeHeadHash, signatures);
    const result: FinalizedTreeHead = { ...pending.head, witnessSignatures: signatures, final };
    if (final) {
      this.#lastPublishedSize = this.#tree.size;
      this.#previousFinalizedHash = pending.head.treeHeadHash.slice();
      this.#pending = undefined;
    }
    return result;
  }
}
