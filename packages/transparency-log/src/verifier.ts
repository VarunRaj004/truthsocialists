import { decodeCanonical, equalBytes, logLeafHash, verifyReceipt, verifyTreeHead, type ReceiptVerificationExpectation } from "@cyber-cipher/protocol-core";
import type { FinalizedTreeHead } from "./heads.js";
import { merkleRoot, verifyInclusion } from "./merkle.js";
import { WitnessQuorum } from "./witness.js";

export interface ReceiptInclusionBundle {
  signedReceiptCbor: Uint8Array;
  leafIndex: number;
  inclusionProof: Uint8Array[];
  treeHead: FinalizedTreeHead;
}

export type PublicVerificationStatus = "FINAL" | "NOT_FINAL" | "INVALID";

export function receiptInclusionStatus(
  bundle: ReceiptInclusionBundle,
  receiptPublicKey: Uint8Array,
  logPublicKey: Uint8Array,
  witnessPublicKeys: readonly Uint8Array[],
  expectedReceipt: ReceiptVerificationExpectation = {},
): PublicVerificationStatus {
  try {
    const receipt = verifyReceipt(bundle.signedReceiptCbor, receiptPublicKey, expectedReceipt);
    const head = verifyTreeHead(bundle.treeHead.signedTreeHeadCbor, logPublicKey);
    if (!equalBytes(head.rootHash, bundle.treeHead.body.rootHash) || head.treeSize !== bundle.treeHead.body.treeSize) return "INVALID";
    if (!verifyInclusion(receipt.logEntryHash, bundle.leafIndex, Number(head.treeSize), bundle.inclusionProof, head.rootHash)) return "INVALID";
    return new WitnessQuorum(witnessPublicKeys).isFinal(bundle.treeHead.treeHeadHash, bundle.treeHead.witnessSignatures)
      ? "FINAL" : "NOT_FINAL";
  } catch { return "INVALID"; }
}

export function verifyReceiptInclusion(
  bundle: ReceiptInclusionBundle,
  receiptPublicKey: Uint8Array,
  logPublicKey: Uint8Array,
  witnessPublicKeys: readonly Uint8Array[],
  expectedReceipt: ReceiptVerificationExpectation = {},
): boolean {
  return receiptInclusionStatus(bundle, receiptPublicKey, logPublicKey, witnessPublicKeys, expectedReceipt) === "FINAL";
}

export function verifyDownloadedLog(
  canonicalEntries: readonly Uint8Array[],
  head: FinalizedTreeHead,
  logPublicKey: Uint8Array,
  witnessPublicKeys: readonly Uint8Array[],
): boolean {
  try {
    for (const entry of canonicalEntries) decodeCanonical(entry);
    const body = verifyTreeHead(head.signedTreeHeadCbor, logPublicKey);
    if (body.treeSize !== BigInt(canonicalEntries.length)) return false;
    if (!equalBytes(merkleRoot(canonicalEntries.map(logLeafHash)), body.rootHash)) return false;
    return new WitnessQuorum(witnessPublicKeys).isFinal(head.treeHeadHash, head.witnessSignatures);
  } catch {
    return false;
  }
}
