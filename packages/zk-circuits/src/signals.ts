import {
  BN254_SCALAR_MODULUS,
  assertBytesLength,
  hashToField,
  poseidonDomain,
  sha256,
  unsignedBigEndian,
} from "@cyber-cipher/protocol-core";
import { poseidon3 } from "poseidon-lite";

export const COMPLAINT_PUBLIC_SIGNAL_NAMES = [
  "membershipRoot",
  "epoch",
  "matterField",
  "serialField",
  "personCommitment",
  "complaintNullifier",
  "complaintCommitmentField",
  "challengeField",
] as const;

export const VOTE_PUBLIC_SIGNAL_NAMES = [
  "membershipRoot",
  "epoch",
  "complaintIdField",
  "voteNullifier",
  "voteChoice",
  "voteMessageCommitment",
  "challengeField",
] as const;

export type ComplaintPublicSignals = readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
export type VotePublicSignals = readonly [bigint, bigint, bigint, bigint, bigint, bigint, bigint];

function scalar(name: string, value: bigint, nonZero = false): bigint {
  if (value < 0n || value >= BN254_SCALAR_MODULUS) throw new RangeError(`${name} is outside BN254`);
  if (nonZero && value === 0n) throw new RangeError(`${name} must be non-zero`);
  return value;
}

function uint(name: string, value: bigint, maximum: bigint): bigint {
  if (value < 0n || value > maximum) throw new RangeError(`${name} is out of range`);
  return value;
}

export function entitlementPersonCommitment(personSecret: bigint, randomness: bigint): bigint {
  return poseidon3([
    poseidonDomain("entitlement-person"),
    scalar("person secret", personSecret, true),
    scalar("entitlement randomness", randomness, true),
  ]);
}

export function complaintNullifier(personSecret: bigint, matterField: bigint): bigint {
  return poseidon3([
    poseidonDomain("complaint-nullifier"),
    scalar("person secret", personSecret, true),
    scalar("matter field", matterField),
  ]);
}

export function voteNullifier(personSecret: bigint, complaintIdField: bigint): bigint {
  return poseidon3([
    poseidonDomain("vote-nullifier"),
    scalar("person secret", personSecret, true),
    scalar("complaint ID field", complaintIdField),
  ]);
}

export function voteMessageCommitment(complaintIdField: bigint, choice: bigint): bigint {
  return poseidon3([
    poseidonDomain("vote-message"),
    scalar("complaint ID field", complaintIdField),
    uint("vote choice", choice, 3n),
  ]);
}

export interface ComplaintSignalInput {
  membershipRoot: bigint;
  epoch: bigint;
  matterId: Uint8Array;
  matterVersion: bigint;
  serial: Uint8Array;
  complaintCommitment: Uint8Array;
  unsignedLeaseCbor: Uint8Array;
  personSecret: bigint;
  entitlementRandomness: bigint;
}

export function complaintPublicSignals(input: ComplaintSignalInput): ComplaintPublicSignals {
  assertBytesLength("matterId", input.matterId, 16);
  assertBytesLength("serial", input.serial, 16);
  assertBytesLength("complaintCommitment", input.complaintCommitment, 32);
  const matterVersion = uint("matter version", input.matterVersion, 0xffff_ffffn);
  if (matterVersion === 0n) throw new RangeError("matter version must be positive");
  const matterField = hashToField(
    "matter-field",
    input.matterId,
    unsignedBigEndian(matterVersion, 4),
  );
  return [
    scalar("membership root", input.membershipRoot),
    uint("epoch", input.epoch, 0xffff_ffff_ffff_ffffn),
    matterField,
    hashToField("serial-field", input.serial),
    entitlementPersonCommitment(input.personSecret, input.entitlementRandomness),
    complaintNullifier(input.personSecret, matterField),
    hashToField("commitment-field", input.complaintCommitment),
    hashToField("challenge-field", sha256(input.unsignedLeaseCbor)),
  ];
}

export interface VoteSignalInput {
  membershipRoot: bigint;
  epoch: bigint;
  complaintId: Uint8Array;
  voteChoice: bigint;
  unsignedLeaseCbor: Uint8Array;
  personSecret: bigint;
}

export function votePublicSignals(input: VoteSignalInput): VotePublicSignals {
  assertBytesLength("complaintId", input.complaintId, 16);
  const complaintField = hashToField("complaint-id-field", input.complaintId);
  const choice = uint("vote choice", input.voteChoice, 3n);
  return [
    scalar("membership root", input.membershipRoot),
    uint("epoch", input.epoch, 0xffff_ffff_ffff_ffffn),
    complaintField,
    voteNullifier(input.personSecret, complaintField),
    choice,
    voteMessageCommitment(complaintField, choice),
    hashToField("challenge-field", sha256(input.unsignedLeaseCbor)),
  ];
}

export function decimalPublicSignals(signals: readonly bigint[]): string[] {
  return signals.map((value, index) => scalar(`public signal ${index}`, value).toString());
}
