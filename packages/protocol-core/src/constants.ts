export const PROTOCOL_VERSION = 1n;

export const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const MAX_CBOR_UINT = 0xffff_ffff_ffff_ffffn;
export const MAX_CBOR_DEPTH = 64;
export const MAX_CBOR_COLLECTION_ITEMS = 100_000;

export const PROTOCOL_PREFIX = "CYBER-CIPHER/v1/";

export const POSEIDON_DOMAIN_LABELS = [
  "person",
  "device",
  "member-leaf",
  "empty-leaf",
  "merkle-node",
  "entitlement-person",
  "complaint-nullifier",
  "vote-nullifier",
  "vote-message",
  "matter-field",
  "serial-field",
  "complaint-id-field",
  "commitment-field",
  "challenge-field",
] as const;

export type PoseidonDomainLabel = (typeof POSEIDON_DOMAIN_LABELS)[number];
