"""Generate deterministic Cyber Cipher v1 CBOR/hash/signature test vectors.

The private seeds in this file are public test data. Never use them in production.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PREFIX = b"CYBER-CIPHER/v1/"


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative value")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer too large")


def cbor(value: Any) -> bytes:
    if isinstance(value, bool) or value is None or isinstance(value, float):
        raise TypeError("bool, null, and float are outside the v1 profile")
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        value = unicodedata.normalize("NFC", value)
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        encoded = [(cbor(k), cbor(v)) for k, v in value.items()]
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    raise TypeError(f"unsupported type: {type(value)!r}")


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def frame(label: str, *parts: bytes) -> bytes:
    out = PREFIX + label.encode("ascii") + b"\x00"
    for part in parts:
        out += len(part).to_bytes(8, "big") + part
    return out


def hash_to_field(label: str, *parts: bytes) -> tuple[bytes, int]:
    framed = frame(label, *parts)
    return framed, int.from_bytes(sha256(framed), "big") % Q


def domain(label: str) -> int:
    return int.from_bytes(sha256(PREFIX + b"poseidon/" + label.encode("ascii")), "big") % Q


def ed25519(seed: bytes) -> tuple[Ed25519PrivateKey, bytes, bytes]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    spki = sk.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sk, raw, sha256(spki)


def hx(value: bytes) -> str:
    return value.hex()


def main() -> None:
    matter_id = bytes.fromhex("00112233445546778899aabbccddeeff")
    matter_version = 1
    matter_key_id = sha256(b"test-only-rsa-3072-spki")
    serial = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
    person_commitment = (12345678901234567890).to_bytes(32, "big")

    entitlement_message = {
        1: 1,
        2: matter_key_id,
        3: serial,
        4: person_commitment,
    }
    entitlement_bytes = cbor(entitlement_message)

    sanitized_attachment = b"Cyber Cipher test evidence v1\n"
    attachment_hash = sha256(sanitized_attachment)
    manifest = {
        1: 1,
        2: matter_id,
        3: matter_version,
        4: "Broken streetlight near Lake Road.",
        5: [{1: 0, 2: len(sanitized_attachment), 3: "text/plain", 4: "evidence.txt", 5: attachment_hash}],
    }
    manifest_bytes = cbor(manifest)
    salt = bytes(range(0xA0, 0xC0))
    complaint_commitment = sha256(salt + manifest_bytes)

    complaint_id = bytes.fromhex("123e4567e89b42d3a456426614174000")
    log_entry = {
        1: 1,
        2: bytes.fromhex("ffeeddccbbaa49888776655443322110"),
        3: 1,
        4: complaint_id,
        5: matter_id,
        6: matter_version,
        7: complaint_commitment,
        8: 1790294400123,
        9: 2,
    }
    log_entry_bytes = cbor(log_entry)
    log_leaf_hash = sha256(b"\x00" + log_entry_bytes)

    receipt_sk, receipt_pub, receipt_key_id = ed25519(bytes(range(32)))
    receipt_body = {
        1: 1,
        2: bytes.fromhex("0123456789ab4def8123456789abcdef"),
        3: bytes(range(0x40, 0x60)),
        4: complaint_id,
        5: matter_id,
        6: matter_version,
        7: complaint_commitment,
        8: 1790294400123,
        9: log_leaf_hash,
        10: receipt_key_id,
    }
    receipt_body_bytes = cbor(receipt_body)
    receipt_signing_input = PREFIX + b"receipt\x00" + receipt_body_bytes
    receipt_signature = receipt_sk.sign(receipt_signing_input)
    receipt_bytes = cbor({1: receipt_body, 2: receipt_signature})

    checkpoint_sk, checkpoint_pub, checkpoint_key_id = ed25519(bytes(range(32, 64)))
    checkpoint_body = {
        1: 1,
        2: 42,
        3: (987654321).to_bytes(32, "big"),
        4: bytes(32),
        5: 1790294400000,
        6: sha256(b"test update batch 42"),
        7: checkpoint_key_id,
    }
    checkpoint_body_bytes = cbor(checkpoint_body)
    checkpoint_signing_input = PREFIX + b"membership-checkpoint\x00" + checkpoint_body_bytes
    checkpoint_signature = checkpoint_sk.sign(checkpoint_signing_input)
    checkpoint_bytes = cbor({1: checkpoint_body, 2: checkpoint_signature})
    checkpoint_hash = sha256(checkpoint_bytes)

    matter_frame, matter_field = hash_to_field(
        "matter-field", matter_id, matter_version.to_bytes(4, "big")
    )
    serial_frame, serial_field = hash_to_field("serial-field", serial)
    commitment_frame, commitment_field = hash_to_field(
        "commitment-field", complaint_commitment
    )

    artifact_manifest = {
        1: 1,
        2: "complaint-membership",
        3: 1,
        4: 16,
        5: "groth16",
        6: "bn254",
        7: "circom-2.x-pinned-by-build",
        8: {"circomlib": "pinned-test-version"},
        9: sha256(b"source bundle"),
        10: sha256(b"r1cs"),
        11: sha256(b"wasm"),
        12: sha256(b"proving key"),
        13: sha256(b"verification key"),
        14: sha256(b"powers of tau"),
        15: sha256(b"phase two transcript"),
        16: 1790294400000,
    }
    artifact_manifest_bytes = cbor(artifact_manifest)

    labels = [
        "person", "device", "member-leaf", "empty-leaf", "merkle-node",
        "entitlement-person", "complaint-nullifier", "vote-nullifier",
        "vote-message", "matter-field", "serial-field", "complaint-id-field",
        "commitment-field", "challenge-field",
    ]

    vectors = {
        "protocolVersion": 1,
        "bn254ScalarModulus": str(Q),
        "entitlementMessage": {
            "cborHex": hx(entitlement_bytes),
            "sha256Hex": hx(sha256(entitlement_bytes)),
            "matterKeyIdHex": hx(matter_key_id),
            "serialHex": hx(serial),
            "personCommitmentHex": hx(person_commitment),
        },
        "complaintManifest": {
            "cborHex": hx(manifest_bytes),
            "saltHex": hx(salt),
            "attachmentBytesHex": hx(sanitized_attachment),
            "attachmentSha256Hex": hx(attachment_hash),
            "complaintCommitmentHex": hx(complaint_commitment),
        },
        "logEntry": {
            "cborHex": hx(log_entry_bytes),
            "leafHashFormula": "SHA-256(0x00 || cbor)",
            "leafHashHex": hx(log_leaf_hash),
        },
        "receipt": {
            "testPrivateSeedHex": hx(bytes(range(32))),
            "publicKeyRawHex": hx(receipt_pub),
            "receiptKeyIdHex": hx(receipt_key_id),
            "unsignedBodyCborHex": hx(receipt_body_bytes),
            "signingInputHex": hx(receipt_signing_input),
            "signatureHex": hx(receipt_signature),
            "signedReceiptCborHex": hx(receipt_bytes),
        },
        "membershipCheckpoint": {
            "testPrivateSeedHex": hx(bytes(range(32, 64))),
            "publicKeyRawHex": hx(checkpoint_pub),
            "signingKeyIdHex": hx(checkpoint_key_id),
            "unsignedBodyCborHex": hx(checkpoint_body_bytes),
            "signingInputHex": hx(checkpoint_signing_input),
            "signatureHex": hx(checkpoint_signature),
            "signedCheckpointCborHex": hx(checkpoint_bytes),
            "checkpointHashHex": hx(checkpoint_hash),
        },
        "hashToField": {
            "matter": {"frameHex": hx(matter_frame), "decimal": str(matter_field)},
            "serial": {"frameHex": hx(serial_frame), "decimal": str(serial_field)},
            "complaintCommitment": {"frameHex": hx(commitment_frame), "decimal": str(commitment_field)},
        },
        "poseidonDomainConstants": {label: str(domain(label)) for label in labels},
        "artifactManifest": {
            "cborHex": hx(artifact_manifest_bytes),
            "artifactIdHex": hx(sha256(artifact_manifest_bytes)),
        },
        "negativeCases": {
            "nonMinimalUint23Hex": "1817",
            "indefiniteEmptyArrayHex": "9fff",
            "fieldEqualToModulusHex": Q.to_bytes(32, "big").hex(),
            "invalidSerial15BytesHex": bytes(15).hex(),
            "unnormalizedText": "Cafe\u0301",
            "duplicateMapKeyHex": "a201010102",
        },
    }

    output = Path(__file__).with_name("cyber-cipher-v1-vectors.json")
    output.write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
