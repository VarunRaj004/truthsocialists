# ZK circuits

This package contains the version-1 Groth16/BN254 complaint and community-vote
circuits. The active-membership tree depth is 16 and all Poseidon domain
constants are shared with `protocol-core` and `membership-core`.

## Reproducible toolchain

- Circom `2.2.3`, with official release-binary hashes per supported platform.
- circomlib `2.0.5`.
- snarkjs `0.7.6`.
- pnpm `11.19.0` and Node `24.10.0` in `Dockerfile.toolchain`.
- `--O2 --sanity_check 2` compilation.

Run `pnpm --filter @cyber-cipher/zk-circuits test`. It downloads the matching
Circom binary into the repository's ignored `tmp` directory, validates its
SHA-256 hash, compiles both circuits, enforces `constraints.lock.json`, and runs
constraint and verifier-boundary tests.

`pnpm --filter @cyber-cipher/zk-circuits test:e2e` creates clearly labelled,
single-machine development keys under ignored `tmp`, verifies them, emits
canonical-CBOR development artifact manifests, and generates real Groth16
proofs. It proves one complaint plus all four vote choices and confirms that a
proof cannot be relabelled with another serial. These keys are never eligible
for deployment.

For the experimental MVP, a three-role single-operator ceremony may be packaged
without weakening the production checks. After generating the reserved
`Development-Simulated-A/B/C` transcript, run
`artifacts:publish-simulation complaint` and `artifacts:publish-simulation vote`.
The deterministic bundles are written beneath ignored
`tmp/simulated-zk-artifacts`, carry `productionEligible: false`, and bind the
simulation report, final transcript, R1CS, WASM, proving key, and verification
key. Run `test:simulation-e2e` to generate and mutate real proofs against those
exact bundles. The normal `artifacts:publish` command rejects these contributor
names, so the simulation cannot be promoted accidentally.

## Frozen public signals

Complaint: `membershipRoot`, `epoch`, `matterField`, `serialField`,
`personCommitment`, `complaintNullifier`, `complaintCommitmentField`,
`challengeField`.

Vote: `membershipRoot`, `epoch`, `complaintIdField`, `voteNullifier`,
`voteChoice`, `voteMessageCommitment`, `challengeField`.

Pass-through binding values such as the serial and challenge are compared with
the request by `Groth16Verifier` before the backend verifies the proof. The
verifier accepts only registered content-addressed artifacts and never resolves
a request-provided verification-key URL.

`Groth16ProofGenerator` provides a backend-neutral client boundary. The included
backend uses snarkjs/WASM; Android and iOS applications can supply Rapidsnark
adapters without changing witness construction, public-signal comparison, proof
envelopes, or artifact IDs. Mobile benchmark records require at least five
samples and bind median, p95, and peak resident memory to the exact artifact ID.

## Ceremony state

`ceremony.lock.json` selects the prepared power-14 Semaphore Perpetual Powers of
Tau transcript. Its 16,384-constraint capacity exceeds both locked circuit
counts. Run `pnpm --filter @cyber-cipher/zk-circuits ceremony:verify-phase1` to
download it into ignored local storage, verify its published BLAKE2b-512 digest,
and run the complete snarkjs transcript verification. The successful full replay
is recorded in `phase1-verification.json`; its transcript digest can be checked
against the ignored local `tmp/ceremony/phase1-verification.txt` output.

The circuit-specific phase-two ceremonies are deliberately not marked complete.
Three genuinely independent people must each contribute to both final circuits,
publish their transcript hashes, and delete toxic intermediate material. The
final proving keys, verification keys, artifact manifests, and device benchmarks
can only be published after those contributions. Synthetic contributions from a
single developer do not satisfy this requirement.

The guarded ceremony commands are:

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 init complaint
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 contribute complaint 1 "Contributor name"
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 verify complaint 1
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 beacon complaint <future-public-32-byte-hex> 10
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 export complaint
```

Repeat contribution/verification for indices 2 and 3 and repeat the ceremony
for `vote`. Each contributor must run their step independently, supply private
entropy interactively, return only the resulting key and public attestation,
and securely erase their local input/output after the next contribution is
accepted. Never put ceremony keys in Git; all outputs stay under ignored `tmp`.
Each contributor completes `contributor-attestation.schema.json` for each circuit;
the schema fixes the circuit commit, input/output hashes, toolchain, independence,
private-entropy handling, and destruction statement.
