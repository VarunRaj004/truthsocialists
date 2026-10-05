# Phase 4 operator checklist

Status: experimental MVP simulation complete; independent production ceremony
and physical-device evidence pending.

The MVP simulation produces deterministic non-production complaint and vote
artifact bundles and passes real-proof/mutation tests against the resulting
keys. Reserved `Development-Simulated-*` identities are rejected by the
production publisher. This evidence validates the workflow only; it does not
claim contributor independence or replace the remaining production gates below.

This checklist separates automated controls from facts that require independent
people or real hardware. Do not substitute development keys for any ceremony
step. Nothing under `tmp/zk-development-keys` is production eligible.

## 1. Actions required from the project owner

1. Select three genuinely independent contributors. They may use public
   pseudonyms, but the project owner must retain evidence that they are distinct
   people and did not share ceremony entropy.
2. Give each contributor a separate machine or environment and the exact Git
   commit containing the final circuits. Freeze circuit changes before starting.
3. Arrange temporary secure transfer for each resulting `.zkey`. Do not use the
   Git repository for proving keys, contributor entropy, or ceremony working files.
4. After contribution 3 is accepted, publish a UTC not-before time for the final
   randomness beacon. It must be in the future when announced.
5. Provide one representative arm64 Android phone and one arm64 iPhone for
   proving-time and peak-memory measurements.
6. Approve where final public artifacts will be hosted. The repository should
   contain hashes and manifests, not large proving keys.

## 2. Phase 1 verification

Run on a machine that can remain active for the complete cryptographic replay:

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:verify-phase1
```

Expected pinned file hashes are in `packages/zk-circuits/ceremony.lock.json`.
Archive the successful snarkjs output. A matching file digest alone does not
replace the complete transcript replay.

## 3. Phase 2 ceremony

Compile and initialize each circuit:

```text
pnpm --filter @cyber-cipher/zk-circuits circuits:compile
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 init complaint
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 init vote
```

For each circuit, contributor 1 runs contribution index 1, contributor 2 runs
index 2, and contributor 3 runs index 3. Entropy is entered interactively and
must never be sent to the project owner or stored in chat, source control, shell
history, screenshots, or shared logs.

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 contribute complaint 1 "Contributor-1"
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 verify complaint 1
```

Repeat with indices 2 and 3, then repeat all three for `vote`. The contributor
names must be distinct and must not contain `test`, `development`, or `insecure`.
Each contributor records the received-input hash, produced-output hash, command
version, UTC time, and a statement that entropy was independently generated and
destroyed after the next contribution was accepted.

## 4. Final public beacon

Recommended prototype procedure:

1. After contribution 3 is verified, publish a future UTC timestamp.
2. After that time, download and archive the corresponding signed NIST Randomness
   Beacon v2 pulse JSON.
3. Derive the 32-byte beacon input from its 512-bit `outputValue`:

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:derive-beacon pulse.json 2026-10-10T12:00:00.000Z
```

4. Independently verify the archived pulse URI/signature, publish the pulse JSON
   and derivation record, and apply the returned 64-hex-character beacon to both
   circuits:

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 beacon complaint <beacon-hex> 10
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 beacon vote <beacon-hex> 10
```

The timestamp above is only an example. Do not reuse it unless it is still in the
future at the time the commitment is publicly made.

## 5. Final artifacts

Verify and export each final key:

```text
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 export complaint
pnpm --filter @cyber-cipher/zk-circuits ceremony:phase2 export vote
```

Publish deterministic artifact bundles using one explicitly recorded build time:

```text
pnpm --filter @cyber-cipher/zk-circuits artifacts:publish complaint <unix-seconds>
pnpm --filter @cyber-cipher/zk-circuits artifacts:publish vote <unix-seconds>
```

Publication fails unless snarkjs reports a valid final key, contributions 1-3
have distinct production names, and contribution 4 is the declared public
beacon. Outputs remain under ignored `tmp/published-zk-artifacts` until uploaded
to the approved artifact host.

## 6. Mobile acceptance evidence

For both complaint and vote artifacts, collect at least five proof samples per
device after one warm-up run. Record:

- exact artifact ID;
- device model, OS version, architecture and Rapidsnark wrapper version;
- every proving duration;
- peak resident memory;
- proof verification result against the published verification key.

No emulator-only result satisfies the Phase 4 exit gate. The final supported
device baseline must be chosen only after measurements are available.

## 7. Completion evidence

Phase 4 is complete only when the repository or approved artifact host contains:

- successful full Phase 1 verification output;
- two final Phase 2 verification transcripts;
- three contributor attestations per circuit;
- the archived future-beacon source and derivation;
- final R1CS, WASM/native prover assets, proving and verification keys;
- canonical-CBOR manifests and artifact IDs;
- Android and iOS benchmark records;
- passing complaint/vote proof and mutation tests against the final keys.
