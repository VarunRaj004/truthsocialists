# Contributing

## Local prerequisites

- Node.js 22 or newer
- pnpm 11.19.0
- Python with `cryptography` only when regenerating the reference vectors

## Initial checks

```text
pnpm install
pnpm check
pnpm test
```

## Protocol changes

Before changing any signed or hashed structure:

1. Update the normative specification and CDDL.
2. Decide whether the protocol or circuit version must change.
3. Update the deterministic vector generator and checked-in vectors.
4. Add positive and negative cross-language tests.
5. Record the decision and obtain security review.

Do not add permissive parsing for unknown fields, noncanonical CBOR, malformed field elements, or untrusted verification-key locations.
