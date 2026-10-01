# ADR 0010: Signed institutional enrollment sessions

- Status: Accepted for prototype
- Date: 2026-10-01

## Context

Enrollment must receive an identified eligible subject without trusting a
client-supplied identity field or deployment-specific plaintext header. The
adapter must also prevent a session issued for one tenant or service from being
replayed into another.

## Decision

Use a canonical-CBOR bearer token signed with a tenant-configured, dedicated
Ed25519 institutional-session key. The signed body binds version, tenant ID,
random 128-bit session ID, synthetic identity reference, issuer, audience,
issue time, expiry, and the SHA-256 fingerprint of the signing public key.

Tokens use the `cc1.` prefix and unpadded base64url encoding. The verifier
requires canonical encodings, exact fields, matching tenant/issuer/audience/key,
a valid signature, and a currently active lifetime of at most fifteen minutes.
Invalid and absent credentials both produce the same unauthenticated result.

The experimental implementation continues to accept only `synthetic:` subjects.
Production NIC/SSO eligibility verification remains an institutional integration
outside the privacy protocol.

## Consequences

- Enrollment bodies cannot select or override the identified subject.
- Tokens cannot cross tenant or service-audience boundaries.
- The IdA stores no bearer token and emits no authentication failure detail.
- Operators must protect and rotate a dedicated institutional-session key and
  distribute only its public key to the tenant IdA.
