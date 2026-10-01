# ADR 0012: RFC 9474 blind-entitlement implementation

- Status: Accepted for prototype
- Date: 2026-10-01

## Context

Phase 3 needs interoperable blind signing, client-side final verification, and
a signer that never receives the entitlement serial or person commitment. The
initial parameter-restricted `rsaPSS` DER produced by Node could not be imported
by WebCrypto for the raw RSA operations required by RFC 9474.

## Decision

Pin Apache-2.0 `@cloudflare/blindrsa-ts` 0.4.6 and select only
`RSABSSA-SHA384-PSS-Randomized`. Generate a dedicated generic RSA-3072 key with
exponent 65537 for every matter version. The standalone canonical DER SPKI uses
the RSA algorithm identifier expected by WebCrypto; the application boundary
fixes SHA-384, MGF1-SHA384, 48-byte PSS salt, and 32-byte randomized message
preparation. Keys are never shared with another protocol or suite.

The client canonicalizes the entitlement, prepares and blinds it locally, and
sends only a 384-byte representative. The IdA checks an identified enrollment,
public matter state, version, and full SPKI fingerprint before atomically
creating the minimal issuance fact and blind-signing. An idempotent replay
returns the original response bytes. The client finalizes and verifies locally.

## Consequences

- The IdA database cannot correlate a later unblinded token using stored blind
  protocol values because none are retained.
- A second issuance under another idempotency key is rejected by the database
  uniqueness constraint.
- The decrypted PKCS#8 buffer is overwritten after every signing attempt.
- Matter private keys are destroyed after close; retirement is published only
  with a 32-byte evidence digest.
- An X.509 deployment must follow RFC 9474's certificate-specific RSASSA-PSS
  algorithm-identifier requirement even though this prototype publishes a
  standalone SPKI.
