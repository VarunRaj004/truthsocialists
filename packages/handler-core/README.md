# Handler Core

Phase 7 provides the handler and anonymous follow-up boundary:

- P-256 WebAuthn assertion verification with RP/origin binding, UV/UP flags,
  expiring one-use challenges, and authenticator-counter replay detection;
- least-privilege staff roles, assignment-only case reads, optimistic lifecycle
  transitions, SLA deadlines/extensions, appeals, and non-destructive suppression;
- Ed25519-signed attributable access decisions for both allowed and denied actions;
- handler-key custody that exposes an unwrapped DEK only to an authorized callback,
  zeroes it afterward, and rewraps only that DEK during cross-organization transfer;
- complaint-specific Ed25519/X25519 mailbox keys derived from a random follow-up
  seed, 60-second signed challenges, HPKE messages, monotonic ordering hashes, and
  AES-256-GCM encrypted recovery bundles;
- an append-only, tenant-separated PostgreSQL schema for staff, cases, audit
  events, mailbox public keys, and ciphertext messages.

The prototype exercises real cryptographic verification but does not claim that
software key custody is an HSM, that its callback is an OS evidence sandbox, or
that simulated staff authenticators are production WebAuthn attestation. Those
remain deployment controls for Phase 9.
