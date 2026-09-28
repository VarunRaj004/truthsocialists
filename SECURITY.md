# Security Policy

Cyber Cipher is in prototype development and is not approved for real complaints or identity data.

## Reporting a vulnerability

Do not open a public issue containing an exploit, private key, identity record, complaint, recovery seed, entitlement, proof witness, or other sensitive data. Contact the repository owner privately and include the affected commit, component, impact, and a minimal synthetic reproduction.

## Development rules

- Use synthetic identities and complaint content only.
- Never commit secrets, private keys, production configuration, circuit toxic waste, or database/object-store data.
- Cryptographic primitives must come from reviewed libraries; project code defines protocol framing, validation, and composition only.
- Changes to wire schemas, circuits, domain separation, signature inputs, or key lifecycles require a version change and security review.
- A passing automated scanner is not a substitute for cryptographic, privacy, and authorization review.

See `docs/cyber-cipher/08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md` for release gates.
