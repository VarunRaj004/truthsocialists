# Experimental MVP Deployment and Acceptance

## 1. Completion boundary

The experimental Cyber Cipher MVP consists of the versioned protocol core, membership and recovery, blind RSA entitlement, Groth16 proof boundary, encrypted complaint acceptance, transparency log, handler/mailbox workflow, community/auditor workflow, and the tenant-fixed demo runtime in this repository.

“MVP complete” means these boundaries build and pass their automated positive, negative, replay, tenant-isolation, and transaction tests using synthetic data. It does **not** mean production-ready or approved for real identities or complaints. Security-plan gate G9 and the operational portions of G7/G8 remain external pilot gates.

## 2. Local deployment

Requirements: Docker with Compose v2 and at least 4 GB of free memory.

1. Copy `infra/compose/.env.mvp.example` to `infra/compose/.env.mvp`.
2. Replace the password and verify the synthetic tenant values.
3. Run:

   ```powershell
   docker compose --env-file infra/compose/.env.mvp -f infra/compose/docker-compose.mvp.yml up --build -d
   ```

4. Check `http://127.0.0.1:8080/health/ready` and `http://127.0.0.1:8080/public/v1/config`.
5. Stop with `docker compose --env-file infra/compose/.env.mvp -f infra/compose/docker-compose.mvp.yml down`. Add `--volumes` only when intentionally deleting all synthetic demo state.

The Compose profile exposes only the runtime on loopback. Identity, complaint, handler, and public databases have separate persistent volumes and internal networks. The runtime selects the tenant at startup; query parameters, headers, and request bodies cannot change it.

## 3. SaaS adaptation

For a hosted synthetic demonstration, build `infra/docker/Dockerfile.mvp`, terminate TLS in front of the runtime, inject the four database URLs and other `MVP_*` settings from a secret manager, and use a separate stack per tenant. Production mode rejects non-HTTPS public origins and PostgreSQL URLs without `sslmode=require`.

The demo runtime is deliberately not a reverse proxy between the identified IdA and anonymous complaint service. Those trust zones retain separate ingress, credentials, telemetry, and deployment identities in a real environment.

## 4. Automated acceptance command

Run `pnpm acceptance:mvp`. It executes:

- deployment-policy checks for four isolated database routes, internal networks, loopback-only exposure, an unprivileged/read-only runtime, and forbidden privileged/host-network modes;
- strict TypeScript checks for every workspace;
- every package and service suite, including PostgreSQL integration when `TEST_DATABASE_URL` is available;
- cryptographic vectors, negative encodings, membership/recovery, RSA issuance, circuit constraints, atomic complaint intake, transparency proofs, handler/mailbox authorization, and community/auditor behavior;
- runtime checks for synthetic-only configuration, distinct trust-zone routes, immutable tenant selection, safe public configuration, and fail-closed readiness.

The same deployment check, type check, and test suite runs in GitHub Actions on each main-branch push and pull request.

## 5. Acceptance statement

| Scope | Result | Evidence |
|---|---|---|
| G1 protocol conformance | Automated MVP coverage | protocol-core vectors and strict decoder tests |
| G2 cryptographic correctness | Automated prototype coverage | RSA, recovery, HPKE, receipt, log, and circuit suites |
| G3 privacy separation | Automated architecture coverage | tenant/store tests, forbidden-field tests, fixed routing, four database routes |
| G4 transaction integrity | Automated PostgreSQL coverage | fault, replay, idempotency, and rollback tests |
| G5 verifiability | Automated MVP coverage | receipt, inclusion, consistency, witness, gossip, and vote comparison tests |
| G6 authorization | Automated prototype coverage | handler assignment, WebAuthn, audit, mailbox, reviewer, and auditor tests |
| G7 resilience | Partial; pilot work remains | fail-closed readiness and transaction recovery are tested; managed backup/failover drills remain |
| G8 product quality | Partial; client lab remains | protocol client adapters are tested; UI, accessibility, language, and device benchmarks remain |
| G9 external approval | Not started | independent crypto, penetration, privacy, legal, and governance approvals required |

No real-user deployment is permitted based on the automated MVP result alone.
