# Guided System Demonstration

## Purpose

This walkthrough demonstrates the implemented security boundaries with synthetic data. The command runs real tests against the code; it is not a prerecorded or mocked success screen.

## Before presenting

From the repository root, install dependencies with `pnpm install --frozen-lockfile`. For the most complete local run, start Docker Desktop and then the disposable PostgreSQL service:

```powershell
docker compose -f infra/compose/docker-compose.test.yml up -d --wait
$env:TEST_DATABASE_URL = "postgresql://truthsocialists:local-integration-only@127.0.0.1:55432/truthsocialists_test"
```

Without Docker, the demo still runs all cryptographic and in-memory workflow checks and clearly reports the skipped database cases. GitHub Actions always supplies PostgreSQL.

## Run the demonstration

```powershell
pnpm demo:guided
```

Allow approximately three to five minutes on a typical laptop. The circuit phase compiles the frozen complaint and voting circuits instead of trusting previously generated output.

## Presenter narrative

1. **Enrollment:** an identified institutional session creates an anonymous membership commitment. The identity authority stores eligibility but never receives a later complaint.
2. **Lost phone:** the user proves possession of the pre-shared recovery secret, the old leaf is replaced with a permanent empty value, and a new device receives a never-reused leaf index.
3. **Entitlement:** the authority blind-signs an RSA-3072 complaint entitlement for an eligible user. It cannot see the final serial, commitment, or signature that will later be spent.
4. **Private proof:** the client creates a Semaphore-style Groth16 proof that the same hidden person commitment is in the current active-membership root. The proof exposes neither identity nor tree position.
5. **Submission:** the complaint and attachments are encrypted on the client. The server checks the blind entitlement first, then the current-root proof, and atomically records the encrypted complaint, spends the serial/nullifier, consumes the proof session, and signs a randomized receipt.
6. **Verification:** the receipt is committed into an append-only transparency log. Anyone can verify inclusion, consistency, and a two-of-three witness quorum without learning the complainant.
7. **Handling:** only assigned staff who complete WebAuthn may unwrap the complaint key. The anonymous mailbox permits follow-up without exposing an account identity.
8. **Community review:** only an approved redacted derivative is public. Eligible anonymous members vote once, and the auditor compares the quorum result with the handler’s outcome. A conflict can freeze the public listing but cannot delete or close the private case.
9. **SaaS boundary:** tenant selection occurs before database access. Identity, complaint, handler, and public data use separate routes, while health responses never expose credentials or sensitive identifiers.

## What to show on screen

- The final `DEMO RESULT: PASS` summary.
- The public runtime configuration at `/public/v1/config` when the MVP Compose stack is running.
- The readiness response at `/health/ready`, which lists only safe trust-zone states.
- The successful GitHub Actions run as independent evidence that PostgreSQL integration tests executed.

## Honest limitations

The deployment runtime includes a browser-based synthetic presentation interface for complaint submission, receipt review, handler decisions, community voting, and auditor comparison. Its workflow state is held in memory and resets when the runtime restarts; it is not a production student app or staff portal, and the browser does not yet perform the cryptographic operations that are verified by the protocol test suites. Do not enter real NICs, personal data, or real complaints. External reviews and operational drills are required before any pilot.
