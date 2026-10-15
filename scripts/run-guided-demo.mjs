import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";

const steps = [
  {
    title: "Protocol foundation",
    packageName: "@cyber-cipher/protocol-core",
    explanation: "Canonical CBOR, signatures, encryption, HPKE, leases, and negative vectors",
  },
  {
    title: "Private membership and lost-phone recovery",
    packageName: "@cyber-cipher/membership-core",
    explanation: "Anonymous Merkle membership, revocation, fresh device index, and recovery rotation",
  },
  {
    title: "Blind complaint entitlement",
    packageName: "@cyber-cipher/matter-registry",
    explanation: "RSA-3072 blind signing, matter windows, key isolation, and retirement evidence",
  },
  {
    title: "Zero-knowledge membership proof",
    packageName: "@cyber-cipher/zk-circuits",
    explanation: "Complaint/vote Groth16 circuits, frozen inputs, artifact allowlist, and invalid-witness rejection",
  },
  {
    title: "Anonymous encrypted submission",
    packageName: "@cyber-cipher/complaint-intake-service",
    explanation: "Proof session, RSA-before-ZK verification, encrypted object storage, and replay protection",
  },
  {
    title: "Individual and universal verifiability",
    packageName: "@cyber-cipher/transparency-log",
    explanation: "Signed receipts, inclusion/consistency proofs, 2-of-3 witnesses, and fork detection",
  },
  {
    title: "Handler and anonymous mailbox",
    packageName: "@cyber-cipher/handler-core",
    explanation: "WebAuthn staff access, assignment controls, DEK rewrap, and unlinkable follow-up",
  },
  {
    title: "Community voting and auditor action",
    packageName: "@cyber-cipher/community-core",
    explanation: "Opt-in redaction, one-person-one-vote, outcome comparison, freeze, and escalation",
  },
  {
    title: "SaaS deployment boundary",
    packageName: "@cyber-cipher/mvp-demo",
    explanation: "Fixed tenant routing, synthetic-only data, four trust zones, and safe readiness",
  },
];

const started = performance.now();
const results = [];

process.stdout.write("\nCYBER CIPHER — GUIDED EXPERIMENTAL MVP DEMO\n");
process.stdout.write("Real automated protocol checks; synthetic data only.\n");
process.stdout.write("No result from this demo authorizes a real-user deployment.\n\n");

for (const [index, step] of steps.entries()) {
  process.stdout.write(`[${index + 1}/${steps.length}] ${step.title}\n`);
  process.stdout.write(`      ${step.explanation}\n`);
  const stepStarted = performance.now();
  const command = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "pnpm";
  const arguments_ = process.platform === "win32"
    ? ["/d", "/s", "/c", "pnpm", "--filter", step.packageName, "test"]
    : ["--filter", step.packageName, "test"];
  const run = spawnSync(command, arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, CI: "true", FORCE_COLOR: "0", NO_COLOR: "1" },
    timeout: 10 * 60 * 1000,
  });
  const output = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
  const durationSeconds = ((performance.now() - stepStarted) / 1000).toFixed(1);
  const summary = parseNodeTestSummary(output);

  if (run.status !== 0 || run.error !== undefined) {
    process.stdout.write(`      FAIL (${durationSeconds}s)\n\n`);
    process.stderr.write(output);
    if (run.error !== undefined) process.stderr.write(`${run.error.message}\n`);
    process.exitCode = 1;
    break;
  }

  results.push({ ...summary, title: step.title });
  const skipText = summary.skipped > 0 ? `, ${summary.skipped} skipped` : "";
  process.stdout.write(`      PASS — ${summary.passed}/${summary.tests} tests${skipText} (${durationSeconds}s)\n\n`);
}

if (process.exitCode !== 1) {
  const totals = results.reduce(
    (sum, result) => ({
      tests: sum.tests + result.tests,
      passed: sum.passed + result.passed,
      skipped: sum.skipped + result.skipped,
    }),
    { tests: 0, passed: 0, skipped: 0 },
  );
  const durationSeconds = ((performance.now() - started) / 1000).toFixed(1);
  process.stdout.write("DEMO RESULT: PASS\n");
  process.stdout.write(`Verified ${totals.passed}/${totals.tests} tests across ${results.length} system boundaries`);
  if (totals.skipped > 0) process.stdout.write(`; ${totals.skipped} database tests skipped because TEST_DATABASE_URL is not set`);
  process.stdout.write(` (${durationSeconds}s).\n`);
  process.stdout.write("Next production gate: independent cryptographic, penetration, privacy, accessibility, legal, and operational review.\n");
}

function parseNodeTestSummary(output) {
  const matches = [...output.matchAll(/(?:^|\n)(?:ℹ|#)\s+(tests|pass|skipped)\s+(\d+)/g)];
  const summary = { tests: 0, passed: 0, skipped: 0 };
  for (const match of matches) {
    const value = Number(match[2]);
    if (match[1] === "tests") summary.tests += value;
    if (match[1] === "pass") summary.passed += value;
    if (match[1] === "skipped") summary.skipped += value;
  }
  if (summary.tests === 0) throw new Error("test runner did not produce a Node test summary");
  return summary;
}
