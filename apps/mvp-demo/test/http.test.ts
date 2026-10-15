import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { loadMvpRuntimeConfig } from "../src/config.js";
import { createMvpHttpServer } from "../src/http.js";

const runtime = loadMvpRuntimeConfig({
  MVP_DEPLOYMENT_MODE: "development",
  MVP_DATA_CLASSIFICATION: "synthetic",
  MVP_TENANT_ID: "9d4b63ce-7e24-45cf-9ec4-0d3c7839dcaf",
  MVP_TENANT_SLUG: "demo-university",
  MVP_PUBLIC_ORIGIN: "http://127.0.0.1:8080",
  MVP_IDENTITY_DATABASE_URL: "postgresql://user:identity-secret@identity-db/identity",
  MVP_COMPLAINT_DATABASE_URL: "postgresql://user:complaint-secret@complaint-db/complaint",
  MVP_HANDLER_DATABASE_URL: "postgresql://user:handler-secret@handler-db/handler",
  MVP_PUBLIC_DATABASE_URL: "postgresql://user:public-secret@public-db/public",
});

async function withServer(
  probe: Parameters<typeof createMvpHttpServer>[0]["probe"],
  run: (origin: string) => Promise<void>,
): Promise<void> {
  const server = createMvpHttpServer({ runtime, probe });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
  }
}

test("exposes liveness and a safe public tenant profile", async () => {
  await withServer(async () => undefined, async (origin) => {
    const live = await fetch(`${origin}/health/live`);
    assert.equal(live.status, 200);
    assert.deepEqual(await live.json(), { live: true });

    const response = await fetch(`${origin}/public/v1/config`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    const body = await response.text();
    assert.match(body, /demo-university/);
    assert.doesNotMatch(body, /secret|database/i);
  });
});

test("readiness fails closed without leaking dependency details", async () => {
  await withServer(async (zone) => {
    if (zone === "handler") throw new Error("postgresql://user:leaked-secret@handler-db/handler");
  }, async (origin) => {
    const response = await fetch(`${origin}/health/ready`);
    assert.equal(response.status, 503);
    const body = await response.text();
    assert.match(body, /\"handler\":\"unavailable\"/);
    assert.doesNotMatch(body, /leaked-secret|postgresql:/);
  });
});

test("does not accept a request-selected tenant", async () => {
  await withServer(async () => undefined, async (origin) => {
    const response = await fetch(`${origin}/public/v1/config?tenantId=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`, {
      headers: { "x-tenant-id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
    });
    const body = await response.json() as { tenantId: string };
    assert.equal(body.tenantId, runtime.tenantId);
  });
});

test("serves the synthetic presentation interface with restrictive browser headers", async () => {
  await withServer(async () => undefined, async (origin) => {
    const page = await fetch(`${origin}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-type") ?? "", /text\/html/);
    assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    const html = await page.text();
    assert.match(html, /Synthetic presentation mode|Presentation mode/);
    assert.match(html, /Submit an encrypted complaint/);

    const script = await fetch(`${origin}/assets/app.js`);
    assert.equal(script.status, 200);
    assert.match(script.headers.get("content-type") ?? "", /javascript/);
  });
});

test("runs the synthetic complaint-to-auditor presentation workflow", async () => {
  await withServer(async () => undefined, async (origin) => {
    async function post(path: string, body?: unknown): Promise<Response> {
      return fetch(`${origin}${path}`, {
        method: "POST",
        ...(body === undefined ? {} : {
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      });
    }

    const submitted = await post("/demo/v1/complaints", {
      matter: "Synthetic student service",
      summary: "A fictional request was not processed within the demonstration time limit.",
      evidenceCount: 2,
    });
    assert.equal(submitted.status, 201);
    const submittedState = await submitted.json() as { activeCase: { receiptId: string; handlerOutcome: string } };
    assert.equal(submittedState.activeCase.receiptId.length, 32);
    assert.equal(submittedState.activeCase.handlerOutcome, "PENDING");

    const decision = await post("/demo/v1/handler-decision", { outcome: "UNSUBSTANTIATED" });
    assert.equal(decision.status, 200);
    const reviewed = await post("/demo/v1/publication-review", { approve: true });
    assert.equal(reviewed.status, 200);

    for (let index = 0; index < 3; index += 1) {
      const vote = await post("/demo/v1/votes", { choice: "SUPPORT" });
      assert.equal(vote.status, 200);
    }
    const audit = await post("/demo/v1/audit");
    assert.equal(audit.status, 200);
    const finalState = await audit.json() as { activeCase: { auditOutcome: string; auditEventId: string } };
    assert.equal(finalState.activeCase.auditOutcome, "CONFLICTING");
    assert.match(finalState.activeCase.auditEventId, /^[0-9a-f-]{36}$/);

    const duplicateDecision = await post("/demo/v1/handler-decision", { outcome: "SUBSTANTIATED" });
    assert.equal(duplicateDecision.status, 409);
  });
});
