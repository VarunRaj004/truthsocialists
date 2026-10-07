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
