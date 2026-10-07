import assert from "node:assert/strict";
import test from "node:test";
import { loadMvpRuntimeConfig, publicRuntimeConfig } from "../src/config.js";

function environment(): NodeJS.ProcessEnv {
  return {
    MVP_DEPLOYMENT_MODE: "development",
    MVP_DATA_CLASSIFICATION: "synthetic",
    MVP_TENANT_ID: "9d4b63ce-7e24-45cf-9ec4-0d3c7839dcaf",
    MVP_TENANT_SLUG: "demo-university",
    MVP_PUBLIC_ORIGIN: "http://127.0.0.1:8080",
    MVP_PORT: "8080",
    MVP_IDENTITY_DATABASE_URL: "postgresql://user:secret@identity-db/identity",
    MVP_COMPLAINT_DATABASE_URL: "postgresql://user:secret@complaint-db/complaint",
    MVP_HANDLER_DATABASE_URL: "postgresql://user:secret@handler-db/handler",
    MVP_PUBLIC_DATABASE_URL: "postgresql://user:secret@public-db/public",
  };
}

test("loads a tenant-fixed synthetic development profile", () => {
  const config = loadMvpRuntimeConfig(environment());
  assert.equal(config.tenantSlug, "demo-university");
  assert.equal(config.dataClassification, "synthetic");
  assert.equal(Object.keys(config.databases).length, 4);
});

test("public configuration never exposes database credentials", () => {
  const publicConfig = publicRuntimeConfig(loadMvpRuntimeConfig(environment()));
  assert.equal(publicConfig.protocol, "cyber-cipher-v1");
  assert.doesNotMatch(JSON.stringify(publicConfig), /secret|database/i);
});

test("rejects non-synthetic data and trust-zone database reuse", () => {
  const realData = environment();
  realData.MVP_DATA_CLASSIFICATION = "real";
  assert.throws(() => loadMvpRuntimeConfig(realData), /synthetic data only/);

  const reused = environment();
  reused.MVP_PUBLIC_DATABASE_URL = reused.MVP_COMPLAINT_DATABASE_URL;
  assert.throws(() => loadMvpRuntimeConfig(reused), /distinct database URL/);
});

test("production requires HTTPS and PostgreSQL transport protection", () => {
  const insecure = environment();
  insecure.MVP_DEPLOYMENT_MODE = "production";
  assert.throws(() => loadMvpRuntimeConfig(insecure), /HTTPS/);

  insecure.MVP_PUBLIC_ORIGIN = "https://complaints.example";
  assert.throws(() => loadMvpRuntimeConfig(insecure), /sslmode=require/);
});
