export const TRUST_ZONES = ["identity", "complaint", "handler", "public"] as const;
export type TrustZone = (typeof TRUST_ZONES)[number];

export interface MvpRuntimeConfig {
  deploymentMode: "development" | "production";
  dataClassification: "synthetic";
  tenantId: string;
  tenantSlug: string;
  publicOrigin: string;
  port: number;
  databases: Readonly<Record<TrustZone, string>>;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function loadMvpRuntimeConfig(env: NodeJS.ProcessEnv): MvpRuntimeConfig {
  const deploymentMode = required(env, "MVP_DEPLOYMENT_MODE");
  if (deploymentMode !== "development" && deploymentMode !== "production") {
    throw new Error("MVP_DEPLOYMENT_MODE must be development or production");
  }
  if (required(env, "MVP_DATA_CLASSIFICATION") !== "synthetic") {
    throw new Error("the experimental MVP accepts synthetic data only");
  }

  const tenantId = required(env, "MVP_TENANT_ID").toLowerCase();
  if (!UUID_V4.test(tenantId)) throw new Error("MVP_TENANT_ID must be a UUIDv4");
  const tenantSlug = required(env, "MVP_TENANT_SLUG");
  if (!SLUG.test(tenantSlug)) throw new Error("MVP_TENANT_SLUG is invalid");

  const publicOrigin = parsePublicOrigin(required(env, "MVP_PUBLIC_ORIGIN"), deploymentMode);
  const port = parsePort(env.MVP_PORT ?? "8080");
  const databases = {
    identity: parseDatabaseUrl(required(env, "MVP_IDENTITY_DATABASE_URL"), deploymentMode),
    complaint: parseDatabaseUrl(required(env, "MVP_COMPLAINT_DATABASE_URL"), deploymentMode),
    handler: parseDatabaseUrl(required(env, "MVP_HANDLER_DATABASE_URL"), deploymentMode),
    public: parseDatabaseUrl(required(env, "MVP_PUBLIC_DATABASE_URL"), deploymentMode),
  } as const;

  if (new Set(Object.values(databases)).size !== TRUST_ZONES.length) {
    throw new Error("each trust zone must use a distinct database URL");
  }

  return {
    deploymentMode,
    dataClassification: "synthetic",
    tenantId,
    tenantSlug,
    publicOrigin,
    port,
    databases,
  };
}

export function publicRuntimeConfig(config: MvpRuntimeConfig): Record<string, string> {
  return {
    protocol: "cyber-cipher-v1",
    tenantId: config.tenantId,
    tenantSlug: config.tenantSlug,
    publicOrigin: config.publicOrigin,
    dataClassification: config.dataClassification,
  };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

function parsePort(value: string): number {
  if (!/^[0-9]+$/.test(value)) throw new Error("MVP_PORT must be an integer");
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("MVP_PORT is outside the TCP port range");
  }
  return port;
}

function parsePublicOrigin(value: string, mode: MvpRuntimeConfig["deploymentMode"]): string {
  const url = new URL(value);
  if (url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new Error("MVP_PUBLIC_ORIGIN must be an origin without credentials, path, query, or fragment");
  }
  const localDevelopment = mode === "development" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (url.protocol !== "https:" && !(localDevelopment && url.protocol === "http:")) {
    throw new Error("MVP_PUBLIC_ORIGIN must use HTTPS outside local development");
  }
  return url.origin;
}

function parseDatabaseUrl(value: string, mode: MvpRuntimeConfig["deploymentMode"]): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("a trust-zone database URL is invalid");
  }
  if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") {
    throw new Error("trust-zone databases must use PostgreSQL URLs");
  }
  if (url.hostname === "" || url.pathname.length < 2) {
    throw new Error("a trust-zone database URL must include a host and database name");
  }
  if (mode === "production" && url.searchParams.get("sslmode") !== "require") {
    throw new Error("production trust-zone database URLs must set sslmode=require");
  }
  return url.href;
}
