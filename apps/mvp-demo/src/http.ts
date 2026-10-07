import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { MvpRuntimeConfig } from "./config.js";
import { publicRuntimeConfig } from "./config.js";
import { checkReadiness, type ZoneProbe } from "./readiness.js";

export interface MvpHttpConfig {
  runtime: MvpRuntimeConfig;
  probe: ZoneProbe;
}

export function createMvpHttpServer(config: MvpHttpConfig): Server {
  return createServer((request, response) => {
    void route(config, request, response).catch(() => sendJson(response, 500, { error: "INTERNAL_ERROR" }, "no-store"));
  });
}

async function route(config: MvpHttpConfig, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", "http://runtime.invalid");
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "METHOD_NOT_ALLOWED" }, "no-store");
    return;
  }
  if (url.pathname === "/health/live") {
    sendJson(response, 200, { live: true }, "no-store");
    return;
  }
  if (url.pathname === "/health/ready") {
    const readiness = await checkReadiness(config.probe);
    sendJson(response, readiness.ready ? 200 : 503, readiness, "no-store");
    return;
  }
  if (url.pathname === "/public/v1/config") {
    sendJson(response, 200, publicRuntimeConfig(config.runtime), "public, max-age=300");
    return;
  }
  sendJson(response, 404, { error: "NOT_FOUND" }, "no-store");
}

function sendJson(response: ServerResponse, status: number, value: unknown, cacheControl: string): void {
  if (response.headersSent) return;
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": cacheControl,
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-site",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}
