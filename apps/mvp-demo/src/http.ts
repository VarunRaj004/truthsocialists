import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import type { MvpRuntimeConfig } from "./config.js";
import { publicRuntimeConfig } from "./config.js";
import { DemoStateError, DemoStore, type ComplaintInput } from "./demo.js";
import { checkReadiness, type ZoneProbe } from "./readiness.js";

export interface MvpHttpConfig {
  runtime: MvpRuntimeConfig;
  probe: ZoneProbe;
}

export function createMvpHttpServer(config: MvpHttpConfig): Server {
  const demo = new DemoStore();
  return createServer((request, response) => {
    void route(config, demo, request, response).catch((error: unknown) => {
      if (error instanceof DemoStateError) {
        sendJson(response, 409, { error: error.code, message: error.message }, "no-store");
        return;
      }
      sendJson(response, 500, { error: "INTERNAL_ERROR" }, "no-store");
    });
  });
}

async function route(
  config: MvpHttpConfig,
  demo: DemoStore,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const url = new URL(request.url ?? "/", "http://runtime.invalid");
  if (request.method === "GET" && url.pathname === "/") {
    await sendAsset(response, "index.html", "text/html; charset=utf-8");
    return;
  }
  if (request.method === "GET" && url.pathname === "/assets/styles.css") {
    await sendAsset(response, "styles.css", "text/css; charset=utf-8");
    return;
  }
  if (request.method === "GET" && url.pathname === "/assets/app.js") {
    await sendAsset(response, "app.js", "text/javascript; charset=utf-8");
    return;
  }
  if (request.method === "GET" && url.pathname === "/health/live") {
    sendJson(response, 200, { live: true }, "no-store");
    return;
  }
  if (request.method === "GET" && url.pathname === "/health/ready") {
    const readiness = await checkReadiness(config.probe);
    sendJson(response, readiness.ready ? 200 : 503, readiness, "no-store");
    return;
  }
  if (request.method === "GET" && url.pathname === "/public/v1/config") {
    sendJson(response, 200, publicRuntimeConfig(config.runtime), "public, max-age=300");
    return;
  }
  if (request.method === "GET" && url.pathname === "/demo/v1/state") {
    sendJson(response, 200, demo.state(), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/reset") {
    sendJson(response, 200, demo.reset(), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/complaints") {
    const body = await readJson<ComplaintInput>(request);
    sendJson(response, 201, demo.submit(body), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/handler-decision") {
    const body = await readJson<{ outcome?: unknown }>(request);
    if (body.outcome !== "SUBSTANTIATED" && body.outcome !== "UNSUBSTANTIATED") {
      sendJson(response, 400, { error: "INVALID_OUTCOME" }, "no-store");
      return;
    }
    sendJson(response, 200, demo.decide(body.outcome), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/publication-review") {
    const body = await readJson<{ approve?: unknown }>(request);
    if (typeof body.approve !== "boolean") {
      sendJson(response, 400, { error: "INVALID_REVIEW" }, "no-store");
      return;
    }
    sendJson(response, 200, demo.review(body.approve), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/votes") {
    const body = await readJson<{ choice?: unknown }>(request);
    if (body.choice !== "SUPPORT" && body.choice !== "OPPOSE") {
      sendJson(response, 400, { error: "INVALID_VOTE" }, "no-store");
      return;
    }
    sendJson(response, 200, demo.vote(body.choice), "no-store");
    return;
  }
  if (request.method === "POST" && url.pathname === "/demo/v1/audit") {
    sendJson(response, 200, demo.audit(), "no-store");
    return;
  }
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "METHOD_NOT_ALLOWED" }, "no-store");
    return;
  }
  sendJson(response, 404, { error: "NOT_FOUND" }, "no-store");
}

async function readJson<T>(request: IncomingMessage): Promise<T> {
  if (!(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
    throw new DemoStateError("JSON_REQUIRED", "Use application/json for demo commands.");
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > 16_384) throw new DemoStateError("BODY_TOO_LARGE", "Demo request body exceeds 16 KiB.");
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
  } catch {
    throw new DemoStateError("INVALID_JSON", "The request body is not valid JSON.");
  }
}

async function sendAsset(response: ServerResponse, filename: string, contentType: string): Promise<void> {
  const body = await readFile(new URL(`../../public/${filename}`, import.meta.url));
  if (response.headersSent) return;
  response.writeHead(200, {
    "content-type": contentType,
    "content-length": body.length,
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
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
