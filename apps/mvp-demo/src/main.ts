import { Pool } from "pg";
import { loadMvpRuntimeConfig, TRUST_ZONES, type TrustZone } from "./config.js";
import { createMvpHttpServer } from "./http.js";

const runtime = loadMvpRuntimeConfig(process.env);
const pools = Object.fromEntries(
  TRUST_ZONES.map((zone) => [zone, new Pool({ connectionString: runtime.databases[zone], max: 2 })]),
) as Record<TrustZone, Pool>;

const server = createMvpHttpServer({
  runtime,
  probe: async (zone) => {
    await pools[zone].query("SELECT 1");
  },
});

server.listen(runtime.port, "0.0.0.0");

async function shutdown(): Promise<void> {
  server.close();
  await Promise.all(TRUST_ZONES.map(async (zone) => pools[zone].end()));
}

process.once("SIGINT", () => void shutdown().finally(() => process.exit(0)));
process.once("SIGTERM", () => void shutdown().finally(() => process.exit(0)));
