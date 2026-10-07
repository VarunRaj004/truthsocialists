import type { TrustZone } from "./config.js";
import { TRUST_ZONES } from "./config.js";

export type ZoneProbe = (zone: TrustZone) => Promise<void>;

export interface ReadinessResult {
  ready: boolean;
  zones: Readonly<Record<TrustZone, "ready" | "unavailable">>;
}

export async function checkReadiness(probe: ZoneProbe): Promise<ReadinessResult> {
  const outcomes = await Promise.all(
    TRUST_ZONES.map(async (zone) => {
      try {
        await probe(zone);
        return [zone, "ready"] as const;
      } catch {
        return [zone, "unavailable"] as const;
      }
    }),
  );
  const zones = Object.fromEntries(outcomes) as Record<TrustZone, "ready" | "unavailable">;
  return { ready: outcomes.every(([, state]) => state === "ready"), zones };
}
