import { assertBytesLength } from "@cyber-cipher/protocol-core";
import type { PostgresMatterRegistry, PublishedMatter } from "./store.js";

export interface MatterPrivateKeyDestroyer {
  /** Idempotently destroys all private-key material and returns a stable 32-byte evidence digest. */
  destroy(matter: PublishedMatter): Promise<Uint8Array>;
}

export interface MatterRetirementRegistry {
  retirementCandidates(at?: Date): Promise<PublishedMatter[]>;
  retire(
    matterId: string,
    version: number,
    retirementEvidence: Uint8Array,
    retiredAt?: Date,
  ): Promise<PublishedMatter>;
}

export class MatterRetirementWorker {
  private timer: NodeJS.Timeout | undefined;
  private running = false;

  constructor(
    private readonly registry: MatterRetirementRegistry | PostgresMatterRegistry,
    private readonly destroyer: MatterPrivateKeyDestroyer,
    private readonly intervalMs = 60_000,
    private readonly now: () => Date = () => new Date(),
  ) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000) {
      throw new RangeError("retirement interval must be at least one second");
    }
  }

  async runOnce(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const at = this.now();
      const candidates = await this.registry.retirementCandidates(at);
      for (const matter of candidates) {
        const evidence = assertBytesLength(
          "private-key destruction evidence",
          await this.destroyer.destroy(matter),
          32,
        );
        await this.registry.retire(matter.matterId, matter.version, evidence, at);
      }
      return candidates.length;
    } finally {
      this.running = false;
    }
  }

  start(onError: (error: unknown) => void = () => undefined): void {
    if (this.timer !== undefined) return;
    void this.runOnce().catch(onError);
    this.timer = setInterval(() => void this.runOnce().catch(onError), this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer === undefined) return;
    clearInterval(this.timer);
    this.timer = undefined;
  }
}
