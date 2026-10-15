import { randomBytes, randomUUID } from "node:crypto";

export type HandlerOutcome = "PENDING" | "SUBSTANTIATED" | "UNSUBSTANTIATED";
export type PublicationStatus = "PRIVATE" | "PENDING_REVIEW" | "APPROVED";
export type AuditOutcome = "PENDING" | "ALIGNED" | "CONFLICTING" | "COMMUNITY_INCONCLUSIVE";

export interface DemoCase {
  complaintId: string;
  receiptId: string;
  submittedAt: string;
  matter: string;
  encryptedSummary: string;
  evidenceCount: number;
  logStatus: "FINAL";
  witnesses: string;
  handlerOutcome: HandlerOutcome;
  publicationStatus: PublicationStatus;
  redactedStatement: string;
  votes: { support: number; oppose: number };
  auditOutcome: AuditOutcome;
  auditEventId?: string;
}

export interface DemoState {
  mode: "synthetic-presentation";
  activeCase: DemoCase | null;
}

export interface ComplaintInput {
  matter: string;
  summary: string;
  evidenceCount: number;
}

export class DemoStateError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export class DemoStore {
  #activeCase: DemoCase | null = null;

  state(): DemoState {
    return { mode: "synthetic-presentation", activeCase: this.#activeCase === null ? null : structuredClone(this.#activeCase) };
  }

  reset(): DemoState {
    this.#activeCase = null;
    return this.state();
  }

  submit(input: ComplaintInput): DemoState {
    if (this.#activeCase !== null) throw new DemoStateError("ACTIVE_CASE_EXISTS", "Reset the demo before submitting another complaint.");
    const matter = input.matter.trim();
    const summary = input.summary.trim();
    if (matter.length < 3 || matter.length > 120) throw new DemoStateError("INVALID_MATTER", "Choose a valid synthetic matter.");
    if (summary.length < 12 || summary.length > 800) throw new DemoStateError("INVALID_SUMMARY", "Use 12 to 800 characters of synthetic text.");
    if (!Number.isInteger(input.evidenceCount) || input.evidenceCount < 0 || input.evidenceCount > 5) {
      throw new DemoStateError("INVALID_EVIDENCE_COUNT", "Evidence count must be between zero and five.");
    }

    const complaintId = `CC-${randomBytes(3).toString("hex").toUpperCase()}`;
    this.#activeCase = {
      complaintId,
      receiptId: randomBytes(16).toString("hex"),
      submittedAt: new Date().toISOString(),
      matter,
      encryptedSummary: `ciphertext:${Buffer.byteLength(summary, "utf8")} bytes`,
      evidenceCount: input.evidenceCount,
      logStatus: "FINAL",
      witnesses: "2 of 3",
      handlerOutcome: "PENDING",
      publicationStatus: "PRIVATE",
      redactedStatement: "",
      votes: { support: 0, oppose: 0 },
      auditOutcome: "PENDING",
    };
    return this.state();
  }

  decide(outcome: Exclude<HandlerOutcome, "PENDING">): DemoState {
    const active = this.requireCase();
    if (active.handlerOutcome !== "PENDING") throw new DemoStateError("HANDLER_ALREADY_DECIDED", "The handler decision is append-only.");
    active.handlerOutcome = outcome;
    active.publicationStatus = "PENDING_REVIEW";
    active.redactedStatement = outcome === "SUBSTANTIATED"
      ? "The reported service failure was confirmed after evidence review. Personal identifiers were removed."
      : "The available evidence did not substantiate the reported service failure. Personal identifiers were removed.";
    return this.state();
  }

  review(approve: boolean): DemoState {
    const active = this.requireCase();
    if (active.publicationStatus !== "PENDING_REVIEW") {
      throw new DemoStateError("NOT_REVIEWABLE", "A handler decision must create a derivative before independent review.");
    }
    active.publicationStatus = approve ? "APPROVED" : "PRIVATE";
    if (!approve) active.redactedStatement = "";
    return this.state();
  }

  vote(choice: "SUPPORT" | "OPPOSE"): DemoState {
    const active = this.requireCase();
    if (active.publicationStatus !== "APPROVED") throw new DemoStateError("NOT_PUBLIC", "Only an approved redacted derivative can be voted on.");
    if (choice === "SUPPORT") active.votes.support += 1;
    else active.votes.oppose += 1;
    active.auditOutcome = "PENDING";
    delete active.auditEventId;
    return this.state();
  }

  audit(): DemoState {
    const active = this.requireCase();
    const total = active.votes.support + active.votes.oppose;
    if (total < 3) throw new DemoStateError("QUORUM_NOT_MET", "At least three synthetic votes are required.");
    const community = active.votes.support / total >= 0.6 ? "SUPPORT" : active.votes.oppose / total >= 0.6 ? "OPPOSE" : "INCONCLUSIVE";
    if (community === "INCONCLUSIVE") active.auditOutcome = "COMMUNITY_INCONCLUSIVE";
    else if (
      (active.handlerOutcome === "SUBSTANTIATED" && community === "SUPPORT") ||
      (active.handlerOutcome === "UNSUBSTANTIATED" && community === "OPPOSE")
    ) active.auditOutcome = "ALIGNED";
    else active.auditOutcome = "CONFLICTING";
    active.auditEventId = randomUUID();
    return this.state();
  }

  private requireCase(): DemoCase {
    if (this.#activeCase === null) throw new DemoStateError("NO_ACTIVE_CASE", "Submit a synthetic complaint first.");
    return this.#activeCase;
  }
}

