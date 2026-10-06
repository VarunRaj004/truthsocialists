import { sha256 } from "@cyber-cipher/protocol-core";
import { signedAccessEvent, type AccessEvent, type ActionSigner } from "./audit.js";
import type { StaffCredential, StaffRole } from "./webauthn.js";

export type CaseState = "SUBMITTED" | "ACKNOWLEDGED" | "ASSIGNED" | "UNDER_REVIEW" | "ACTION_REQUIRED" | "RESOLVED" | "REJECTED" | "CLOSED" | "APPEALED";

export interface HandlerCase {
  complaintId: string;
  organizationId: string;
  ciphertextUri: string;
  ciphertextHash: Uint8Array;
  handlerKeyId: Uint8Array;
  state: CaseState;
  assignedStaffId?: string;
  rowVersion: number;
  publicSuppressed: boolean;
  acceptedAt: number;
  acknowledgementDueAt: number;
  assignmentDueAt: number;
  findingDueAt: number;
  appealUntil?: number;
}

export interface CaseEvent { complaintId: string; actorId: string; type: string; from: CaseState; to: CaseState; reasonCode: string; occurredAt: number; previousEventHash: Uint8Array; eventHash: Uint8Array; rowVersion: number }

const transitions: Readonly<Record<CaseState, readonly CaseState[]>> = {
  SUBMITTED: ["ACKNOWLEDGED"], ACKNOWLEDGED: ["ASSIGNED"], ASSIGNED: ["UNDER_REVIEW"],
  UNDER_REVIEW: ["ACTION_REQUIRED", "RESOLVED", "REJECTED", "CLOSED"], ACTION_REQUIRED: ["UNDER_REVIEW"],
  RESOLVED: ["APPEALED"], REJECTED: ["APPEALED"], CLOSED: ["APPEALED"], APPEALED: ["UNDER_REVIEW"],
};

function hasRole(actor: StaffCredential, ...roles: StaffRole[]): boolean { return roles.some((role) => actor.roles.has(role)); }
function copyCase(value: HandlerCase): HandlerCase { return { ...value, ciphertextHash: value.ciphertextHash.slice(), handlerKeyId: value.handlerKeyId.slice() }; }

export class HandlerWorkflow {
  readonly #cases = new Map<string, HandlerCase>();
  readonly #caseEvents = new Map<string, CaseEvent[]>();
  readonly #accessEvents: AccessEvent[] = [];

  constructor(readonly actionSigner: ActionSigner) {}

  registerCase(input: Omit<HandlerCase, "state" | "rowVersion" | "publicSuppressed" | "acknowledgementDueAt" | "assignmentDueAt" | "findingDueAt">): HandlerCase {
    if (this.#cases.has(input.complaintId)) throw new Error("case already exists");
    const value: HandlerCase = { ...input, state: "SUBMITTED", rowVersion: 1, publicSuppressed: false,
      acknowledgementDueAt: input.acceptedAt + 86_400_000, assignmentDueAt: input.acceptedAt + 259_200_000,
      findingDueAt: input.acceptedAt + 1_209_600_000 };
    this.#cases.set(value.complaintId, value); this.#caseEvents.set(value.complaintId, []);
    return copyCase(value);
  }

  listAssigned(actor: StaffCredential): HandlerCase[] {
    return [...this.#cases.values()].filter((item) => item.organizationId === actor.organizationId &&
      (item.assignedStaffId === actor.staffId || hasRole(actor, "SUPERVISOR"))).map(copyCase);
  }

  async openCase(actor: StaffCredential, complaintId: string, now = Date.now()): Promise<HandlerCase> {
    const value = this.requiredCase(complaintId);
    const allowed = value.organizationId === actor.organizationId &&
      (value.assignedStaffId === actor.staffId || hasRole(actor, "SUPERVISOR"));
    await this.audit(value.complaintId, actor.staffId, "READ_CASE", allowed ? "ALLOWED" : "DENIED", allowed ? "ASSIGNED" : "NOT_ASSIGNED", now);
    if (!allowed) throw new Error("case access denied");
    return copyCase(value);
  }

  async assign(actor: StaffCredential, complaintId: string, assignedStaffId: string, expectedVersion: number, now = Date.now()): Promise<HandlerCase> {
    const value = this.requiredCase(complaintId);
    const allowed = value.organizationId === actor.organizationId && hasRole(actor, "TRIAGE", "SUPERVISOR") && value.state === "ACKNOWLEDGED" && value.rowVersion === expectedVersion;
    await this.audit(complaintId, actor.staffId, "ASSIGN_CASE", allowed ? "ALLOWED" : "DENIED", allowed ? "ROLE_AUTHORIZED" : value.rowVersion !== expectedVersion ? "VERSION_CONFLICT" : "ROLE_OR_STATE", now);
    if (!allowed) throw new Error("case assignment denied");
    value.assignedStaffId = assignedStaffId;
    return this.applyTransition(value, actor.staffId, "ASSIGNED", "ASSIGNED_BY_TRIAGE", expectedVersion, now);
  }

  async transition(actor: StaffCredential, complaintId: string, to: CaseState, reasonCode: string, expectedVersion: number, now = Date.now()): Promise<HandlerCase> {
    const value = this.requiredCase(complaintId);
    const assigned = value.organizationId === actor.organizationId && (value.assignedStaffId === actor.staffId || hasRole(actor, "SUPERVISOR"));
    const allowed = assigned && transitions[value.state].includes(to) && value.rowVersion === expectedVersion;
    await this.audit(complaintId, actor.staffId, `TRANSITION_${to}`, allowed ? "ALLOWED" : "DENIED", allowed ? reasonCode : value.rowVersion !== expectedVersion ? "VERSION_CONFLICT" : "NOT_ASSIGNED_OR_INVALID_TRANSITION", now);
    if (!allowed) throw new Error("case transition denied");
    return this.applyTransition(value, actor.staffId, to, reasonCode, expectedVersion, now);
  }

  async extendFindingSla(actor: StaffCredential, complaintId: string, extensionMs: number, reasonCode: string, now = Date.now()): Promise<HandlerCase> {
    const value = this.requiredCase(complaintId);
    const allowed = value.organizationId === actor.organizationId && hasRole(actor, "SUPERVISOR") && extensionMs > 0 && extensionMs <= 1_209_600_000;
    await this.audit(complaintId, actor.staffId, "EXTEND_SLA", allowed ? "ALLOWED" : "DENIED", allowed ? reasonCode : "SUPERVISOR_REQUIRED", now);
    if (!allowed) throw new Error("SLA extension denied");
    value.findingDueAt += extensionMs; value.rowVersion += 1;
    return copyCase(value);
  }

  async setSuppressed(actor: StaffCredential, complaintId: string, suppressed: boolean, reasonCode: string, now = Date.now()): Promise<HandlerCase> {
    const value = this.requiredCase(complaintId);
    const allowed = value.organizationId === actor.organizationId && hasRole(actor, "SUPERVISOR");
    await this.audit(complaintId, actor.staffId, suppressed ? "SUPPRESS_PUBLIC" : "RESTORE_PUBLIC", allowed ? "ALLOWED" : "DENIED", allowed ? reasonCode : "SUPERVISOR_REQUIRED", now);
    if (!allowed) throw new Error("visibility change denied");
    value.publicSuppressed = suppressed; value.rowVersion += 1;
    return copyCase(value);
  }

  accessEvents(): AccessEvent[] { return this.#accessEvents.map((item) => ({ ...item, eventCbor: item.eventCbor.slice(), signature: item.signature.slice() })); }
  caseEvents(complaintId: string): CaseEvent[] { return (this.#caseEvents.get(complaintId) ?? []).map((item) => ({ ...item, previousEventHash: item.previousEventHash.slice(), eventHash: item.eventHash.slice() })); }

  private requiredCase(id: string): HandlerCase { const value = this.#cases.get(id); if (!value) throw new Error("case not found"); return value; }
  private async audit(complaintId: string, actorId: string, action: string, decision: "ALLOWED" | "DENIED", reasonCode: string, now: number): Promise<void> {
    this.#accessEvents.push(await signedAccessEvent(this.actionSigner, { complaintId, actorId, action, decision, reasonCode, occurredAt: BigInt(now) }));
  }
  private applyTransition(value: HandlerCase, actorId: string, to: CaseState, reasonCode: string, expectedVersion: number, now: number): HandlerCase {
    if (value.rowVersion !== expectedVersion) throw new Error("case version conflict");
    const from = value.state; const events = this.#caseEvents.get(value.complaintId)!;
    const previousEventHash = events.at(-1)?.eventHash ?? new Uint8Array(32);
    value.state = to; value.rowVersion += 1;
    if (to === "RESOLVED" || to === "REJECTED" || to === "CLOSED") value.appealUntil = now + 1_209_600_000;
    const eventHash = sha256(previousEventHash, new TextEncoder().encode(`${value.complaintId}\0${actorId}\0${from}\0${to}\0${reasonCode}\0${now}`));
    events.push({ complaintId: value.complaintId, actorId, type: `STATE_${to}`, from, to, reasonCode, occurredAt: now, previousEventHash, eventHash, rowVersion: value.rowVersion });
    return copyCase(value);
  }
}
