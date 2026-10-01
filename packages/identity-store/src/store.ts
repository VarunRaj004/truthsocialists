import type { Pool, PoolClient } from "pg";
import { assertBytesLength, bytesToHex } from "@cyber-cipher/protocol-core";
import { emptyLeaf, memberLeaf, scalarToBytes } from "@cyber-cipher/membership-core";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_LEAVES = 65_536;
const MAX_RECOVERY_ATTEMPTS = 10;
const MAX_SERIALIZATION_RETRIES = 3;

export type IdentityStoreErrorCode =
  | "TENANT_MISMATCH"
  | "TREE_FULL"
  | "RECOVERY_NOT_AVAILABLE"
  | "CHALLENGE_NOT_FOUND"
  | "CHALLENGE_CONSUMED"
  | "CHALLENGE_EXPIRED"
  | "ATTEMPT_LIMIT"
  | "AUTHORIZATION_REJECTED"
  | "STALE_RECOVERY_GENERATION";

export class IdentityStoreError extends Error {
  constructor(
    readonly code: IdentityStoreErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "IdentityStoreError";
  }
}

export interface TenantStoreConfig {
  tenantId: string;
  tenantSlug: string;
}

export interface PersistentEnrollment {
  enrollmentId: string;
  syntheticIdentityRef: string;
  personAnchor: bigint;
  activeDeviceHash: bigint;
  activeLeafIndex: number;
  recoveryId: Uint8Array;
  recoveryPublicKey: Uint8Array;
  recoveryGeneration: number;
  active: boolean;
  rowVersion: bigint;
}

export interface EnrollSyntheticInput {
  enrollmentId: string;
  syntheticIdentityRef: string;
  personAnchor: bigint;
  deviceHash: bigint;
  recoveryId: Uint8Array;
  recoveryPublicKey: Uint8Array;
  enrolledAt?: Date;
}

export interface LockedRecoveryEnrollment {
  enrollmentId: string;
  recoveryId: Uint8Array;
  recoveryGeneration: number;
}

export interface RecoveryChallengeDraft {
  challengeId: Uint8Array;
  signedChallengeCbor: Uint8Array;
  issuedAt: Date;
  expiresAt: Date;
}

export interface LockedRecoveryAuthorization {
  signedChallengeCbor: Uint8Array;
  recoveryId: Uint8Array;
  recoveryGeneration: number;
  recoveryPublicKey: Uint8Array;
  personAnchor: bigint;
  activeDeviceHash: bigint;
  activeLeafIndex: number;
}

export interface CompleteRecoveryTransactionInput {
  challengeId: Uint8Array;
  newDeviceHash: bigint;
  newRecoveryId: Uint8Array;
  newRecoveryPublicKey: Uint8Array;
  /** A side-effect-free verifier; serialization retries may invoke it again. */
  authorize(locked: LockedRecoveryAuthorization): void | Promise<void>;
}

export interface MembershipState {
  nextLeafIndex: number;
  currentEpoch: bigint;
  rowVersion: bigint;
}

export interface PendingMembershipUpdate {
  sequence: bigint;
  leafIndex: number;
  operation: "ACTIVATE" | "REVOKE";
  newLeafValue: bigint;
}

interface EnrollmentRow {
  enrollment_id: string;
  synthetic_identity_ref: string;
  person_anchor: string;
  active_device_hash: string;
  active_leaf_index: number;
  recovery_id: Buffer;
  recovery_public_key: Buffer;
  recovery_generation: number;
  active: boolean;
  row_version: string;
}

interface RecoveryRow extends EnrollmentRow {
  signed_challenge_cbor: Buffer;
  challenge_recovery_generation: number;
  consumed_at: Date | null;
  attempts: number;
  expired: boolean;
}

function assertUuid(name: string, value: string): string {
  if (!UUID_PATTERN.test(value)) throw new TypeError(`${name} must be a canonical UUID`);
  return value.toLowerCase();
}

function assertSlug(value: string): string {
  if (!TENANT_SLUG_PATTERN.test(value)) throw new TypeError("tenantSlug is invalid");
  return value;
}

function enrollmentFromRow(row: EnrollmentRow): PersistentEnrollment {
  return {
    enrollmentId: row.enrollment_id,
    syntheticIdentityRef: row.synthetic_identity_ref,
    personAnchor: BigInt(row.person_anchor),
    activeDeviceHash: BigInt(row.active_device_hash),
    activeLeafIndex: row.active_leaf_index,
    recoveryId: new Uint8Array(row.recovery_id),
    recoveryPublicKey: new Uint8Array(row.recovery_public_key),
    recoveryGeneration: row.recovery_generation,
    active: row.active,
    rowVersion: BigInt(row.row_version),
  };
}

export class PostgresIdentityStore {
  readonly tenantId: string;
  readonly tenantSlug: string;

  constructor(
    private readonly pool: Pool,
    config: TenantStoreConfig,
  ) {
    this.tenantId = assertUuid("tenantId", config.tenantId);
    this.tenantSlug = assertSlug(config.tenantSlug);
  }

  async initializeTenant(): Promise<void> {
    await this.serializable(async (client) => {
      await client.query(
        `INSERT INTO ida.tenant_context(singleton, tenant_id, tenant_slug)
         VALUES (true, $1::uuid, $2)
         ON CONFLICT (singleton) DO NOTHING`,
        [this.tenantId, this.tenantSlug],
      );
      const current = await client.query<{ tenant_id: string; tenant_slug: string }>(
        "SELECT tenant_id::text, tenant_slug FROM ida.tenant_context WHERE singleton = true FOR UPDATE",
      );
      if (
        current.rows[0]!.tenant_id !== this.tenantId ||
        current.rows[0]!.tenant_slug !== this.tenantSlug
      ) {
        throw new IdentityStoreError(
          "TENANT_MISMATCH",
          "database is already bound to a different tenant",
        );
      }
      await client.query(
        "INSERT INTO ida.membership_state(singleton) VALUES (true) ON CONFLICT (singleton) DO NOTHING",
      );
    });
  }

  async enrollSynthetic(input: EnrollSyntheticInput): Promise<PersistentEnrollment> {
    assertUuid("enrollmentId", input.enrollmentId);
    if (!input.syntheticIdentityRef.startsWith("synthetic:")) {
      throw new TypeError("prototype enrollment accepts synthetic identities only");
    }
    assertBytesLength("recoveryId", input.recoveryId, 16);
    assertBytesLength("recoveryPublicKey", input.recoveryPublicKey, 32);
    scalarToBytes(input.personAnchor);
    scalarToBytes(input.deviceHash);
    const leaf = memberLeaf(input.personAnchor, input.deviceHash);
    const enrolledAt = input.enrolledAt ?? new Date();
    return this.serializable(async (client) => {
      await this.assertTenant(client);
      const state = await client.query<{ next_leaf_index: number }>(
        "SELECT next_leaf_index FROM ida.membership_state WHERE singleton = true FOR UPDATE",
      );
      const index = state.rows[0]!.next_leaf_index;
      if (index >= MAX_LEAVES) throw new IdentityStoreError("TREE_FULL", "membership tree is full");
      const inserted = await client.query<EnrollmentRow>(
        `INSERT INTO ida.enrollment(
           enrollment_id, synthetic_identity_ref, person_anchor, active_device_hash,
           active_leaf_index, recovery_id, recovery_public_key, recovery_generation,
           active, enrolled_at, updated_at
         ) VALUES ($1::uuid, $2, $3::numeric, $4::numeric, $5, $6, $7, 1, true, $8, $8)
         RETURNING *`,
        [
          input.enrollmentId,
          input.syntheticIdentityRef,
          input.personAnchor.toString(),
          input.deviceHash.toString(),
          index,
          Buffer.from(input.recoveryId),
          Buffer.from(input.recoveryPublicKey),
          enrolledAt,
        ],
      );
      await client.query(
        "INSERT INTO ida.membership_leaf(leaf_index, leaf_value, state) VALUES ($1, $2::numeric, 'ACTIVE')",
        [index, leaf.toString()],
      );
      await client.query(
        `INSERT INTO ida.membership_pending_update(leaf_index, operation, new_leaf_value)
         VALUES ($1, 'ACTIVATE', $2::numeric)`,
        [index, leaf.toString()],
      );
      await client.query(
        `UPDATE ida.membership_state
         SET next_leaf_index = next_leaf_index + 1, row_version = row_version + 1
         WHERE singleton = true`,
      );
      return enrollmentFromRow(inserted.rows[0]!);
    });
  }

  async issueRecoveryChallenge(
    recoveryId: Uint8Array,
    create: (locked: LockedRecoveryEnrollment) => Promise<RecoveryChallengeDraft>,
  ): Promise<RecoveryChallengeDraft> {
    assertBytesLength("recoveryId", recoveryId, 16);
    return this.serializable(async (client) => {
      await this.assertTenant(client);
      const result = await client.query<EnrollmentRow>(
        `SELECT * FROM ida.enrollment
         WHERE recovery_id = $1 AND active = true
         FOR UPDATE`,
        [Buffer.from(recoveryId)],
      );
      if (result.rowCount !== 1) {
        throw new IdentityStoreError("RECOVERY_NOT_AVAILABLE", "recovery challenge is not available");
      }
      const row = result.rows[0]!;
      const draft = await create({
        enrollmentId: row.enrollment_id,
        recoveryId: new Uint8Array(row.recovery_id),
        recoveryGeneration: row.recovery_generation,
      });
      assertBytesLength("challengeId", draft.challengeId, 16);
      if (draft.expiresAt <= draft.issuedAt) throw new RangeError("challenge expiry is invalid");
      if (draft.expiresAt.getTime() - draft.issuedAt.getTime() > 300_000) {
        throw new RangeError("challenge lifetime exceeds five minutes");
      }
      await client.query(
        `INSERT INTO ida.recovery_challenge(
           challenge_id, enrollment_id, recovery_generation, signed_challenge_cbor,
           issued_at, expires_at
         ) VALUES ($1, $2::uuid, $3, $4, $5, $6)`,
        [
          Buffer.from(draft.challengeId),
          row.enrollment_id,
          row.recovery_generation,
          Buffer.from(draft.signedChallengeCbor),
          draft.issuedAt,
          draft.expiresAt,
        ],
      );
      return {
        ...draft,
        challengeId: draft.challengeId.slice(),
        signedChallengeCbor: draft.signedChallengeCbor.slice(),
      };
    });
  }

  async completeRecoveryAtomic(
    input: CompleteRecoveryTransactionInput,
  ): Promise<PersistentEnrollment> {
    assertBytesLength("challengeId", input.challengeId, 16);
    assertBytesLength("newRecoveryId", input.newRecoveryId, 16);
    assertBytesLength("newRecoveryPublicKey", input.newRecoveryPublicKey, 32);
    scalarToBytes(input.newDeviceHash);

    for (let retry = 0; retry < MAX_SERIALIZATION_RETRIES; retry += 1) {
      const client = await this.pool.connect();
      let rejection: unknown;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        await this.assertTenant(client);
        const result = await client.query<RecoveryRow>(
          `SELECT e.*, c.signed_challenge_cbor,
                  c.recovery_generation AS challenge_recovery_generation,
                  c.consumed_at, c.attempts,
                  (c.expires_at <= clock_timestamp()) AS expired
           FROM ida.recovery_challenge c
           JOIN ida.enrollment e ON e.enrollment_id = c.enrollment_id
           WHERE c.challenge_id = $1
           FOR UPDATE OF c, e`,
          [Buffer.from(input.challengeId)],
        );
        if (result.rowCount !== 1) {
          throw new IdentityStoreError("CHALLENGE_NOT_FOUND", "recovery challenge is not recognized");
        }
        const row = result.rows[0]!;
        if (row.consumed_at !== null) {
          throw new IdentityStoreError("CHALLENGE_CONSUMED", "recovery challenge was already consumed");
        }
        if (row.expired) {
          throw new IdentityStoreError("CHALLENGE_EXPIRED", "recovery challenge has expired");
        }
        if (row.attempts >= MAX_RECOVERY_ATTEMPTS) {
          throw new IdentityStoreError("ATTEMPT_LIMIT", "recovery challenge attempt limit reached");
        }
        if (!row.active) {
          throw new IdentityStoreError("RECOVERY_NOT_AVAILABLE", "enrollment is no longer active");
        }
        if (row.challenge_recovery_generation !== row.recovery_generation) {
          throw new IdentityStoreError(
            "STALE_RECOVERY_GENERATION",
            "recovery challenge belongs to a superseded recovery generation",
          );
        }
        const locked: LockedRecoveryAuthorization = {
          signedChallengeCbor: new Uint8Array(row.signed_challenge_cbor),
          recoveryId: new Uint8Array(row.recovery_id),
          recoveryGeneration: row.recovery_generation,
          recoveryPublicKey: new Uint8Array(row.recovery_public_key),
          personAnchor: BigInt(row.person_anchor),
          activeDeviceHash: BigInt(row.active_device_hash),
          activeLeafIndex: row.active_leaf_index,
        };
        try {
          await input.authorize(locked);
        } catch (error) {
          await client.query(
            `UPDATE ida.recovery_challenge
             SET attempts = attempts + 1
             WHERE challenge_id = $1`,
            [Buffer.from(input.challengeId)],
          );
          rejection = new IdentityStoreError(
            "AUTHORIZATION_REJECTED",
            "recovery authorization was rejected",
            { cause: error },
          );
          await client.query("COMMIT");
          throw rejection;
        }
        const state = await client.query<{ next_leaf_index: number }>(
          "SELECT next_leaf_index FROM ida.membership_state WHERE singleton = true FOR UPDATE",
        );
        const newIndex = state.rows[0]!.next_leaf_index;
        if (newIndex >= MAX_LEAVES) {
          throw new IdentityStoreError("TREE_FULL", "membership tree is full");
        }
        const replacementLeaf = memberLeaf(BigInt(row.person_anchor), input.newDeviceHash);
        const revokedLeaf = emptyLeaf();
        await client.query(
          `UPDATE ida.membership_leaf
           SET leaf_value = $2::numeric, state = 'REVOKED', updated_epoch = NULL
           WHERE leaf_index = $1`,
          [row.active_leaf_index, revokedLeaf.toString()],
        );
        await client.query(
          `INSERT INTO ida.membership_leaf(leaf_index, leaf_value, state)
           VALUES ($1, $2::numeric, 'ACTIVE')`,
          [newIndex, replacementLeaf.toString()],
        );
        await client.query(
          `INSERT INTO ida.membership_pending_update(leaf_index, operation, new_leaf_value)
           VALUES ($1, 'REVOKE', $2::numeric), ($3, 'ACTIVATE', $4::numeric)`,
          [row.active_leaf_index, revokedLeaf.toString(), newIndex, replacementLeaf.toString()],
        );
        const updated = await client.query<EnrollmentRow>(
          `UPDATE ida.enrollment
           SET active_device_hash = $2::numeric,
               active_leaf_index = $3,
               recovery_id = $4,
               recovery_public_key = $5,
               recovery_generation = recovery_generation + 1,
               updated_at = clock_timestamp(),
               row_version = row_version + 1
           WHERE enrollment_id = $1::uuid AND recovery_generation = $6
           RETURNING *`,
          [
            row.enrollment_id,
            input.newDeviceHash.toString(),
            newIndex,
            Buffer.from(input.newRecoveryId),
            Buffer.from(input.newRecoveryPublicKey),
            row.recovery_generation,
          ],
        );
        if (updated.rowCount !== 1) {
          throw new IdentityStoreError(
            "STALE_RECOVERY_GENERATION",
            "recovery generation changed during rotation",
          );
        }
        await client.query(
          `UPDATE ida.membership_state
           SET next_leaf_index = next_leaf_index + 1, row_version = row_version + 1
           WHERE singleton = true`,
        );
        await client.query(
          "UPDATE ida.recovery_challenge SET consumed_at = clock_timestamp() WHERE challenge_id = $1",
          [Buffer.from(input.challengeId)],
        );
        await client.query("COMMIT");
        return enrollmentFromRow(updated.rows[0]!);
      } catch (error) {
        if (error !== rejection) await client.query("ROLLBACK").catch(() => undefined);
        if (error !== rejection && isSerializationFailure(error) && retry + 1 < MAX_SERIALIZATION_RETRIES) {
          continue;
        }
        throw error;
      } finally {
        client.release();
      }
    }
    throw new Error("unreachable serialization retry state");
  }

  async enrollment(enrollmentId: string): Promise<PersistentEnrollment | undefined> {
    assertUuid("enrollmentId", enrollmentId);
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<EnrollmentRow>(
        "SELECT * FROM ida.enrollment WHERE enrollment_id = $1::uuid",
        [enrollmentId],
      );
      return result.rowCount === 0 ? undefined : enrollmentFromRow(result.rows[0]!);
    } finally {
      client.release();
    }
  }

  async membershipState(): Promise<MembershipState> {
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<{
        next_leaf_index: number;
        current_epoch: string;
        row_version: string;
      }>("SELECT next_leaf_index, current_epoch, row_version FROM ida.membership_state WHERE singleton = true");
      const row = result.rows[0]!;
      return {
        nextLeafIndex: row.next_leaf_index,
        currentEpoch: BigInt(row.current_epoch),
        rowVersion: BigInt(row.row_version),
      };
    } finally {
      client.release();
    }
  }

  async pendingUpdates(): Promise<PendingMembershipUpdate[]> {
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<{
        pending_sequence: string;
        leaf_index: number;
        operation: "ACTIVATE" | "REVOKE";
        new_leaf_value: string;
      }>(
        `SELECT pending_sequence, leaf_index, operation, new_leaf_value
         FROM ida.membership_pending_update ORDER BY pending_sequence`,
      );
      return result.rows.map((row) => ({
        sequence: BigInt(row.pending_sequence),
        leafIndex: row.leaf_index,
        operation: row.operation,
        newLeafValue: BigInt(row.new_leaf_value),
      }));
    } finally {
      client.release();
    }
  }

  private async assertTenant(client: PoolClient): Promise<void> {
    const result = await client.query<{ tenant_id: string; tenant_slug: string }>(
      "SELECT tenant_id::text, tenant_slug FROM ida.tenant_context WHERE singleton = true",
    );
    const row = result.rows[0];
    if (row === undefined || row.tenant_id !== this.tenantId || row.tenant_slug !== this.tenantSlug) {
      throw new IdentityStoreError("TENANT_MISMATCH", "database tenant binding does not match");
    }
  }

  private async serializable<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    for (let retry = 0; retry < MAX_SERIALIZATION_RETRIES; retry += 1) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const value = await work(client);
        await client.query("COMMIT");
        return value;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        if (isSerializationFailure(error) && retry + 1 < MAX_SERIALIZATION_RETRIES) continue;
        throw error;
      } finally {
        client.release();
      }
    }
    throw new Error("unreachable serialization retry state");
  }
}

export class TenantIdentityStoreRegistry {
  private readonly stores = new Map<string, PostgresIdentityStore>();

  register(store: PostgresIdentityStore): void {
    if (this.stores.has(store.tenantId)) throw new Error("tenant identity store already registered");
    this.stores.set(store.tenantId, store);
  }

  forTrustedTenant(tenantId: string): PostgresIdentityStore {
    const store = this.stores.get(assertUuid("tenantId", tenantId));
    if (store === undefined) throw new Error("tenant identity store is not configured");
    return store;
  }
}

function isSerializationFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "40001";
}

export function recoveryLookupKey(recoveryId: Uint8Array): string {
  return bytesToHex(assertBytesLength("recoveryId", recoveryId, 16));
}
