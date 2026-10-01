import type { Pool, PoolClient } from "pg";
import {
  assertBytesLength,
  ed25519SpkiFromRaw,
  encodeCanonical,
  integerMap,
  keyIdFromSpkiDer,
  membershipCheckpointBody,
  sha256,
  signedObject,
  signingInput,
  verifyEd25519Raw,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import {
  MembershipOperationType,
  SparseMembershipTree,
  scalarToBytes,
  type CheckpointSigner,
} from "@cyber-cipher/membership-core";

const MAX_SERIALIZATION_RETRIES = 3;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;

export interface MembershipDeltaOperation {
  operation: "ACTIVATE" | "REVOKE";
  leafIndex: number;
  newLeafValue: bigint;
}

export interface CheckpointBundle {
  tenantId: Uint8Array;
  epoch: bigint;
  root: bigint;
  deltaCbor: Uint8Array;
  signedCheckpointCbor: Uint8Array;
  checkpointHash: Uint8Array;
}

export interface CreateCheckpointInput {
  tenantId: Uint8Array;
  epoch: bigint;
  root: bigint;
  previousCheckpointHash: Uint8Array;
  publishedAt: bigint;
  updates: readonly MembershipDeltaOperation[];
}

export interface CheckpointPublisher {
  publishPending(publishedAt: bigint): Promise<CheckpointBundle | undefined>;
}

interface StateRow {
  current_epoch: string;
  previous_checkpoint_hash: Buffer;
}

interface UpdateRow {
  pending_sequence: string;
  leaf_index: number;
  operation: "ACTIVATE" | "REVOKE";
  new_leaf_value: string;
}

interface HistoricalUpdateRow {
  epoch: string;
  sequence_in_batch: number;
  leaf_index: number;
  operation: "ACTIVATE" | "REVOKE";
  new_leaf_value: string;
}

interface CheckpointRow {
  epoch: string;
  root: string;
  checkpoint_cbor: Buffer;
  checkpoint_hash: Buffer;
}

function cloneBytes(value: Uint8Array): Uint8Array {
  return value.slice();
}

function uuidToBytes(uuid: string): Uint8Array {
  const compact = uuid.replaceAll("-", "");
  if (!/^[0-9a-f]{32}$/i.test(compact)) throw new TypeError("tenantId must be a UUID");
  return Uint8Array.from(Buffer.from(compact, "hex"));
}

function operationType(operation: MembershipDeltaOperation["operation"]): bigint {
  return operation === "ACTIVATE"
    ? MembershipOperationType.Activate
    : MembershipOperationType.Revoke;
}

function deltaCbor(
  tenantId: Uint8Array,
  epoch: bigint,
  updates: readonly MembershipDeltaOperation[],
): Uint8Array {
  const operations = updates.map((update, sequence) =>
    integerMap([
      [1, BigInt(sequence)],
      [2, operationType(update.operation)],
      [3, BigInt(update.leafIndex)],
      [4, scalarToBytes(update.newLeafValue)],
    ]),
  );
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, assertBytesLength("tenantId", tenantId, 16)],
      [3, epoch],
      [4, operations as readonly CborValue[]],
    ]),
  );
}

export async function createSignedMembershipCheckpoint(
  input: CreateCheckpointInput,
  signer: CheckpointSigner,
): Promise<CheckpointBundle> {
  if (input.epoch < 1n || input.epoch > UINT64_MAX) throw new RangeError("epoch is outside uint64");
  if (input.publishedAt < 0n || input.publishedAt > UINT64_MAX) {
    throw new RangeError("checkpoint timestamp is outside uint64");
  }
  if (input.updates.length === 0) throw new RangeError("checkpoint requires at least one update");
  scalarToBytes(input.root);
  assertBytesLength("checkpoint public key", signer.publicKey, 32);
  const encodedDelta = deltaCbor(input.tenantId, input.epoch, input.updates);
  const signingKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(signer.publicKey));
  const body = membershipCheckpointBody({
    epoch: input.epoch,
    root: scalarToBytes(input.root),
    previousCheckpointHash: input.previousCheckpointHash,
    publishedAt: input.publishedAt,
    updateBatchHash: sha256(encodedDelta),
    signingKeyId,
  });
  const bodyBytes = encodeCanonical(body);
  const message = signingInput("membership-checkpoint", bodyBytes);
  const signature = assertBytesLength("checkpoint signature", await signer.sign(message), 64);
  if (!verifyEd25519Raw(signer.publicKey, message, signature)) {
    throw new Error("checkpoint signer returned a signature from the wrong key");
  }
  const signedCheckpointCbor = encodeCanonical(signedObject(body, signature));
  return {
    tenantId: cloneBytes(input.tenantId),
    epoch: input.epoch,
    root: input.root,
    deltaCbor: encodedDelta,
    signedCheckpointCbor,
    checkpointHash: sha256(signedCheckpointCbor),
  };
}

export class PostgresCheckpointPublisher {
  private readonly tenantBytes: Uint8Array;

  constructor(
    private readonly pool: Pool,
    private readonly tenantId: string,
    private readonly tenantSlug: string,
    private readonly signer: CheckpointSigner,
  ) {
    this.tenantBytes = uuidToBytes(tenantId);
    assertBytesLength("checkpoint public key", signer.publicKey, 32);
  }

  async publishPending(publishedAt: bigint): Promise<CheckpointBundle | undefined> {
    const date = new Date(Number(publishedAt));
    if (
      publishedAt < 0n ||
      publishedAt > UINT64_MAX ||
      !Number.isSafeInteger(Number(publishedAt)) ||
      Number.isNaN(date.getTime())
    ) {
      throw new RangeError("publishedAt must be a PostgreSQL-compatible Unix millisecond value");
    }
    return this.serializable(async (client) => {
      await this.assertTenant(client);
      const stateResult = await client.query<StateRow>(
        `SELECT current_epoch, previous_checkpoint_hash
         FROM ida.membership_state WHERE singleton = true FOR UPDATE`,
      );
      const state = stateResult.rows[0]!;
      const pendingResult = await client.query<UpdateRow>(
        `SELECT pending_sequence, leaf_index, operation, new_leaf_value
         FROM ida.membership_pending_update
         ORDER BY pending_sequence
         FOR UPDATE`,
      );
      if (pendingResult.rowCount === 0) return undefined;

      const currentEpoch = BigInt(state.current_epoch);
      const historyResult = await client.query<HistoricalUpdateRow>(
        `SELECT epoch, sequence_in_batch, leaf_index, operation, new_leaf_value
         FROM ida.membership_update
         ORDER BY epoch, sequence_in_batch`,
      );
      const tree = new SparseMembershipTree(16);
      for (const update of historyResult.rows) {
        tree.setLeaf(update.leaf_index, BigInt(update.new_leaf_value));
      }
      if (currentEpoch === 0n) {
        if (
          historyResult.rowCount !== 0 ||
          !state.previous_checkpoint_hash.equals(Buffer.alloc(32))
        ) {
          throw new Error("initial membership state has a non-empty checkpoint history");
        }
      } else {
        const previous = await client.query<{ root: string; checkpoint_hash: Buffer }>(
          "SELECT root, checkpoint_hash FROM ida.membership_checkpoint WHERE epoch = $1",
          [currentEpoch.toString()],
        );
        if (
          previous.rowCount !== 1 ||
          BigInt(previous.rows[0]!.root) !== tree.root ||
          !previous.rows[0]!.checkpoint_hash.equals(state.previous_checkpoint_hash)
        ) {
          throw new Error("persisted membership history does not match the current checkpoint root");
        }
      }

      const updates = pendingResult.rows.map<MembershipDeltaOperation>((row) => ({
        operation: row.operation,
        leafIndex: row.leaf_index,
        newLeafValue: BigInt(row.new_leaf_value),
      }));
      for (const update of updates) tree.setLeaf(update.leafIndex, update.newLeafValue);

      const currentLeaves = await client.query<{ leaf_index: number; leaf_value: string }>(
        "SELECT leaf_index, leaf_value FROM ida.membership_leaf ORDER BY leaf_index",
      );
      const currentTree = new SparseMembershipTree(16);
      for (const leaf of currentLeaves.rows) currentTree.setLeaf(leaf.leaf_index, BigInt(leaf.leaf_value));
      if (currentTree.root !== tree.root) {
        throw new Error("pending membership updates do not reproduce the current leaf state");
      }

      const published = await createSignedMembershipCheckpoint(
        {
          tenantId: this.tenantBytes,
          epoch: currentEpoch + 1n,
          root: tree.root,
          previousCheckpointHash: new Uint8Array(state.previous_checkpoint_hash),
          publishedAt,
          updates,
        },
        this.signer,
      );
      await client.query(
        `INSERT INTO ida.membership_checkpoint(
           epoch, root, previous_checkpoint_hash, update_batch_hash,
           checkpoint_cbor, checkpoint_hash, published_at
         ) VALUES ($1, $2::numeric, $3, $4, $5, $6, $7)`,
        [
          published.epoch.toString(),
          published.root.toString(),
          Buffer.from(state.previous_checkpoint_hash),
          Buffer.from(sha256(published.deltaCbor)),
          Buffer.from(published.signedCheckpointCbor),
          Buffer.from(published.checkpointHash),
          date,
        ],
      );
      for (let sequence = 0; sequence < updates.length; sequence += 1) {
        const update = updates[sequence]!;
        await client.query(
          `INSERT INTO ida.membership_update(
             epoch, sequence_in_batch, leaf_index, operation, new_leaf_value
           ) VALUES ($1, $2, $3, $4, $5::numeric)`,
          [published.epoch.toString(), sequence, update.leafIndex, update.operation, update.newLeafValue.toString()],
        );
      }
      const leafIndices = [...new Set(updates.map((update) => update.leafIndex))];
      await client.query(
        "UPDATE ida.membership_leaf SET updated_epoch = $1 WHERE leaf_index = ANY($2::integer[])",
        [published.epoch.toString(), leafIndices],
      );
      await client.query(
        `UPDATE ida.membership_state
         SET current_epoch = $1,
             previous_checkpoint_hash = $2,
             row_version = row_version + 1
         WHERE singleton = true`,
        [published.epoch.toString(), Buffer.from(published.checkpointHash)],
      );
      await client.query(
        "DELETE FROM ida.membership_pending_update WHERE pending_sequence = ANY($1::bigint[])",
        [pendingResult.rows.map((row) => row.pending_sequence)],
      );
      return published;
    });
  }

  async latestCheckpoint(): Promise<CheckpointBundle | undefined> {
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<CheckpointRow>(
        `SELECT epoch, root, checkpoint_cbor, checkpoint_hash
         FROM ida.membership_checkpoint ORDER BY epoch DESC LIMIT 1`,
      );
      if (result.rowCount === 0) return undefined;
      return this.bundleFromRow(client, result.rows[0]!);
    } finally {
      client.release();
    }
  }

  async checkpointsAfter(epoch: bigint, limit = 100): Promise<CheckpointBundle[]> {
    if (epoch < 0n || epoch > UINT64_MAX) throw new RangeError("epoch is outside uint64");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("limit must be between 1 and 100");
    }
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<CheckpointRow>(
        `SELECT epoch, root, checkpoint_cbor, checkpoint_hash
         FROM ida.membership_checkpoint
         WHERE epoch > $1 ORDER BY epoch LIMIT $2`,
        [epoch.toString(), limit],
      );
      const bundles: CheckpointBundle[] = [];
      for (const row of result.rows) bundles.push(await this.bundleFromRow(client, row));
      return bundles;
    } finally {
      client.release();
    }
  }

  private async bundleFromRow(client: PoolClient, row: CheckpointRow): Promise<CheckpointBundle> {
    const epoch = BigInt(row.epoch);
    const updatesResult = await client.query<HistoricalUpdateRow>(
      `SELECT epoch, sequence_in_batch, leaf_index, operation, new_leaf_value
       FROM ida.membership_update WHERE epoch = $1 ORDER BY sequence_in_batch`,
      [row.epoch],
    );
    const updates = updatesResult.rows.map<MembershipDeltaOperation>((update) => ({
      operation: update.operation,
      leafIndex: update.leaf_index,
      newLeafValue: BigInt(update.new_leaf_value),
    }));
    return {
      tenantId: cloneBytes(this.tenantBytes),
      epoch,
      root: BigInt(row.root),
      deltaCbor: deltaCbor(this.tenantBytes, epoch, updates),
      signedCheckpointCbor: new Uint8Array(row.checkpoint_cbor),
      checkpointHash: new Uint8Array(row.checkpoint_hash),
    };
  }

  private async assertTenant(client: PoolClient): Promise<void> {
    const result = await client.query<{ tenant_id: string; tenant_slug: string }>(
      "SELECT tenant_id::text, tenant_slug FROM ida.tenant_context WHERE singleton = true",
    );
    const row = result.rows[0];
    if (row === undefined || row.tenant_id !== this.tenantId || row.tenant_slug !== this.tenantSlug) {
      throw new Error("database tenant binding does not match checkpoint publisher");
    }
  }

  private async serializable<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    for (let retry = 0; retry < MAX_SERIALIZATION_RETRIES; retry += 1) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const result = await work(client);
        await client.query("COMMIT");
        return result;
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

export class MembershipCheckpointWorker {
  private timer: NodeJS.Timeout | undefined;
  private running = false;

  constructor(
    private readonly publisher: CheckpointPublisher,
    private readonly now: () => bigint = () => BigInt(Date.now()),
    private readonly intervalMs = 30_000,
  ) {
    if (!Number.isInteger(intervalMs) || intervalMs < 1) {
      throw new RangeError("checkpoint interval must be a positive integer");
    }
  }

  async runOnce(): Promise<CheckpointBundle | undefined> {
    return this.publisher.publishPending(this.now());
  }

  start(onError: (error: unknown) => void): void {
    if (this.timer !== undefined) throw new Error("checkpoint worker is already running");
    const tick = async (): Promise<void> => {
      if (this.running) return;
      this.running = true;
      try {
        await this.runOnce();
      } catch (error) {
        onError(error);
      } finally {
        this.running = false;
      }
    };
    void tick();
    this.timer = setInterval(() => void tick(), this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }
}

function isSerializationFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "40001";
}
