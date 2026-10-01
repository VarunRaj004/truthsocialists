import type { Pool, PoolClient } from "pg";
import { assertBytesLength, bytesToHex } from "@cyber-cipher/protocol-core";
import { validateMatterPublicKey } from "./key-material.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_VERSION = 0xffff_ffff;
const PUBLICATION_LEAD_MS = 24 * 60 * 60 * 1000;
const MAX_SERIALIZATION_RETRIES = 3;

export type MatterState = "PUBLISHED" | "OPEN" | "CLOSED" | "RETIRED";

export interface MatterRegistryConfig {
  tenantId: string;
  tenantSlug: string;
  now?: () => Date;
}

export interface PublishMatterInput {
  matterId: string;
  version: number;
  title: string;
  opensAt: Date;
  closesAt: Date;
  rsaSpkiDer: Uint8Array;
  matterKeyId: Uint8Array;
  complaintArtifactId: Uint8Array;
  voteArtifactId: Uint8Array;
  handlerOrgId: string;
  handlerKeyId: Uint8Array;
}

export interface PublishedMatter {
  matterId: string;
  version: number;
  title: string;
  opensAt: Date;
  closesAt: Date;
  publishedAt: Date;
  rsaSpkiDer: Uint8Array;
  matterKeyId: Uint8Array;
  complaintArtifactId: Uint8Array;
  voteArtifactId: Uint8Array;
  handlerOrgId: string;
  handlerKeyId: Uint8Array;
  retiredAt?: Date;
  state: MatterState;
}

interface MatterRow {
  matter_id: string;
  version: string;
  title: string;
  opens_at: Date;
  closes_at: Date;
  published_at: Date;
  rsa_spki_der: Buffer;
  matter_key_id: Buffer;
  complaint_artifact_id: Buffer;
  vote_artifact_id: Buffer;
  handler_org_id: string;
  handler_key_id: Buffer;
  retired_at: Date | null;
}

export class MatterRegistryError extends Error {
  constructor(
    readonly code:
      | "TENANT_MISMATCH"
      | "VERSION_SEQUENCE"
      | "PUBLICATION_LEAD_TIME"
      | "MATTER_NOT_FOUND"
      | "MATTER_NOT_CLOSED",
    message: string,
  ) {
    super(message);
    this.name = "MatterRegistryError";
  }
}

function assertUuid(name: string, value: string, v4 = false): string {
  if (!(v4 ? UUID_V4_PATTERN : UUID_PATTERN).test(value)) {
    throw new TypeError(`${name} must be a canonical ${v4 ? "UUIDv4" : "UUID"}`);
  }
  return value.toLowerCase();
}

function assertDate(name: string, value: Date): Date {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError(`${name} is invalid`);
  return new Date(value.getTime());
}

export function validatePublishMatterInput(
  input: PublishMatterInput,
  publishedAtValue = new Date(),
): PublishMatterInput & { publishedAt: Date } {
  const matterId = assertUuid("matterId", input.matterId, true);
  const handlerOrgId = assertUuid("handlerOrgId", input.handlerOrgId);
  if (!Number.isSafeInteger(input.version) || input.version < 1 || input.version > MAX_VERSION) {
    throw new RangeError("matter version must be an unsigned 32-bit integer greater than zero");
  }
  if (
    input.title.length < 1 ||
    input.title.length > 200 ||
    input.title.normalize("NFC") !== input.title
  ) {
    throw new TypeError("matter title must be 1-200 NFC characters");
  }
  const opensAt = assertDate("opensAt", input.opensAt);
  const closesAt = assertDate("closesAt", input.closesAt);
  const publishedAt = assertDate("publishedAt", publishedAtValue);
  if (closesAt.getTime() <= opensAt.getTime()) throw new RangeError("matter close time must follow open time");
  if (opensAt.getTime() - publishedAt.getTime() < PUBLICATION_LEAD_MS) {
    throw new MatterRegistryError(
      "PUBLICATION_LEAD_TIME",
      "matter must be published at least 24 hours before submissions open",
    );
  }
  assertBytesLength("matterKeyId", input.matterKeyId, 32);
  const derivedKeyId = validateMatterPublicKey(input.rsaSpkiDer);
  if (bytesToHex(derivedKeyId) !== bytesToHex(input.matterKeyId)) {
    throw new TypeError("matterKeyId does not match the RSA SubjectPublicKeyInfo");
  }
  assertBytesLength("complaintArtifactId", input.complaintArtifactId, 32);
  assertBytesLength("voteArtifactId", input.voteArtifactId, 32);
  assertBytesLength("handlerKeyId", input.handlerKeyId, 32);
  return {
    ...input,
    matterId,
    handlerOrgId,
    opensAt,
    closesAt,
    publishedAt,
    rsaSpkiDer: input.rsaSpkiDer.slice(),
    matterKeyId: input.matterKeyId.slice(),
    complaintArtifactId: input.complaintArtifactId.slice(),
    voteArtifactId: input.voteArtifactId.slice(),
    handlerKeyId: input.handlerKeyId.slice(),
  };
}

function stateAt(row: MatterRow, at: Date): MatterState {
  if (row.retired_at !== null && row.retired_at.getTime() <= at.getTime()) return "RETIRED";
  if (at.getTime() < row.opens_at.getTime()) return "PUBLISHED";
  if (at.getTime() < row.closes_at.getTime()) return "OPEN";
  return "CLOSED";
}

function fromRow(row: MatterRow, at: Date): PublishedMatter {
  const base = {
    matterId: row.matter_id,
    version: Number(row.version),
    title: row.title,
    opensAt: new Date(row.opens_at),
    closesAt: new Date(row.closes_at),
    publishedAt: new Date(row.published_at),
    rsaSpkiDer: new Uint8Array(row.rsa_spki_der),
    matterKeyId: new Uint8Array(row.matter_key_id),
    complaintArtifactId: new Uint8Array(row.complaint_artifact_id),
    voteArtifactId: new Uint8Array(row.vote_artifact_id),
    handlerOrgId: row.handler_org_id,
    handlerKeyId: new Uint8Array(row.handler_key_id),
    state: stateAt(row, at),
  };
  return row.retired_at === null ? base : { ...base, retiredAt: new Date(row.retired_at) };
}

function isSerializationFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "40001";
}

export class PostgresMatterRegistry {
  readonly tenantId: string;
  readonly tenantSlug: string;
  private readonly now: () => Date;

  constructor(
    private readonly pool: Pool,
    config: MatterRegistryConfig,
  ) {
    this.tenantId = assertUuid("tenantId", config.tenantId);
    if (!TENANT_SLUG_PATTERN.test(config.tenantSlug)) throw new TypeError("tenantSlug is invalid");
    this.tenantSlug = config.tenantSlug;
    this.now = config.now ?? (() => new Date());
  }

  async initializeTenant(): Promise<void> {
    await this.serializable(async (client) => {
      await client.query(
        `INSERT INTO matter_registry.tenant_context(singleton, tenant_id, tenant_slug)
         VALUES (true, $1::uuid, $2)
         ON CONFLICT (singleton) DO NOTHING`,
        [this.tenantId, this.tenantSlug],
      );
      await this.assertTenant(client, true);
    });
  }

  async publish(input: PublishMatterInput): Promise<PublishedMatter> {
    const value = validatePublishMatterInput(input, this.now());
    return this.serializable(async (client) => {
      await this.assertTenant(client, true);
      const previous = await client.query<{ maximum: string | null }>(
        "SELECT max(version)::text AS maximum FROM matter_registry.matter WHERE matter_id = $1::uuid",
        [value.matterId],
      );
      const maximum = previous.rows[0]!.maximum;
      const expected = maximum === null ? 1 : Number(maximum) + 1;
      if (value.version !== expected) {
        throw new MatterRegistryError(
          "VERSION_SEQUENCE",
          `matter version must be the next unsigned version (${expected})`,
        );
      }
      const inserted = await client.query<MatterRow>(
        `INSERT INTO matter_registry.matter(
           matter_id, version, title, opens_at, closes_at, published_at,
           matter_key_id, rsa_spki_der, complaint_artifact_id, vote_artifact_id,
           handler_org_id, handler_key_id
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::uuid, $12)
         RETURNING *`,
        [
          value.matterId,
          value.version,
          value.title,
          value.opensAt,
          value.closesAt,
          value.publishedAt,
          Buffer.from(value.matterKeyId),
          Buffer.from(value.rsaSpkiDer),
          Buffer.from(value.complaintArtifactId),
          Buffer.from(value.voteArtifactId),
          value.handlerOrgId,
          Buffer.from(value.handlerKeyId),
        ],
      );
      return fromRow(inserted.rows[0]!, value.publishedAt);
    });
  }

  async listPublic(at = new Date()): Promise<PublishedMatter[]> {
    const trustedAt = assertDate("at", at);
    const client = await this.pool.connect();
    try {
      await this.assertTenant(client);
      const result = await client.query<MatterRow>(
        `SELECT * FROM matter_registry.matter
         WHERE published_at <= $1
         ORDER BY opens_at, matter_id, version`,
        [trustedAt],
      );
      return result.rows.map((row) => fromRow(row, trustedAt));
    } finally {
      client.release();
    }
  }

  async retire(matterId: string, version: number, retiredAt = new Date()): Promise<PublishedMatter> {
    const trustedMatterId = assertUuid("matterId", matterId, true);
    if (!Number.isSafeInteger(version) || version < 1 || version > MAX_VERSION) {
      throw new RangeError("matter version is invalid");
    }
    const trustedRetiredAt = assertDate("retiredAt", retiredAt);
    return this.serializable(async (client) => {
      await this.assertTenant(client);
      const current = await client.query<MatterRow>(
        `SELECT * FROM matter_registry.matter
         WHERE matter_id = $1::uuid AND version = $2
         FOR UPDATE`,
        [trustedMatterId, version],
      );
      if (current.rowCount !== 1) {
        throw new MatterRegistryError("MATTER_NOT_FOUND", "matter version is not recognized");
      }
      const row = current.rows[0]!;
      if (trustedRetiredAt.getTime() < row.closes_at.getTime()) {
        throw new MatterRegistryError("MATTER_NOT_CLOSED", "matter cannot retire before it closes");
      }
      if (row.retired_at !== null) return fromRow(row, trustedRetiredAt);
      const updated = await client.query<MatterRow>(
        `UPDATE matter_registry.matter SET retired_at = $3
         WHERE matter_id = $1::uuid AND version = $2
         RETURNING *`,
        [trustedMatterId, version, trustedRetiredAt],
      );
      return fromRow(updated.rows[0]!, trustedRetiredAt);
    });
  }

  private async assertTenant(client: PoolClient, lock = false): Promise<void> {
    const result = await client.query<{ tenant_id: string; tenant_slug: string }>(
      `SELECT tenant_id::text, tenant_slug
       FROM matter_registry.tenant_context WHERE singleton = true${lock ? " FOR UPDATE" : ""}`,
    );
    const row = result.rows[0];
    if (row === undefined || row.tenant_id !== this.tenantId || row.tenant_slug !== this.tenantSlug) {
      throw new MatterRegistryError("TENANT_MISMATCH", "matter registry tenant binding does not match");
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
