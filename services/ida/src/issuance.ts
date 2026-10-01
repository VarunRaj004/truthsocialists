import { timingSafeEqual } from "node:crypto";
import type {
  IdempotentIdentityResult,
  IdentityIdempotencyRequest,
  IssueBlindEntitlementInput,
} from "@cyber-cipher/identity-store";
import {
  blindSignEntitlement,
  type PublishedMatter,
} from "@cyber-cipher/matter-registry";
import {
  assertBytesLength,
  encodeCanonical,
  integerMap,
  sha256,
} from "@cyber-cipher/protocol-core";
import { encodeBlindIssuanceResponse } from "./wire.js";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface BlindIssuanceRepository {
  idempotentResponse(
    scope: "blind-issuance",
    key: string,
    requestHash: Uint8Array,
  ): Promise<Uint8Array | undefined>;
  issueBlindEntitlementIdempotent(
    input: IssueBlindEntitlementInput,
    idempotency: IdentityIdempotencyRequest<Uint8Array>,
  ): Promise<IdempotentIdentityResult<Uint8Array>>;
}

export interface PublicMatterRepository {
  publicMatter(
    matterId: string,
    version: number,
    at?: Date,
  ): Promise<PublishedMatter | undefined>;
  listPublic(at?: Date): Promise<PublishedMatter[]>;
}

export interface MatterPrivateKeyProvider {
  /** Returns a fresh mutable copy; the application zeroes it after signing. */
  load(matter: PublishedMatter): Promise<Uint8Array>;
}

export interface BlindIssuanceCommand {
  syntheticIdentityRef: string;
  matterId: string;
  matterVersion: number;
  matterKeyId: Uint8Array;
  blindedMessage: Uint8Array;
}

export interface BlindEntitlementIssuanceOperations {
  issueIdempotent(
    command: BlindIssuanceCommand,
    key: string,
    requestBody: Uint8Array,
  ): Promise<Uint8Array>;
}

export class BlindIssuanceError extends Error {
  constructor(
    readonly code: "MATTER_NOT_ISSUABLE" | "MATTER_KEY_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "BlindIssuanceError";
  }
}

function uuidBytes(uuid: string): Uint8Array {
  if (!UUID_V4.test(uuid)) throw new TypeError("matterId must be a UUIDv4");
  return new Uint8Array(Buffer.from(uuid.replaceAll("-", ""), "hex"));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export class BlindEntitlementIssuanceApplication
  implements BlindEntitlementIssuanceOperations
{
  constructor(
    private readonly identities: BlindIssuanceRepository,
    private readonly matters: PublicMatterRepository,
    private readonly privateKeys: MatterPrivateKeyProvider,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async issueIdempotent(
    command: BlindIssuanceCommand,
    key: string,
    requestBody: Uint8Array,
  ): Promise<Uint8Array> {
    if (!command.syntheticIdentityRef.startsWith("synthetic:")) {
      throw new TypeError("blind issuance requires an identified synthetic session");
    }
    const matterIdBytes = uuidBytes(command.matterId);
    if (
      !Number.isSafeInteger(command.matterVersion) ||
      command.matterVersion < 1 ||
      command.matterVersion > 0xffff_ffff
    ) {
      throw new RangeError("matterVersion must be a positive unsigned 32-bit integer");
    }
    assertBytesLength("matterKeyId", command.matterKeyId, 32);
    assertBytesLength("blindedMessage", command.blindedMessage, 384);
    const requestHash = sha256(
      encodeCanonical(
        integerMap([
          [1, command.syntheticIdentityRef],
          [2, matterIdBytes],
          [3, BigInt(command.matterVersion)],
          [4, sha256(requestBody)],
        ]),
      ),
    );
    const replay = await this.identities.idempotentResponse(
      "blind-issuance",
      key,
      requestHash,
    );
    if (replay !== undefined) return replay;
    const matter = await this.matters.publicMatter(
      command.matterId,
      command.matterVersion,
      this.now(),
    );
    if (matter === undefined || (matter.state !== "PUBLISHED" && matter.state !== "OPEN")) {
      throw new BlindIssuanceError(
        "MATTER_NOT_ISSUABLE",
        "matter is unavailable, closed, or retired",
      );
    }
    if (!equalBytes(matter.matterKeyId, command.matterKeyId)) {
      throw new BlindIssuanceError("MATTER_KEY_MISMATCH", "matter key fingerprint does not match");
    }

    const result = await this.identities.issueBlindEntitlementIdempotent(
      {
        syntheticIdentityRef: command.syntheticIdentityRef,
        matterId: command.matterId,
        matterVersion: command.matterVersion,
        matterKeyId: command.matterKeyId,
        sign: async () => {
          const privateKey = await this.privateKeys.load(matter);
          try {
            return await blindSignEntitlement(privateKey, command.blindedMessage);
          } finally {
            privateKey.fill(0);
          }
        },
      },
      {
        scope: "blind-issuance",
        key,
        requestHash,
        encodeResponse: (blindSignature) =>
          encodeBlindIssuanceResponse({
            matterId: command.matterId,
            matterVersion: command.matterVersion,
            matterKeyId: command.matterKeyId,
            blindSignature,
          }),
      },
    );
    return result.responseCbor;
  }
}
