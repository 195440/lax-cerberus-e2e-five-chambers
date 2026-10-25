/**
 * Cerberus airlock orchestrator. Chambers are injected so Kognai can replace
 * defaults with production implementations while keeping the same contract.
 */

export type ChamberName =
  | "identity"
  | "trustScore"
  | "intent"
  | "soulHandshake"
  | "sessionToken";

export interface IdentityChallenge {
  issuedAt: number;
  expiresAt: number;
}

export interface IdentityInput {
  did: string;
  listingId: string;
  challenge: IdentityChallenge;
  /** Test double: pre-recovered signer from fixture (not on-chain recovery). */
  recoveredSigner: string;
  expectedOwner: string;
}

export interface TrustRecord {
  acceptedDeliveries: number;
  rejectedDeliveries: number;
}

export interface IntentPayload {
  scope: string;
  expiresAt: number;
  /** Canonical string whose sha256 must match intent.contextHash in fixture. */
  canonicalPayload: string;
  contextHash: string;
}

export interface SoulHandshakeInput {
  protocolVersion: string;
  sentNonce: string;
  peerNonceEcho: string;
  expiresAt: number;
}

export interface AirlockInput {
  now: number;
  identity: IdentityInput;
  trust: TrustRecord;
  intent: IntentPayload;
  soul: SoulHandshakeInput;
  /** Clearly labelled test secret for session token HMAC. */
  sessionTokenSecret: string;
  sessionTokenTtlSeconds: number;
}

export interface AirlockContext {
  input: AirlockInput;
  /** Outputs from earlier chambers (optional enrichment). */
  identity?: { ok: true };
  trustScore?: { ok: true; tier: string };
  intent?: { ok: true };
  soulHandshake?: { ok: true };
}

export interface ChamberResultOk {
  ok: true;
  reason: string;
  tier?: string;
  sessionToken?: string;
}

export interface ChamberResultFail {
  ok: false;
  reason: string;
}

export type ChamberResult = ChamberResultOk | ChamberResultFail;

export type IdentityChamber = (
  ctx: AirlockContext
) => ChamberResult;
export type TrustScoreChamber = (ctx: AirlockContext) => ChamberResult;
export type IntentChamber = (ctx: AirlockContext) => ChamberResult;
export type SoulHandshakeChamber = (ctx: AirlockContext) => ChamberResult;
export type SessionTokenChamber = (ctx: AirlockContext) => ChamberResult;

export interface AirlockChambers {
  identity: IdentityChamber;
  trustScore: TrustScoreChamber;
  intent: IntentChamber;
  soulHandshake: SoulHandshakeChamber;
  sessionToken: SessionTokenChamber;
}

export interface AirlockSuccess {
  ok: true;
  reason: string;
  sessionToken: string;
}

export interface AirlockFailure {
  ok: false;
  failedChamber: ChamberName;
  reason: string;
}

export type AirlockResult = AirlockSuccess | AirlockFailure;

const ORDER: { name: ChamberName; key: keyof AirlockChambers }[] = [
  { name: "identity", key: "identity" },
  { name: "trustScore", key: "trustScore" },
  { name: "intent", key: "intent" },
  { name: "soulHandshake", key: "soulHandshake" },
  { name: "sessionToken", key: "sessionToken" },
];

export function runAirlock(
  chambers: AirlockChambers,
  input: AirlockInput
): AirlockResult {
  const ctx: AirlockContext = { input };

  for (const { name, key } of ORDER) {
    const result = chambers[key](ctx);
    if (!result.ok) {
      return {
        ok: false,
        failedChamber: name,
        reason: result.reason,
      };
    }

    switch (name) {
      case "identity":
        ctx.identity = { ok: true };
        break;
      case "trustScore":
        ctx.trustScore = { ok: true, tier: result.tier ?? "unknown" };
        break;
      case "intent":
        ctx.intent = { ok: true };
        break;
      case "soulHandshake":
        ctx.soulHandshake = { ok: true };
        break;
      case "sessionToken": {
        const token = result.sessionToken;
        if (!token) {
          return {
            ok: false,
            failedChamber: name,
            reason: "session token chamber passed but issued no token",
          };
        }
        return {
          ok: true,
          reason: result.reason,
          sessionToken: token,
        };
      }
    }
  }

  return {
    ok: false,
    failedChamber: "sessionToken",
    reason: "airlock completed without issuing session token",
  };
}
