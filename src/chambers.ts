import { createHmac, timingSafeEqual, createHash } from "node:crypto";
import type {
  AirlockContext,
  ChamberResult,
  IdentityChamber,
  IntentChamber,
  SessionTokenChamber,
  SoulHandshakeChamber,
  TrustScoreChamber,
} from "./airlock.js";

function fail(reason: string): ChamberResult {
  return { ok: false, reason };
}

function pass(reason: string, extra?: { tier?: string; sessionToken?: string }): ChamberResult {
  return { ok: true, reason, ...extra };
}

/** Identity: DID, listing, challenge window, signer equals expected owner (fixture signer field). */
export const defaultIdentityChamber: IdentityChamber = (ctx) => {
  const { identity, now } = ctx.input;
  if (!identity.did?.trim()) {
    return fail("missing did");
  }
  if (!identity.listingId?.trim()) {
    return fail("missing listingId");
  }
  if (now < identity.challenge.issuedAt) {
    return fail("challenge not yet valid");
  }
  if (now >= identity.challenge.expiresAt) {
    return fail("challenge expired");
  }
  if (identity.recoveredSigner !== identity.expectedOwner) {
    return fail("signer does not match expected owner");
  }
  return pass("identity verified");
};

export type TrustTier = "proven" | "established" | "unproven";

function computeTrustTier(
  accepted: number,
  rejected: number
): { tier: TrustTier; score: number } {
  const score = accepted * 2 - rejected * 3;
  if (score >= 10 && rejected <= 2) {
    return { tier: "proven", score };
  }
  if (score >= 3) {
    return { tier: "established", score };
  }
  return { tier: "unproven", score };
}

/** Trust score: pure score from deliveries; unproven still passes unless malformed counts. */
export const defaultTrustScoreChamber: TrustScoreChamber = (ctx) => {
  const { acceptedDeliveries, rejectedDeliveries } = ctx.input.trust;
  if (acceptedDeliveries < 0 || rejectedDeliveries < 0) {
    return fail("malformed trust record: negative delivery counts");
  }
  const { tier } = computeTrustTier(acceptedDeliveries, rejectedDeliveries);
  return pass(`trust tier ${tier}`, { tier });
};

/** Intent: non-empty scope, future expiry, contextHash matches sha256(canonicalPayload). */
export const defaultIntentChamber: IntentChamber = (ctx) => {
  const intent = ctx.input.intent;
  const { now } = ctx.input;
  if (!intent.scope?.trim()) {
    return fail("intent scope is empty");
  }
  if (now >= intent.expiresAt) {
    return fail("intent expired");
  }
  const hash = createHash("sha256")
    .update(intent.canonicalPayload, "utf8")
    .digest("hex");
  if (hash !== intent.contextHash) {
    return fail("intent contextHash mismatch");
  }
  return pass("intent validated");
};

/** SOUL handshake: SOUL/1, nonce echo, future expiry. */
export const defaultSoulHandshakeChamber: SoulHandshakeChamber = (ctx) => {
  const soul = ctx.input.soul;
  const { now } = ctx.input;
  if (soul.protocolVersion !== "SOUL/1") {
    return fail("unsupported SOUL protocol version");
  }
  if (soul.peerNonceEcho !== soul.sentNonce) {
    return fail("SOUL nonce echo mismatch");
  }
  if (now >= soul.expiresAt) {
    return fail("SOUL handshake expired");
  }
  return pass("SOUL handshake complete");
};

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(str: string): Buffer {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(b64, "base64");
}

export interface SessionTokenPayload {
  sub: string;
  listingId: string;
  tier: string;
  iat: number;
  exp: number;
}

/** Session token: HMAC-SHA256 as base64url(payload).base64url(mac). */
export const defaultSessionTokenChamber: SessionTokenChamber = (ctx) => {
  const { input } = ctx;
  if (!input.sessionTokenSecret?.trim()) {
    return fail("session token secret missing");
  }
  const tier = ctx.trustScore?.tier ?? "unproven";
  const iat = input.now;
  const exp = input.now + input.sessionTokenTtlSeconds;
  const payload: SessionTokenPayload = {
    sub: input.identity.did,
    listingId: input.identity.listingId,
    tier,
    iat,
    exp,
  };
  const payloadJson = JSON.stringify(payload);
  const payloadPart = base64UrlEncode(Buffer.from(payloadJson, "utf8"));
  const mac = createHmac("sha256", input.sessionTokenSecret)
    .update(payloadPart)
    .digest();
  const macPart = base64UrlEncode(mac);
  const token = `${payloadPart}.${macPart}`;
  return pass("session token issued", { sessionToken: token });
};

export function verifySessionToken(
  token: string,
  secret: string,
  now: number
): { ok: true; payload: SessionTokenPayload } | { ok: false; reason: string } {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return { ok: false, reason: "malformed token" };
  }
  const [payloadPart, macPart] = parts;
  if (!payloadPart || !macPart) {
    return { ok: false, reason: "malformed token" };
  }
  const expectedMac = createHmac("sha256", secret)
    .update(payloadPart)
    .digest();
  let actualMac: Buffer;
  try {
    actualMac = base64UrlDecode(macPart);
  } catch {
    return { ok: false, reason: "invalid mac encoding" };
  }
  if (
    expectedMac.length !== actualMac.length ||
    !timingSafeEqual(expectedMac, actualMac)
  ) {
    return { ok: false, reason: "token tampered or invalid signature" };
  }
  let payload: SessionTokenPayload;
  try {
    const json = base64UrlDecode(payloadPart).toString("utf8");
    payload = JSON.parse(json) as SessionTokenPayload;
  } catch {
    return { ok: false, reason: "invalid payload encoding" };
  }
  if (now >= payload.exp) {
    return { ok: false, reason: "session token expired" };
  }
  return { ok: true, payload };
}

export const defaultChambers = {
  identity: defaultIdentityChamber,
  trustScore: defaultTrustScoreChamber,
  intent: defaultIntentChamber,
  soulHandshake: defaultSoulHandshakeChamber,
  sessionToken: defaultSessionTokenChamber,
};
