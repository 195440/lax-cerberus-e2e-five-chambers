import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  runAirlock,
  type AirlockChambers,
  type AirlockInput,
  type ChamberName,
  type ChamberResult,
} from "../src/airlock.js";
import {
  defaultChambers,
  verifySessionToken,
} from "../src/chambers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "fixtures");

function loadFixture(name: string): AirlockInput {
  const raw = readFileSync(join(fixturesDir, name), "utf8");
  return JSON.parse(raw) as AirlockInput;
}

function withRecording(
  chambers: AirlockChambers
): { chambers: AirlockChambers; calls: ChamberName[] } {
  const calls: ChamberName[] = [];
  const wrap = (
    name: ChamberName,
    fn: (ctx: Parameters<AirlockChambers["identity"]>[0]) => ChamberResult
  ) => {
    return (ctx: Parameters<AirlockChambers["identity"]>[0]) => {
      calls.push(name);
      return fn(ctx);
    };
  };
  return {
    calls,
    chambers: {
      identity: wrap("identity", chambers.identity),
      trustScore: wrap("trustScore", chambers.trustScore),
      intent: wrap("intent", chambers.intent),
      soulHandshake: wrap("soulHandshake", chambers.soulHandshake),
      sessionToken: wrap("sessionToken", chambers.sessionToken),
    },
  };
}

describe("Cerberus airlock five chambers", () => {
  it("full pass runs all five chambers in order and issues session token", () => {
    const input = loadFixture("base-pass.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.ok(result.sessionToken.includes("."));
    assert.deepEqual(calls, [
      "identity",
      "trustScore",
      "intent",
      "soulHandshake",
      "sessionToken",
    ]);
    const verified = verifySessionToken(
      result.sessionToken,
      input.sessionTokenSecret,
      input.now
    );
    assert.equal(verified.ok, true);
  });

  it("identity chamber refuses missing did and stops before trust", () => {
    const input = loadFixture("fail-identity-missing-did.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "identity");
    assert.deepEqual(calls, ["identity"]);
  });

  it("identity chamber refuses missing listingId", () => {
    const input = loadFixture("fail-identity-missing-listing.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "identity");
    assert.match(result.reason, /listingId/i);
  });

  it("identity chamber refuses expired challenge", () => {
    const input = loadFixture("fail-identity-challenge-expired.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "identity");
    assert.deepEqual(calls, ["identity"]);
  });

  it("identity chamber refuses wrong signer", () => {
    const input = loadFixture("fail-identity-wrong-signer.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "identity");
    assert.match(result.reason, /signer/i);
  });

  it("trust score chamber refuses malformed negative deliveries", () => {
    const input = loadFixture("fail-trust-malformed-negative.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "trustScore");
    assert.deepEqual(calls, ["identity", "trustScore"]);
  });

  it("unproven agent still passes trust score chamber", () => {
    const input = loadFixture("pass-trust-unproven-agent.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, true);
    assert.ok(calls.includes("trustScore"));
    if (!result.ok) return;
    const verified = verifySessionToken(
      result.sessionToken,
      input.sessionTokenSecret,
      input.now
    );
    assert.equal(verified.ok, true);
    if (verified.ok) {
      assert.equal(verified.payload.tier, "unproven");
    }
  });

  it("intent chamber refuses empty scope", () => {
    const input = loadFixture("fail-intent-empty-scope.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "intent");
    assert.deepEqual(calls, [
      "identity",
      "trustScore",
      "intent",
    ]);
  });

  it("intent chamber refuses contextHash mismatch", () => {
    const input = loadFixture("fail-intent-hash-mismatch.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "intent");
  });

  it("intent chamber refuses expired intent", () => {
    const input = loadFixture("fail-intent-expired.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "intent");
  });

  it("SOUL handshake refuses protocol version mismatch", () => {
    const input = loadFixture("fail-soul-version-mismatch.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "soulHandshake");
    assert.deepEqual(calls, [
      "identity",
      "trustScore",
      "intent",
      "soulHandshake",
    ]);
  });

  it("SOUL handshake refuses nonce echo mismatch", () => {
    const input = loadFixture("fail-soul-nonce-mismatch.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "soulHandshake");
  });

  it("SOUL handshake refuses expired handshake window", () => {
    const input = loadFixture("fail-soul-handshake-expired.json");
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "soulHandshake");
  });

  it("session token chamber refuses empty secret", () => {
    const input = loadFixture("fail-session-token-empty-secret.json");
    const { chambers, calls } = withRecording(defaultChambers);
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "sessionToken");
    assert.deepEqual(calls, [
      "identity",
      "trustScore",
      "intent",
      "soulHandshake",
      "sessionToken",
    ]);
  });

  it("verifySessionToken rejects expired token", () => {
    const input = loadFixture("base-pass.json");
    const pass = runAirlock(defaultChambers, input);
    assert.equal(pass.ok, true);
    if (!pass.ok) return;
    const payloadPart = pass.sessionToken.split(".")[0]!;
    const atExpiry = verifySessionToken(
      pass.sessionToken,
      input.sessionTokenSecret,
      input.now + input.sessionTokenTtlSeconds
    );
    assert.equal(atExpiry.ok, false);
    if (!atExpiry.ok) {
      assert.match(atExpiry.reason, /expired/i);
    }
    void payloadPart;
  });

  it("verifySessionToken rejects tampered payload segment", () => {
    const input = loadFixture("base-pass.json");
    const pass = runAirlock(defaultChambers, input);
    assert.equal(pass.ok, true);
    if (!pass.ok) return;
    const [, mac] = pass.sessionToken.split(".");
    const tamperedPayload = pass.sessionToken.split(".")[0]!.slice(0, -1) + "x";
    const tampered = `${tamperedPayload}.${mac}`;
    const verified = verifySessionToken(
      tampered,
      input.sessionTokenSecret,
      input.now
    );
    assert.equal(verified.ok, false);
    if (!verified.ok) {
      assert.match(verified.reason, /tampered|invalid signature/i);
    }
  });

  it("verifySessionToken rejects tampered mac segment", () => {
    const input = loadFixture("base-pass.json");
    const pass = runAirlock(defaultChambers, input);
    assert.equal(pass.ok, true);
    if (!pass.ok) return;
    const [payload] = pass.sessionToken.split(".");
    const tamperedMac = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const tampered = `${payload}.${tamperedMac}`;
    const verified = verifySessionToken(
      tampered,
      input.sessionTokenSecret,
      input.now
    );
    assert.equal(verified.ok, false);
  });

  it("proven tier assigned for strong delivery record", () => {
    const input = loadFixture("base-pass.json");
    let capturedTier: string | undefined;
    const chambers: AirlockChambers = {
      ...defaultChambers,
      trustScore: (ctx) => {
        const r = defaultChambers.trustScore(ctx);
        if (r.ok && r.tier) capturedTier = r.tier;
        return r;
      },
    };
    const result = runAirlock(chambers, input);
    assert.equal(result.ok, true);
    assert.equal(capturedTier, "proven");
  });

  it("challenge not yet valid refuses identity", () => {
    const input = loadFixture("base-pass.json");
    input.now = input.identity.challenge.issuedAt - 1;
    const result = runAirlock(defaultChambers, input);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failedChamber, "identity");
  });

  it("verifySessionToken rejects wrong secret", () => {
    const input = loadFixture("base-pass.json");
    const pass = runAirlock(defaultChambers, input);
    assert.equal(pass.ok, true);
    if (!pass.ok) return;
    const verified = verifySessionToken(
      pass.sessionToken,
      "wrong-test-secret",
      input.now
    );
    assert.equal(verified.ok, false);
  });

  it("verifySessionToken rejects malformed token shape", () => {
    const verified = verifySessionToken(
      "not-a-valid-token",
      "TEST-ONLY-session-hmac-secret-not-for-production",
      1700000100
    );
    assert.equal(verified.ok, false);
  });

  it("session token payload includes listing and subject from identity", () => {
    const input = loadFixture("base-pass.json");
    const pass = runAirlock(defaultChambers, input);
    assert.equal(pass.ok, true);
    if (!pass.ok) return;
    const verified = verifySessionToken(
      pass.sessionToken,
      input.sessionTokenSecret,
      input.now
    );
    assert.equal(verified.ok, true);
    if (verified.ok) {
      assert.equal(verified.payload.sub, input.identity.did);
      assert.equal(verified.payload.listingId, input.identity.listingId);
    }
  });
});
