# LAX Cerberus E2E Five Chambers

Fixture-based end-to-end tests for the Cerberus airlock with all five chambers enabled. No network calls.

## Chamber order

The orchestrator runs chambers strictly in this order and stops at the first refusal:

1. **identity** - DID, listing, challenge window, signer matches expected owner
2. **trust score** - Pure delivery score and tier (unproven agents still pass)
3. **intent** - Scope, expiry, SHA-256 context hash over canonical payload
4. **SOUL handshake** - `SOUL/1`, nonce echo, handshake expiry
5. **session token** - HMAC-SHA256 session token (test secret only)

## Architecture

- `src/airlock.ts` - `AirlockChambers` interface, `runAirlock(chambers, input)`
- `src/chambers.ts` - Default pure chamber implementations and `verifySessionToken`
- `test/fixtures/*.json` - Pass and fail inputs loaded by tests
- `test/airlock.test.ts` - `node:test` suite via `tsx`

Each chamber is an injected function `(ctx: AirlockContext) => ChamberResult`. The orchestrator never embeds Kognai-specific logic.

### Interface contract

- Input: `AirlockInput` (identity, trust record, intent, SOUL fields, `now`, test session secret, TTL)
- Success: `{ ok: true, reason, sessionToken }`
- Failure: `{ ok: false, failedChamber, reason }`

**Test double boundary:** identity uses `recoveredSigner` from the fixture instead of on-chain signature recovery. Production code can replace the identity chamber while keeping the same orchestrator.

## Plug in Kognai chambers

```typescript
import { runAirlock, type AirlockChambers } from "./src/airlock.js";
import { defaultChambers } from "./src/chambers.js";

const chambers: AirlockChambers = {
  ...defaultChambers,
  identity: kognaiIdentityChamber,
  trustScore: kognaiTrustChamber,
};

const result = runAirlock(chambers, input);
```

Swap any chamber independently. Tests in this repo use `defaultChambers` plus JSON fixtures.

## Fixtures

| File | Purpose |
|------|---------|
| `base-pass.json` | Full happy path |
| `fail-identity-*.json` | Identity refusals |
| `fail-trust-malformed-negative.json` | Trust refusal |
| `pass-trust-unproven-agent.json` | Unproven tier still passes |
| `fail-intent-*.json` | Intent refusals |
| `fail-soul-*.json` | SOUL refusals |
| `fail-session-token-empty-secret.json` | Session token refusal |

## Run

```bash
npm install
npm test
npm run typecheck
```

Session token secret in fixtures: `TEST-ONLY-session-hmac-secret-not-for-production` (not for production).
