# x402 gating plan — Phase 5E (PLANNING ONLY, no code yet)

> **Status: notes.** This is a design checklist for gating the receipt verifier (or
> a paid receipt-issuing route) behind x402 and settling one real payment. It is
> intentionally written **before** implementation: any middleware should wrap the
> deployed reality from Phase 5D, not a hypothetical. Do not start coding 5E until
> the public runtime is live and smoke-tested at `api.paxiom.org` (Phase 5D step 6).

## Why 5E is the real Bazaar-eligibility phase

Verification alone does not get a resource indexed. CDP Bazaar indexes a resource
**after a successful settlement** through the facilitator. So 5E = "gate a route +
settle one real payment," and only then does listing (5F) become truthful.

## What to gate (decide first)

Two candidate paid surfaces — pick ONE for the first settlement:
- **A. Paid verification** — gate `POST /v1/receipt/verify`. Simplest, but the v0
  verifier is positioned as *free*; gating it contradicts the current copy. Prefer a
  separate paid path (e.g. `POST /v1/receipt/verify+` or a new `/v1/receipt/notarize`)
  so the free verifier stays free.
- **B. Paid receipt issuance / notarization** — a new route that *issues* a
  Paxiom receipt for a caller's payment+output. More aligned with the product story
  ("Paxiom proves what the payment bought") and doesn't cannibalize the free verifier.

Leaning **B** (new paid route), keep the free verifier free. Confirm before building.

## Required configuration (env vars — NOT committed)

| Var | Purpose | Notes |
|-----|---------|-------|
| `X402_ENABLED` | feature flag, default `false` | ship dark; flip on only when ready |
| `X402_NETWORK` | `base-sepolia` (testnet first) then `base` | testnet before mainnet |
| `X402_PAY_TO` | receiving address for settlements | a dedicated wallet, NOT a personal/hot key |
| `X402_ASSET` | `USDC` | |
| `X402_PRICE_ATOMIC` | tiny price, e.g. `1000` (=$0.001 test) | keep trivially small for first settle |
| `CDP_FACILITATOR_URL` | CDP facilitator endpoint | from CDP docs; may need a CDP key |
| `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` | if facilitator requires auth | secrets — env only, never in repo |
| `X402_RESOURCE_URL` | canonical `resource` advertised in 402 + Bazaar metadata | must match the live route |

Secrets live in the host's env (Render dashboard), never in git. AGENT_RULES.md
still applies: no private keys in the repo, no transactions sent from this workspace.

## Flow to implement (later)

1. Unpaid request to the gated route → `402 Payment Required` with x402
   `accepts[]` (scheme `exact`, network, `maxAmountRequired`, `asset`, `payTo`,
   `resource`, `mimeType`, `maxTimeoutSeconds`).
2. Client retries with an x402 `payment` payload.
3. Server verifies + **settles** via the CDP facilitator.
4. On settlement success → run the paid work (issue/verify receipt), set
   `payment.settlement.status = "verified_settled"` and `checkedByPaxiom = true`
   in the issued receipt, include `settlementTx`.
5. Return the result + receipt.

## Claim boundaries (must stay honest)

- Only a route that **actually settles onchain via the facilitator** may set
  `verified_settled` / `checkedByPaxiom: true`. The free offline verifier still
  reports `settlement_claimed_not_checked` for self-asserted settlement.
- Testnet settlements must be labeled testnet; never present a `base-sepolia`
  settlement as mainnet.
- Update `/version` `notChecked` only for the capabilities the paid route genuinely adds.

## Testnet → mainnet plan

1. `base-sepolia`, price `$0.001`, one successful verify+settle end-to-end.
2. Capture the settlement tx as evidence (screenshot/tx hash → DECISIONS log).
3. Only then flip `X402_NETWORK=base` with a small real price for a single mainnet settle.
4. `.well-known/x402.json` and Bazaar submission (5F) come **after** a real settlement.

## Rollback plan

- `X402_ENABLED=false` instantly reverts the route to free/un-gated (or 404 for a
  new paid route) with no redeploy of code — a pure env flip.
- Keep the free verifier path completely independent of the gated route so a 5E
  problem never takes down the free service.
- Revert-friendly: 5E ships as an additive route behind a flag, not a modification
  of the existing verifier.

## Open questions for Kyle (before any 5E code)

1. Gate a **new paid route** (recommended) or the existing verify endpoint?
2. Which `payTo` wallet, and is it already funded on base-sepolia?
3. CDP facilitator: self-hosted or CDP-hosted? Does it require a CDP API key here?
4. First settlement on testnet only, confirm before any mainnet money moves.

## Not in scope for the notes / not yet

No middleware code, no wallet keys, no transactions, no facilitator calls, no
`.well-known/x402.json`. Those begin only after these questions are answered and the
5D runtime is live.
