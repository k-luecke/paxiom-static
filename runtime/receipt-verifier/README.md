# paxiom-receipt-verifier — public & monetizable runtime

Deployable zero-dependency HTTP server for the **Paxiom Receipt Verifier** (`https://api.paxiom.org`).
It wraps the canonical verifier core (`standards/receipts/v0/src/verify.mjs`) and adds optional,
environment-gated **live Base / Base Sepolia USDC settlement verification**, **Paxiom Ed25519 counter-attestation**,
and **SaaS API-key + x402 payment gating**.

## Default mode vs. Live-settlement mode

- **Default (zero env vars required):**
  - `GET /health`, `GET /version`, `GET /v1/receipt/demo`, `POST /v1/receipt/verify`, `GET /.well-known/paxiom-keys.json`, and `GET /.well-known/x402.json` run completely free and offline.
  - `POST /v1/receipt/verify-live` returns `503` (`LIVE_VERIFY_DISABLED`) until explicitly enabled.
- **Live-settlement & monetized mode (`LIVE_VERIFY_ENABLED=true`):**
  - `POST /v1/receipt/verify-live` queries `BASE_RPC_URL` / `BASE_SEPOLIA_RPC_URL` (`eth_getTransactionReceipt` + `eth_blockNumber`) to verify canonical USDC `Transfer(address,address,uint256)` logs (`>= amountAtomic`, `status == 0x1`, optional `expectedPayTo` recipient match, configurable block confirmations).
  - Supports **dual monetization gates**:
    1. **SaaS API keys** (`PAXIOM_API_KEYS` via `X-API-Key` or `Authorization: Bearer`)
    2. **x402 pay-per-call** (`X402_ENABLED=true`, default `2000` atomic USDC = `$0.002` on Base, facilitator `verify -> settle -> serve`, full CDP Bazaar `outputSchema` metadata).
  - When `PAXIOM_SIGNING_PRIVATE_KEY_PEM` is configured, verified onchain settlements receive a `counterAttestedReceipt` signed by Paxiom (`checkedByPaxiom: true`) verifiable offline against `/.well-known/paxiom-keys.json`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness — `{ ok: true, service, version }` |
| GET | `/version` | Service identity, active `capabilities`, and explicit `checks` / `notChecked` boundaries |
| GET | `/v1/receipt/demo` | Canonical demo receipt + delivered output |
| POST | `/v1/receipt/verify` | Free offline verification `{ receipt, output?, trustedPaxiomPublicKeys? }` |
| POST | `/v1/receipt/verify-live` | Opt-in live Base/Base-Sepolia USDC `Transfer` log check + counter-attestation |
| GET | `/.well-known/paxiom-keys.json` | Published Paxiom counter-attestation Ed25519 public keys |
| GET | `/.well-known/x402.json` | Machine-readable x402 payment & Bazaar discovery manifest |

## Environment variables (all optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8787` | HTTP listen port |
| `LIVE_VERIFY_ENABLED` | `false` | Enable `POST /v1/receipt/verify-live` |
| `BASE_RPC_URL` | — | Base mainnet JSON-RPC URL (`eip155:8453`, USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) |
| `BASE_SEPOLIA_RPC_URL` | — | Base Sepolia JSON-RPC URL (`eip155:84532`, USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e`) |
| `MIN_CONFIRMATIONS` | `1` | Minimum block confirmations required for `verified_settled` |
| `PAXIOM_API_KEYS` | — | Comma-separated API keys (`label:secret` or `secret`) bypassing x402 on `/v1/receipt/verify-live` |
| `X402_ENABLED` | `false` | Require x402 payment (unless valid API key presented) on `/v1/receipt/verify-live` |
| `X402_PAY_TO` | — | Recipient `0x...` wallet address for x402 USDC settlement |
| `X402_NETWORK` | `base` | `base` (`eip155:8453`) or `base-sepolia` (`eip155:84532`) |
| `X402_PRICE_ATOMIC` | `2000` | Price in atomic USDC (`2000` = `$0.002`) |
| `X402_FACILITATOR_URL` | `https://x402.org/facilitator` | Facilitator base URL exposing `/verify` and `/settle` |
| `PAXIOM_PUBLIC_URL` | `https://api.paxiom.org` | Canonical public base URL advertised in `402` `PaymentRequirements.resource` |
| `PAXIOM_SIGNING_PRIVATE_KEY_PEM` | — | Ed25519 PKCS#8 PEM private key (supports literal `\n` in env vars) for counter-attesting `verified_settled` receipts |
| `PAXIOM_SIGNING_KEY_ID` | `paxiom-live-verifier-key-1` | Key identifier published in `/.well-known/paxiom-keys.json` |

## Run & test locally

```bash
node runtime/receipt-verifier/server.mjs      # PORT=8787 default
npm --prefix runtime/receipt-verifier test    # offline + monetized live-verify test suites
```

## Deploying publicly

Deployed on Render at `https://api.paxiom.org` (`Root Directory: runtime/receipt-verifier`,
`Build Command: npm install`, `Start Command: npm start`). See [`docs/runtime-deployment.md`](../../docs/runtime-deployment.md).
