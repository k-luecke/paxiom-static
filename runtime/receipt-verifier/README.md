# paxiom-receipt-verifier (`0.2.0`) — Free Public Reference Runtime

Deployable zero-dependency HTTP server for the **Paxiom Receipt Verifier** (`https://api.paxiom.org`, MIT).
It wraps the canonical `paxiom.receipt.v0` verifier (`standards/receipts/v0/src/verify.mjs`) and provides
free, rate-limited public reference utilities for **live Base / Base Sepolia USDC settlement verification**,
**Ed25519 counter-attestation**, and **SSRF-hardened pre-payment `x402` seller readiness scanning**.

## Modes

- **Default offline mode (zero env vars required):**
  - `GET /health`, `GET /version`, `GET /v1/receipt/demo`, `POST /v1/receipt/verify`, `GET /.well-known/x402-keys.json`, `GET /.well-known/paxiom-keys.json`, and `POST /mcp` run completely free and offline.
- **Public reference live mode (`LIVE_VERIFY_ENABLED=true`, enabled automatically on Render):**
  - `POST /v1/receipt/verify-live` queries `BASE_RPC_URL` / `BASE_SEPOLIA_RPC_URL` (`eth_getTransactionReceipt` + `eth_blockNumber`) to verify canonical Circle USDC `Transfer(address,address,uint256)` logs (`>= amountAtomic`, `status == 0x1`, `expectedPayTo` recipient match, block confirmations).
  - `POST /v1/x402/preflight` probes untrusted `https://` `x402` seller endpoints before an agent signs an EIP-3009 payment (blocking private/loopback/CGNAT/metadata IPs, DNS rebinding, redirects, spoofed USDC tokens, and `payTo` manifest bait-and-switch).
  - Protected by a zero-dependency, bounded O(1)-memory per-IP burst rate limiter (`RATE_LIMIT_VERIFY_LIVE_PER_MIN=60`, `RATE_LIMIT_PREFLIGHT_PER_MIN=30` -> `429` with `Retry-After`) and cross-site browser CSRF/DNS-oracle protection.
  - When `PAXIOM_SIGNING_PRIVATE_KEY_PEM` is configured, verified on-chain settlements emit `counterAttestedReceipt` (`checkedByVerifier: true`) and attach both `Payment-Receipt` and `X-Paxiom-Receipt` headers verifiable offline against `/.well-known/x402-keys.json`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness — `{ ok: true, service, version }` |
| GET | `/version` | Service identity, active `capabilities`, `rateLimits`, and explicit `checks` / `notChecked` boundaries |
| GET | `/.well-known/x402-keys.json` | Published Ed25519 counter-attestation public keys (`/.well-known/paxiom-keys.json` alias) |
| GET | `/v1/receipt/demo` | Canonical demo receipt + delivered output |
| POST | `/v1/receipt/verify` | Free offline verification `{ receipt, output?, expectedIssuerPublicKeys?, expectedPayTo?, trustedVerifierPublicKeys? }` |
| POST | `/v1/receipt/verify-live` | Free rate-limited live Base/Base-Sepolia USDC `Transfer` log check + counter-attestation |
| POST | `/v1/x402/preflight` | Free rate-limited SSRF-hardened pre-payment `x402` seller safety scanner |
| POST | `/mcp` | Stateless MCP Streamable-HTTP server (`io.github.k-luecke/paxiom-receipts` `0.2.0`) |

## Run & test locally

```bash
node runtime/receipt-verifier/server.mjs      # PORT=8787 default
npm --prefix runtime/receipt-verifier test    # full runtime, SSRF, rate-limiter, and MCP test suites
```
