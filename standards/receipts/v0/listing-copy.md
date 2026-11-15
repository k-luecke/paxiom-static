# Listing copy — Paxiom Receipts (`paxiom.receipt.v0` · `v0.2.0`)

Ready-to-paste copy for `coinbase/x402` ecosystem directories, `awesome-x402`, and MCP server registries.

> **Open MIT standard & free public reference verifier.** All routes are live and free (rate-limited, no API key or paywall) at `https://api.paxiom.org` (`@paxiom/receipts@0.2.0` on npm · `paxiom-receipts==0.2.0` on PyPI · `io.github.k-luecke/paxiom-receipts` on Official MCP Registry):
> - **Free offline verification:** `POST https://api.paxiom.org/v1/receipt/verify` (zero network calls)
> - **Free live Base / Base Sepolia USDC settlement verification + counter-attestation:** `POST https://api.paxiom.org/v1/receipt/verify-live` (public keys at `https://api.paxiom.org/.well-known/x402-keys.json`)
> - **Free pre-payment `x402` seller readiness & scam scan:** `POST https://api.paxiom.org/v1/x402/preflight` (checks canonical Circle USDC asset, EIP-712 domain, `payTo` manifest consistency, and `Payment-Receipt` / `X-Paxiom-Receipt` support before an agent pays)
> - **Local stdio MCP server:** `npx --yes --package=@paxiom/receipts paxiom-receipt-mcp`

## Listing name
```
Paxiom Receipts (x402 Delivery Receipt Standard & Verifier)
```

## Short description (directory ready, <500 chars)
```
Open MIT Ed25519 delivery-receipt specification and zero-dependency Node.js & Python SDKs for x402 v2 APIs. Sellers emit Payment-Receipt headers binding HTTP request, x402 PaymentRequirements, EVM/Solana txHash, and JCS or raw SHA-256 response bytes. Buyers verify signer keys (/.well-known/x402-keys.json) offline or confirm Base USDC settlement via the free reference verifier at api.paxiom.org.
```

## Tags
```
x402
receipt
verification
proof-of-delivery
agent-payments
settlement
base
solana
MCP
open-standard
```

## Links to include in a listing
- `x402` Delivery Receipt Extension Spec: `https://paxiom.org/standards/receipts/v0/x402-delivery-receipt-extension.md`
- Free Public Reference API: `https://api.paxiom.org` (`GET /version`, `GET /.well-known/x402-keys.json`, `POST /v1/receipt/verify`, `POST /v1/receipt/verify-live`, `POST /v1/x402/preflight`)
- Spec & SDK Docs: `https://paxiom.org/receipts.html`
- npm Package: `https://www.npmjs.com/package/@paxiom/receipts`
- PyPI Package: `https://pypi.org/project/paxiom-receipts/`
- OpenAPI: `https://paxiom.org/standards/receipts/v0/openapi.json`
- Repo: `https://github.com/k-luecke/paxiom-static`
