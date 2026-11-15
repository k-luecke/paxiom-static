# Paxiom — Proof-of-Delivery Receipts & Verifier (`paxiom.receipt.v0`)

[![npm](https://img.shields.io/npm/v/@paxiom/receipts)](https://www.npmjs.com/package/@paxiom/receipts)
[![PyPI](https://img.shields.io/pypi/v/paxiom-receipts)](https://pypi.org/project/paxiom-receipts/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **x402 proves a payment. Paxiom proves what the payment bought.**

Open MIT specification, `x402` v2 `delivery-receipt` extension draft, zero-dependency TypeScript/Node & Python SDKs, MCP servers, free public reference verification runtime (`https://api.paxiom.org`), and specification site (`https://paxiom.org`) maintained by **Driftbound Labs** (`https://driftboundlabs.com`).

## Shipped Packages & Free Public Reference Endpoints (`v0.2.0`)

| Surface | Location | Install / Endpoint |
|---|---|---|
| **TypeScript / Node SDK & CLI** | [`standards/receipts/v0/`](standards/receipts/v0/) | `npm install @paxiom/receipts` (`0.2.0`, MIT, zero deps) |
| **Python SDK** | [`standards/receipts/v0/python/`](standards/receipts/v0/python/) | `pip install paxiom-receipts` (`0.2.0`, MIT, zero deps) |
| **x402 v2 Extension Draft** | [`x402-delivery-receipt-extension.md`](standards/receipts/v0/x402-delivery-receipt-extension.md) | Vendor-neutral `Payment-Receipt` header & `/.well-known/x402-keys.json` discovery |
| **MCP Server (Official Registry)** | `io.github.k-luecke/paxiom-receipts` | `npx -y --package=@paxiom/receipts paxiom-receipt-mcp` or `https://api.paxiom.org/mcp` |
| **Offline Verifier Mirror** | `https://api.paxiom.org/v1/receipt/verify` | Free public reference · schema, Ed25519 signature, signer pinning, & `jcs-sha256` / `raw-sha256` output binding |
| **Live Base Settlement Verifier** | `https://api.paxiom.org/v1/receipt/verify-live` | Free public reference (60 req/min/IP) · verifies Base / Base Sepolia USDC `Transfer` logs + Ed25519 counter-attestation |
| **x402 Seller Preflight Scanner** | `https://api.paxiom.org/v1/x402/preflight` | Free public reference (30 req/min/IP) · SSRF-hardened pre-payment quote, asset, key-discovery, & receipt-readiness scan |
| **Verifier Key Discovery** | `https://api.paxiom.org/.well-known/x402-keys.json` | Published Ed25519 counter-signing public keys (also mirrored at `/.well-known/paxiom-keys.json`) |
| **Documentation & Spec Site** | [`https://paxiom.org`](https://paxiom.org) | [`receipts.html`](https://paxiom.org/receipts.html) · [`api.html`](https://paxiom.org/api.html) · [`llms.txt`](https://paxiom.org/llms.txt) |

## Quick Verification

```bash
# Node SDK, Schema Validation & Cross-Language Test Vectors
cd standards/receipts/v0 && npm run validate && npm test

# Python SDK (zero-dependency stdlib + cross-language interop)
cd standards/receipts/v0 && python3 -m unittest discover -s python/tests -v

# Public Reference Verifier & x402 Preflight Runtime Suite
cd runtime/receipt-verifier && npm test
```

## Explicit Boundaries (What `v0.2.0` Checks vs. Does Not Claim)

- **Offline verification (`verifyReceipt` / `POST /v1/receipt/verify`)** verifies schema conformance, deterministic canonical JSON (`jcs-sha256`) or raw byte (`raw-sha256`) payload digests, Ed25519 signatures, optional seller key / `payTo` authorization (`unauthorized_issuer`), and counter-attestation key pinning (`trustedVerifierPublicKeys`), reporting unverified on-chain hashes honestly as `settlement_claimed_not_checked` without touching RPC.
- **Live verification (`POST /v1/receipt/verify-live`)** is operated as a free, rate-limited public reference utility (and is 100% MIT self-hostable via `runtime/receipt-verifier/server.mjs`). It verifies canonical Base (`eip155:8453`) and Base Sepolia (`eip155:84532`) USDC `Transfer` logs on-chain via multi-RPC failover and issues an Ed25519 counter-attestation, without inspecting internal facilitator databases or off-chain archives.
- Earlier Ethereum sync-committee (`k-luecke/bls-verifier`) and Merkle-Patricia (`k-luecke/paxiom`) substrate prototypes remain documented in [`journal.html`](https://paxiom.org/journal.html).

## License

MIT — see [`LICENSE`](LICENSE).
