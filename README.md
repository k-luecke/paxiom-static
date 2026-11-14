# Paxiom — Proof-of-Delivery Receipts & Verifier (`paxiom.receipt.v0`)

[![npm](https://img.shields.io/npm/v/@paxiom/receipts)](https://www.npmjs.com/package/@paxiom/receipts)
[![PyPI](https://img.shields.io/pypi/v/paxiom-receipts)](https://pypi.org/project/paxiom-receipts/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **x402 proves a payment. Paxiom proves what the payment bought.**

Public specification, zero-dependency TypeScript/Node & Python SDKs, MCP servers, live Base Mainnet x402 verification runtime (`https://api.paxiom.org`), and static site (`https://paxiom.org`) developed by **Driftbound Labs** (`https://driftboundlabs.com`).

## Shipped Packages & Live Endpoints (`v0.1.3`)

| Surface | Location | Install / Endpoint |
|---|---|---|
| **TypeScript / Node SDK & CLI** | [`standards/receipts/v0/`](standards/receipts/v0/) | `npm install @paxiom/receipts` |
| **Python SDK & CLI** | [`standards/receipts/v0/python/`](standards/receipts/v0/python/) | `pip install paxiom-receipts` |
| **MCP Server (Official Registry)** | `io.github.k-luecke/paxiom-receipts` | `npx -y --package=@paxiom/receipts paxiom-receipt-mcp` or `https://api.paxiom.org/mcp` |
| **Free Offline Verifier** | `https://api.paxiom.org/v1/receipt/verify` | `$0` · deterministic schema, Ed25519 signature, & JCS `SHA-256(output)` binding |
| **Live Base Settlement Verifier** | `https://api.paxiom.org/v1/receipt/verify-live` | `$0.002` USDC via x402 · verifies Base/Base-Sepolia USDC `Transfer` logs + Paxiom counter-attestation |
| **x402 Seller Preflight Scanner** | `https://api.paxiom.org/v1/x402/preflight` | `$0.01` USDC via x402 · SSRF-hardened pre-payment quote, asset, & receipt-readiness check |
| **Documentation & Spec Site** | [`https://paxiom.org`](https://paxiom.org) | [`receipts.html`](https://paxiom.org/receipts.html) · [`api.html`](https://paxiom.org/api.html) · [`llms.txt`](https://paxiom.org/llms.txt) |

## Quick Verification

```bash
# Node SDK & Cross-Language Test Vectors
cd standards/receipts/v0 && npm test

# Python SDK
cd standards/receipts/v0/python && pytest

# Live Receipt Verifier & x402 Runtime Suite
cd runtime/receipt-verifier && npm test
```

## Explicit Boundaries (What `v0` Does Not Claim)

- **Offline verification (`verifyReceipt` / `POST /v1/receipt/verify`)** verifies schema conformance, deterministic RFC 8785 canonical JSON hashing, and Ed25519 signatures, and reports unverified settlement assertions honestly as `claimed_not_checked` without touching RPC.
- **Live verification (`POST /v1/receipt/verify-live`)** verifies canonical Base and Base Sepolia USDC `Transfer` logs on-chain via multi-RPC consensus and issues a Paxiom Ed25519 counter-attestation, but does not inspect off-chain facilitator databases or non-Paxiom receipt dialects.
- Earlier Ethereum sync-committee (`k-luecke/bls-verifier`) and Merkle-Patricia (`k-luecke/paxiom`) substrate prototypes remain documented in [`journal.html`](https://paxiom.org/journal.html).

## License

MIT — see [`LICENSE`](LICENSE).
