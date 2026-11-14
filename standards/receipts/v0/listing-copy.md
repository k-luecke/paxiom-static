# Listing copy — Paxiom Receipt Verifier

Ready-to-paste copy for x402 Bazaar, `awesome-x402`, and MCP server registries.

> **Live production status.** Both routes are live at `https://api.paxiom.org`:
> - **Free offline verification:** `POST https://api.paxiom.org/v1/receipt/verify` (`$0`, zero network calls)
> - **Live x402 on-chain settlement verification + Paxiom counter-attestation:** `POST https://api.paxiom.org/v1/receipt/verify-live` (`$0.002` USDC on Base Mainnet via x402 or `X-API-Key`, discoverable at `https://api.paxiom.org/.well-known/x402.json` and public keys at `https://api.paxiom.org/.well-known/paxiom-keys.json`)
> - **Local stdio MCP server:** `@paxiom/receipts` (`standards/receipts/v0/mcp/server.mjs`)

## Listing name
```
Paxiom Receipt Verifier
```

## Short description (Bazaar & directory ready, <500 chars)
```
Proof-bound Ed25519 receipts and on-chain USDC settlement verification for x402 and agentic APIs. Sellers attach free X-Paxiom-Receipt headers binding request, payment txHash, and SHA-256(output). Buyers verify offline for free (/v1/receipt/verify) or verify live Base/Base-Sepolia USDC settlement + receive a Paxiom Ed25519 counter-attestation via x402 (/v1/receipt/verify-live, $0.002 USDC).
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
MCP
```

## Category (pick per directory)
```
Developer Tools
Security
Verification
Payments Infrastructure
```

## What the verifier checks
- **Free route (`POST /v1/receipt/verify`):**
  - `paxiom.receipt.v0` schema conformance
  - Ed25519 signature over deterministic RFC 8785-style canonical JSON
  - Output binding (`SHA-256(canonical(output)) == delivery.outputHash`)
  - Request & payment binding fields + honest settlement/evidence trust states
- **Paid x402 / API-key route (`POST /v1/receipt/verify-live`):**
  - Everything in offline verification, **plus** live Base / Base Sepolia JSON-RPC verification of the claimed USDC `Transfer` log (`status == 0x1`, confirmations, canonical USDC contract, recipient, and atomic amount)
  - Emits a counter-signed `X-Paxiom-Receipt` verifiable offline against `https://api.paxiom.org/.well-known/paxiom-keys.json`

## What v0 does NOT claim
```
Offline verify (/v1/receipt/verify) reports claimed_not_checked honestly without touching RPC.
Live verify (/v1/receipt/verify-live) verifies canonical Base & Base Sepolia USDC Transfer logs on-chain,
but does not inspect off-chain proof archives or non-Paxiom receipt dialects.
```

## Example request / response
Free offline request (`POST https://api.paxiom.org/v1/receipt/verify`):
```json
{ "receipt": { "receiptVersion": "paxiom.receipt.v0", "payload": {}, "signature": {} }, "output": {} }
```
Live on-chain verification (`POST https://api.paxiom.org/v1/receipt/verify-live` with x402 `PAYMENT-SIGNATURE` or `X-API-Key`):
```json
{
  "valid": true,
  "trustState": "verified",
  "checks": { "schema": "pass", "signature": "pass", "outputHash": "pass", "settlement": "verified_settled", "proof": "not_provided" },
  "onchainSettlement": { "checked": true, "settled": true, "network": "eip155:8453", "transactionHash": "0x..." },
  "counterAttestedReceipt": { "receiptVersion": "paxiom.receipt.v0", "payload": {}, "signature": {} }
}
```

## Links to include in a listing
- Live API: `https://api.paxiom.org` (`GET /version`, `GET /v1/receipt/demo`, `POST /v1/receipt/verify`, `POST /v1/receipt/verify-live`)
- x402 Discovery: `https://api.paxiom.org/.well-known/x402.json`
- Verifier Public Keys: `https://api.paxiom.org/.well-known/paxiom-keys.json`
- API Docs: `https://paxiom.org/api.html`
- Spec & SDK (`@paxiom/receipts`): `https://paxiom.org/standards/receipts/v0/README.md`
- OpenAPI: `https://paxiom.org/standards/receipts/v0/openapi.json`
- Trust States: `https://paxiom.org/standards/receipts/v0/trust-states.md`
- MCP Server (stdio): `standards/receipts/v0/mcp/server.mjs` (`verify_receipt`, `explain_receipt`, `issue_receipt`)
- Repo: `https://github.com/k-luecke/paxiom-static`
