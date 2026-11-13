# Listing copy — Paxiom Receipt Verifier

Ready-to-paste copy for x402 Bazaar / awesome-x402 / MCP-registry style listings.

> **Readiness boundary (read first).** The public HTTP verifier is live at
> `https://api.paxiom.org` (free offline verification at `POST /v1/receipt/verify`), and
> the stdio MCP server ships at `standards/receipts/v0/mcp/server.mjs`. Directory
> submissions for free API / MCP / open-spec registries can use `https://api.paxiom.org`
> today. For **x402 Bazaar** specifically, enable `LIVE_VERIFY_ENABLED=true` +
> `X402_ENABLED=true` on `POST /v1/receipt/verify-live` and complete at least one
> settled facilitator transaction before claiming Bazaar indexing.

## Listing name
```
Paxiom Receipt Verifier
```

## Short description (Bazaar-ready, <500 chars)
```
Verify proof-bound receipts for x402-paid APIs. Paxiom checks receipt schema, Ed25519 signature, request/output binding, and settlement status, and reports optional evidence fields — so agents and developers can understand what was paid for and delivered. Developer preview: offline verification. v0 reports settlement honestly (claimed vs checked) and does not yet perform onchain settlement or proof-source verification.
```
(Character count is under 500; trim the last sentence first if a stricter cap applies.)

## Tags
```
x402
receipt
verification
proof
agent
settlement
audit
MCP
```

## Category (pick per directory)
```
Developer Tools
Security
Verification
```

## What the verifier checks (v0)
- receipt structure (schema conformance)
- Ed25519 signature over the canonical signing input
- output binding — delivered output hash vs `delivery.outputHash`
- presence of request and payment binding fields
- explicit, honest settlement status and evidence status → one deterministic trust state

## What v0 does NOT verify
- onchain settlement (reported as `claimed_not_checked` / `verify_only`, never independently confirmed)
- x402 facilitator responses
- proof-source / evidence archive availability or validity
- foreign (non-Paxiom) receipt dialects

Claim boundary, stated plainly:
```
v0 verifies receipt integrity and output binding.
v0 reports settlement and evidence status honestly.
v0 does NOT independently check onchain settlement or proof-source evidence.
Schema-valid is not receipt-verified.
```

## Example request / response
Request (`POST /v1/receipt/verify`):
```json
{ "receipt": { "receiptVersion": "paxiom.receipt.v0", "payload": { }, "signature": { } }, "output": { } }
```
Response (verified):
```json
{ "valid": true, "trustState": "verified", "checks": { "schema": "pass", "signature": "pass", "outputHash": "pass", "settlement": "verify_only", "proof": "not_provided" }, "receiptHash": "0x…", "summary": "Receipt verified: …" }
```

## Links to include in a listing
- Live API: `https://api.paxiom.org` (`GET /version`, `GET /v1/receipt/demo`, `POST /v1/receipt/verify`)
- API docs: `https://paxiom.org/api.html`
- Spec & SDK: `https://paxiom.org/standards/receipts/v0/README.md`
- OpenAPI: `https://paxiom.org/standards/receipts/v0/openapi.json`
- Trust states: `https://paxiom.org/standards/receipts/v0/trust-states.md`
- MCP server (stdio): `standards/receipts/v0/mcp/server.mjs` (`verify_receipt`, `explain_receipt`, `issue_receipt`)
- Repo: `https://github.com/k-luecke/paxiom-static`
- Status: developer preview / alpha — **not** production standard

## Future listing language (only after a public x402-settling runtime exists)
```
Once the endpoint is x402-gated and successfully settled through the facilitator,
this route can be listed in the x402 Bazaar as a live x402 resource. Until then it
is a public, free, offline receipt verifier and an open receipt specification.
```
