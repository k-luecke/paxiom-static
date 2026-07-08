# Paxiom Receipt v0 — HTTP verifier (developer preview)

A minimal HTTP wrapper around the offline `verifyReceipt()` core. **Free**
developer-preview endpoint: no x402 payment gating, no chain or facilitator calls.
It is a thin transport over the CLI's verifier — same trust states, same result
shape. Node built-ins only.

## Run

```bash
node standards/receipts/v0/server/server.mjs        # PORT=8787 by default
PORT=9000 node standards/receipts/v0/server/server.mjs
```

## Endpoints

### `GET /health`
```json
{ "ok": true, "service": "paxiom-receipt-verifier", "version": "v0" }
```

### `GET /v1/receipt/demo`
Returns the canonical demo `receipt` + `output` fixtures and a hint showing how to
POST them back to `/v1/receipt/verify`.

### `POST /v1/receipt/verify`
Request body: `{ "receipt": { … }, "output": { … } }` (`output` optional).
Returns the verifier result JSON (same shape as the CLI):
```json
{ "valid": true, "trustState": "verified", "checks": { … }, "receiptHash": "0x…", "summary": "…" }
```

## Status codes

| Code | When |
|------|------|
| `200` | Any normal verification result — **including non-`verified` receipts** (e.g. `output_hash_mismatch`). A verification that ran is a success at the transport layer. |
| `400` | Malformed request: invalid JSON, or missing `receipt` field. |
| `413` | Request body exceeds **256 KiB**. Receipts are small; hash large output/proof material locally and reference it. |
| `404` | Unknown route. |
| `500` | Verifier internal error. |

Structured error shape:
```json
{ "valid": false, "trustState": "error", "error": { "code": "body_too_large", "message": "Request body exceeds 256 KiB" } }
```

CORS: `Access-Control-Allow-Origin: *` (developer-preview usability).

## Example

```bash
node standards/receipts/v0/server/server.mjs &
curl -s localhost:8787/health
curl -s localhost:8787/v1/receipt/demo
# round-trip the demo fixtures through the verifier:
curl -s localhost:8787/v1/receipt/demo \
  | node -e 'const d=JSON.parse(require("fs").readFileSync(0));process.stdout.write(JSON.stringify({receipt:d.receipt,output:d.output}))' \
  | curl -s -X POST localhost:8787/v1/receipt/verify -H 'content-type: application/json' --data @-
```

## Test

```bash
node --test standards/receipts/v0/server/server.test.mjs
```

## Scope / non-goals (v0)

No x402 gating, no onchain settlement check, no facilitator calls, no evidence
fetching, no persistence, no auth. Those are later, deliberately separate steps.

> This repo has no root `package.json` (it is a static site), so there are no npm
> scripts. Run the commands above directly with `node`.
