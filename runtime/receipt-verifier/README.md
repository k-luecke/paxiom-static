# paxiom-receipt-verifier — public runtime (developer preview)

Deployable HTTP surface for the **free, offline** Paxiom Receipt Verifier. It wraps
the spec repo's verifier core (`standards/receipts/v0/src/verify.mjs`) — the single
source of truth for verification logic — and adds nothing to the semantics.

**Free developer-preview runtime.**
- No onchain settlement verification.
- No proof-source verification.
- No x402 gating (verification is free).
- Bazaar eligibility requires a later x402-settling route and at least one
  successful settlement — that is a separate phase, not this runtime.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | liveness — `{ ok: true, ... }` |
| GET | `/version` | service identity + explicit `checks` / `notChecked` claim boundaries |
| GET | `/v1/receipt/demo` | canonical demo receipt + output |
| POST | `/v1/receipt/verify` | `{ receipt, output? }` → verifier result JSON |

Status codes: `200` for any verification result (including non-verified), `400`
malformed request, `413` body > 256 KiB, `404` unknown route, `500` verifier error.
CORS `*`. Structured JSON errors.

## Run locally

```bash
node runtime/receipt-verifier/server.mjs      # PORT=8787 default
curl localhost:8787/health
curl localhost:8787/version
curl localhost:8787/v1/receipt/demo
```

Test:

```bash
node --test runtime/receipt-verifier/test/     # 8 smoke tests
```

## Abuse controls (v0)

Body cap 256 KiB · JSON only · methods restricted · no file writes · no env secrets
required · no chain calls · **does not log full receipt payloads**. No auth, no
database, no archive in v0.

## Deploying publicly

See [`docs/runtime-deployment.md`](../../docs/runtime-deployment.md) for the
Render / Vercel / Cloudflare comparison and exact steps. Key constraint: this
runtime imports the verifier core from `../../standards/`, so a deploy must include
the whole repo (not just this subdirectory). Recommended first deploy: **Render**
(a normal long-running Node server — no serverless adaptation of the existing
`http.createServer` needed).

## Module surface

`server.mjs` exports:
- `handle(req, res)` — the core request handler (serverless-friendly; also the default export)
- `createServer()` — an `http.Server` for long-running hosts
- `default` — `handle`, for platforms that expect `export default (req,res)=>…`
