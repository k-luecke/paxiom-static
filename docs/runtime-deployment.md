# Runtime deployment — Paxiom Receipt Verifier (Phase 5D)

Goal: get the **free, offline** verifier running at a public URL such as:

```
https://api.paxiom.org/health
https://api.paxiom.org/version
https://api.paxiom.org/v1/receipt/demo
https://api.paxiom.org/v1/receipt/verify
```

This phase deploys a **public but free/offline-semantics** service. It does **not**
add x402 gating, chain calls, or settlement checks — that is Phase 5E.

## The one packaging constraint

`runtime/receipt-verifier/server.mjs` imports the verifier core from
`../../standards/receipts/v0/src/verify.mjs` (single source of truth). It also reads
the demo fixtures from `../../standards/receipts/v0/examples/`. **Therefore a deploy
must include the whole repository**, not just the `runtime/receipt-verifier/`
subdirectory. Both platforms below check out the full repo, so this is fine — but
it is the thing that breaks if you try to upload only the subfolder.

## Option comparison

| Option | Fit for first deploy | Why |
|--------|----------------------|-----|
| **Render (Web Service)** | **Recommended first** | Our code is already a normal long-running `http.createServer`. Render runs it as-is with a start command — no serverless adaptation. |
| **Vercel (Node function)** | Good alternative | Lowest-friction managed API + preview deploys, and the Node runtime supports the crypto APIs we use. But our server must be wrapped as a serverless function (a catch-all), which is extra packaging. |
| Fly.io | Later | More infra control (Dockerfile, regions) than we need now. |
| Cloudflare Workers | Later | Not a normal Node server; needs porting to a `fetch` handler and crypto-compat testing under `nodejs_compat`. |

**Recommendation:** deploy to **Render first** because the existing server needs
zero code changes. Move to Vercel or a custom domain once the smoke tests pass.

---

## A. Render (recommended first deploy)

1. Push this branch and merge to `main` (or point Render at the branch).
2. Render dashboard → **New → Web Service** → connect the `paxiom-static` repo.
3. Settings:
   - **Environment:** Node
   - **Root Directory:** `runtime/receipt-verifier`
   - **Build Command:** `npm install`  (there are no dependencies; this is a no-op that satisfies the builder)
   - **Start Command:** `npm start`  (→ `node server.mjs`)
   - **Instance type:** the smallest is fine for a stateless verifier.
   - No environment variables. No secrets. No disk.
4. Deploy. Render gives a URL like `https://paxiom-receipt-verifier.onrender.com`.
5. Smoke test the live URL (see “Post-deploy smoke” below).

> Render checks out the full repo, so `server.mjs`'s `../../standards/...` import
> resolves even with Root Directory set to the subfolder. If a future Render change
> ever restricts the checkout to the root directory only, fall back to **Root
> Directory = repo root**, Start Command `node runtime/receipt-verifier/server.mjs`
> (you may then need a minimal root `package.json` for Node detection).

Note: on Render's free tier the service idles after inactivity and cold-starts on
the next request (a few seconds). Acceptable for a developer preview.

---

## B. Vercel (alternative)

Vercel's Node runtime supports our crypto usage, but it invokes a serverless
function per request rather than running a long-lived server. Wrap the exported
handler in a catch-all function:

1. Add `api/[[...path]].mjs` at the repo root:
   ```js
   export { default } from '../runtime/receipt-verifier/server.mjs';
   ```
   (`server.mjs`'s default export is the `(req, res)` handler, which routes
   internally by `req.url`.)
2. Add `vercel.json` at the repo root to route everything to it:
   ```json
   { "rewrites": [{ "source": "/(.*)", "destination": "/api/$1" }] }
   ```
3. Import Project in Vercel → **Root Directory: repo root** (so `standards/` is
   bundled) → deploy. URL like `https://paxiom-receipt-verifier.vercel.app`.

Watch-outs: serverless cold starts; ensure the function bundler includes the
imported `standards/` files (root-dir = repo root handles this); request/body limits.

> This repo currently has no `api/` or `vercel.json`; they are intentionally NOT
> committed while Render is the recommended path, to avoid unused platform config.
> Add them only if you choose Vercel.

---

## Custom domain (`api.paxiom.org`) — only after smoke tests pass

1. In the host (Render/Vercel), add the custom domain `api.paxiom.org`.
2. Create the DNS record it asks for (usually a CNAME to the platform host) at the
   `paxiom.org` DNS provider.
3. Wait for the managed TLS cert to issue, then re-run the smoke tests against
   `https://api.paxiom.org`.
4. Only then update `receipts.html` (the “Run the verifier” section) to add the
   public URL alongside the local commands.

## Post-deploy smoke

```bash
BASE=https://YOUR-DEPLOY-URL
curl -s $BASE/health
curl -s $BASE/version
curl -s $BASE/v1/receipt/demo > demo.json
node -e 'const d=JSON.parse(require("fs").readFileSync("demo.json"));process.stdout.write(JSON.stringify({receipt:d.receipt,output:d.output}))' \
  | curl -s -X POST $BASE/v1/receipt/verify -H 'content-type: application/json' --data @-
# expect: {"valid":true,"trustState":"verified",...}
```

## Keep the claim boundaries intact

The live service must keep saying, in `/version` and the README:

> Developer-preview reference verifier for `paxiom.receipt.v0`. Verifies receipt
> schema, Ed25519 signature, and output binding. Reports settlement and
> proof-evidence states but does NOT independently verify onchain settlement,
> facilitator records, or proof-source evidence in v0. Free — no x402 gating.

## What comes after (Phase 5E, not now)

x402 payment middleware + CDP facilitator config + a test `payTo` wallet + a tiny
price + one successful verify-and-settle + `paymentPayload.resource` set. Bazaar
indexing happens **after** a settlement, so 5E is the actual eligibility phase.
