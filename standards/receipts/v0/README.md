# Paxiom Receipt v0 (`@paxiom/receipts` `v0.3.0` & `paxiom-receipts` `v0.3.0`)

**License:** MIT · **Status:** Open protocol specification, conformance vectors, zero-dependency Node.js, Cloudflare Workers / WebCrypto (`@paxiom/receipts/web`), & Python SDKs, and free public reference verifier (`https://api.paxiom.org`).

> **x402 proves a payment. Paxiom proves what the payment bought.**

A **`paxiom.receipt.v0` delivery receipt** binds **HTTP request, `x402` payment terms, settlement claim, and delivered response payload** into a single Ed25519-signed envelope carried in `Payment-Receipt` (and `X-Paxiom-Receipt`). It is **100% open, free, and vendor-neutral**: any `x402` resource server on Base, EVM, or Solana can mint receipts offline with zero dependencies, and any buyer wallet or agent router can verify them with only a public key.

See [`x402-delivery-receipt-extension.md`](./x402-delivery-receipt-extension.md) for the formal **`x402` v2 `delivery-receipt` extension specification**.

## What's New in `v0.3.0`

- **Two-Gate Buyer Policy Firewall & `AuthCaptureEscrow` Arbiter (`@paxiom/receipts/guard` & Python `paxiom_receipts.guard`):**
  - **Gate 1 (`evaluatePreSignPolicy`):** Evaluates `402 Payment Required` challenges *before* invoking any wallet signer — enforcing HTTPS transport, origin allow/deny lists, reservation-safe `BigInt` atomic caps (`maxPerCallAtomic`, `maxPerOriginWindowAtomic`, `maxSessionAtomic`), `payTo` pinning, automatic upgrade from irreversible `exact` above `maxUnescrowedExactAtomic` to Coinbase `AuthCaptureEscrow` (`auth-capture`), and strict `PaymentInfo` (`operator`, `maxFeeBps`, `authorizationExpiry`) bounds.
  - **Gate 2 (`evaluateDeliveryArbiter` & `createGuardedFetch`):** Gates escrow `CAPTURE` vs. `VOID` on HTTP 2xx bounds, Ed25519 `Payment-Receipt` verification, request/query/body & payment anti-replay binding, and caller `validateContent()` predicates — emitting a non-repudiable `FraudEvidenceRecord` under the seller's `keyId` when signed bogus content is rejected and tripping a per-origin circuit breaker.
  - Zero `node:*` imports and zero `Buffer` tokens — runs identically in Node.js `>=18`, Cloudflare Workers, Deno, Bun, and browsers.

## What's New in `v0.2.1`

- **Pure WebCrypto / Cloudflare Workers / Browser Subpath (`@paxiom/receipts/web`):** Zero `node:*` imports (`node:crypto`, `node:fs`) and zero `Buffer` references anywhere in its module graph or `.d.ts` declarations (`src/web.d.ts`). Uses only standard `globalThis.crypto.subtle` (`Ed25519` + `SHA-256`), `Uint8Array`, `TextEncoder`/`TextDecoder`, and `fetch` — bundles directly into Cloudflare Workers without `nodejs_compat` or `@types/node`, Vercel Edge, Deno Deploy, and browsers while remaining 100% byte-identical with Node and Python PKCS#8 PEM keys and signatures.
- **W3C `did:web` Discovery (`/.well-known/did.json`):** `discoverIssuerKeys()` resolves Ed25519 `JsonWebKey2020` verification methods per `x402` `offer-receipt` §4.5.1 alongside `/.well-known/x402-keys.json` and `/.well-known/paxiom-keys.json`.

## What's New in `v0.2.0`

- **Vendor-neutral `Payment-Receipt` header + settlement fields:** Middleware and verifiers emit and inspect `Payment-Receipt` alongside `X-Paxiom-Receipt`, and use vendor-neutral `settlement.checkedByVerifier` + `trustedVerifierPublicKeys` (while preserving 100% backward compatibility with `v0.1.x` `checkedByPaxiom` fixtures).
- **Signer authorization (`unauthorized_issuer`) & `/.well-known/x402-keys.json` discovery:** `discoverIssuerKeys()` / `discover_issuer_keys()` fetches a seller's published Ed25519 keys, and `verifyReceipt()` / `verify_receipt()` enforces `expectedIssuerPublicKeys` and `expectedPayTo` so spoofed keys never pass as `verified`.
- **Dual `jcs-sha256` + `raw-sha256` payload hashing:** Automatically canonicalizes JSON responses via RFC 8785 JCS and hashes Markdown, plain text, CSV, images, PDFs, and binary responses (`<= 256 KiB`) via `raw-sha256` alongside `delivery.statusCode`.
- **Native `x402` v2 header auto-parsing & Solana + CAIP-2 support:** Seller middleware decodes `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`, and `PAYMENT-REQUIRED` automatically to bind CAIP-2 `network` (`eip155:8453`, `solana:...`), `amountAtomic`, `payer`, `payTo`, and EVM `0x` or Solana base58 `transactionHash`.
- **100% Free Public Reference Endpoints (`https://api.paxiom.org`):** Offline verification (`/v1/receipt/verify`), pre-payment seller safety preflight (`/v1/x402/preflight`), and live Base/Base-Sepolia USDC on-chain settlement counter-attestation (`/v1/receipt/verify-live`) are all **free, rate-limited public reference utilities** — no API keys or micropayment paywalls required.

## Install & Quick Start

```bash
# Node.js / TypeScript / Edge (zero dependencies, MIT):
npm install @paxiom/receipts

# Python 3.10+ / FastAPI / ASGI (zero dependencies, MIT):
pip install paxiom-receipts
```

```js
import {
  generateReceiptKeyPair,
  withPaxiomReceipt,
  discoverIssuerKeys,
  verifyResponseReceipt,
  preflightX402,
  verifyReceiptLive
} from '@paxiom/receipts';
```

- **CLI (zero install):** `npx @paxiom/receipts --help`
- **MCP stdio server:** `npx -y --package=@paxiom/receipts paxiom-receipt-mcp`
- **Free Public Reference API (`https://api.paxiom.org`):**
  - `GET https://api.paxiom.org/.well-known/x402-keys.json` — published verifier Ed25519 keys
  - `POST https://api.paxiom.org/v1/receipt/verify` — free offline verification
  - `POST https://api.paxiom.org/v1/x402/preflight` — free rate-limited pre-payment `x402` seller readiness & canonical Circle USDC check
  - `POST https://api.paxiom.org/v1/receipt/verify-live` — free rate-limited Base / Base Sepolia USDC `Transfer` log verification + Ed25519 counter-attestation

## Seller Middleware (`withPaxiomReceipt` & `createReceiptMiddleware`)

Wrap any Fetch handler (`Cloudflare Workers`, `Next.js`, `Hono`, `Bun`, `Deno`) or Express / Node `http.Server` route. The middleware auto-parses `x402` v2 `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers, hashes JSON (`jcs-sha256`) or non-JSON (`raw-sha256`) payloads, and attaches both `Payment-Receipt` and `X-Paxiom-Receipt`:

```js
import { generateReceiptKeyPair, withPaxiomReceipt } from '@paxiom/receipts';

const keys = generateReceiptKeyPair({ keyId: 'seller-key-01' });

export const POST = withPaxiomReceipt(
  async () => Response.json({ forecast: 'sunny', tempC: 23 }),
  {
    privateKey: keys.privateKeyPem,
    issuer: {
      name: 'weather-seller',
      uri: 'https://seller.example',
      keyId: keys.keyId,
      payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
      keysUri: 'https://seller.example/.well-known/x402-keys.json'
    },
    serviceName: 'Weather Forecast API'
  }
);
```

### Pure Cloudflare Workers / Edge / Browser (`@paxiom/receipts/web`)

For Workers or Edge projects compiled with `@cloudflare/workers-types` (`lib: ["ES2022", "WebWorker"]`) and **no `nodejs_compat` or `@types/node`**, import from `@paxiom/receipts/web`:

```ts
import {
  withPaxiomReceipt,
  issueReceipt,
  verifyReceipt,
  publicKeyFromPrivateKey
} from '@paxiom/receipts/web';

export default {
  async fetch(request: Request, env: { PAXIOM_PRIVATE_KEY_PEM: string }): Promise<Response> {
    const handler = withPaxiomReceipt(
      async () => Response.json({ ok: true }),
      {
        privateKey: env.PAXIOM_PRIVATE_KEY_PEM,
        issuer: { name: 'edge-seller', keyId: 'edge-1' }
      }
    );
    return handler(request);
  }
};
```

## Buyer Verification & Signer Authorization

```js
import {
  discoverIssuerKeys,
  verifyResponseReceipt,
  preflightX402,
  verifyReceiptLive
} from '@paxiom/receipts';

// 1. Free pre-payment seller safety scan (catches non-Circle USDC spoofing & payTo bait-and-switch):
const scan = await preflightX402('https://seller.example/v1/query', {
  maxBudgetAtomic: '10000',
  expectedNetwork: 'eip155:8453'
});
if (scan.verdict === 'block') throw new Error('Unsafe x402 quote');

// 2. Discover seller's pinned Ed25519 keys from /.well-known/x402-keys.json:
const keyDoc = await discoverIssuerKeys('https://seller.example');

// 3. Verify Payment-Receipt / X-Paxiom-Receipt offline with signer + payTo authorization:
const delivery = verifyResponseReceipt(paidResponse, {
  output: parsedBody,
  expectedIssuerPublicKeys: keyDoc.ok ? keyDoc.publicKeys : undefined,
  expectedPayTo: scan.report?.selectedQuote?.payTo
});

// 4. Optional free on-chain Base USDC Transfer confirmation + counter-attestation:
if (delivery.trustState === 'settlement_claimed_not_checked') {
  const live = await verifyReceiptLive(delivery.receipt, {
    output: parsedBody,
    expectedPayTo: scan.report?.selectedQuote?.payTo
  });
}
```

## Conformance & Self-Tests

```bash
# Validate JSON Schema + cryptographic test vectors:
npm --prefix standards/receipts/v0 run validate

# Run Node.js SDK, CLI, HTTP server, and MCP unit tests:
npm --prefix standards/receipts/v0 test

# Run Python 3.10+ zero-dependency SDK + Node<->Python cross-language tests:
python3 -m unittest discover -s standards/receipts/v0/python/tests -v
```
