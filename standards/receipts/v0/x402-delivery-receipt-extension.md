# Extension: Proof-Bound Delivery Receipts (`delivery-receipt`)

- **Extension Identifier:** `delivery-receipt`
- **Wire Envelope Version:** `paxiom.receipt.v0` (reference implementation `0.2.0`)
- **HTTP Response Header:** `Payment-Receipt` (compatibility alias: `X-Paxiom-Receipt`)
- **Signer Key Discovery:** `GET /.well-known/x402-keys.json` or W3C `did:web` (`GET /.well-known/did.json`)
- **License:** MIT (open specification, test vectors, TypeScript/Node.js & Python 3.10+ zero-dependency reference SDKs)

---

## 1. Motivation & Gap Analysis

The core `x402` v2 HTTP transport proves that a client authorized payment (`PAYMENT-SIGNATURE`) and that a facilitator or resource server accepted or settled it (`PAYMENT-RESPONSE`). However, `PAYMENT-RESPONSE` and existing offer/settlement receipt drafts bind only **payment terms and settlement metadata** — they do not bind **what HTTP request was executed** or **what response bytes were delivered in return**.

Without a cryptographic 4-way binding across **(1) request, (2) payment terms, (3) settlement claim, and (4) delivered output**, autonomous agents, wallets, and API routers cannot detect or audit:

1. **Bait-and-switch / truncated delivery:** A resource server settles an EIP-3009 or Solana transfer and returns an empty `{}`, stale cached error, or altered payload.
2. **Receipt replay across queries:** A seller replays a valid settlement receipt from an earlier call against a different request body or URL.
3. **Spoofed receipt signers:** An intermediary or untrusted proxy strips the seller's response and attaches a self-signed receipt under an unpinned ephemeral key.
4. **Silent JSON-only failure:** Paid endpoints returning Markdown, plain text, CSV, images, audio, or PDFs cannot use JSON-only canonicalization without either failing or omitting output hashes.
5. **Overstated settlement finality:** Offline verifiers cannot distinguish between a seller *claiming* a transaction hash settled and an independent verifier *confirming* the on-chain transfer log.

The `delivery-receipt` extension defines a compact, zero-dependency, chain-agnostic Ed25519 envelope that closes all five gaps in a single HTTP header.

---

## 2. Protocol Flow & Extension Negotiation

### 2.1 `402 Payment Required` Advertisement (Optional)

A resource server MAY advertise `delivery-receipt` support inside `PaymentRequired.extensions` on its `402` challenge or `/.well-known/x402.json` discovery document:

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "amount": "2000",
      "payTo": "0xSellerRecipientAddress..."
    }
  ],
  "extensions": {
    "delivery-receipt": {
      "info": {
        "receiptVersion": "paxiom.receipt.v0",
        "header": "Payment-Receipt",
        "keysUri": "https://seller.example/.well-known/x402-keys.json",
        "canonicalization": ["jcs-sha256", "raw-sha256"],
        "keyIds": ["seller-key-01"]
      }
    }
  }
}
```

### 2.2 Paid `2xx` Delivery Header (`Payment-Receipt`)

When returning the paid HTTP response, the resource server signs `{ receiptVersion, payload }` with its Ed25519 key, base64url-encodes the UTF-8 JSON receipt (RFC 4648 §5, unpadded), and emits:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Payment-Response: <base64 x402 SettleResponse>
Payment-Receipt: eyJyZWNlaXB0VmVyc2lvbiI6InBheGlvbS5yZWNlaXB0LnYwIiwicGF5bG9hZCI6e...
```

During transition, implementations SHOULD also emit `X-Paxiom-Receipt` with the identical value. If a response carries both `Payment-Receipt` and `X-Paxiom-Receipt` with differing values, a buyer verifier MUST reject the response (`malformed_header`) to prevent header-smuggling ambiguity.

---

## 3. Signer Key Discovery & Authorization (`/.well-known/x402-keys.json` & W3C `did:web`)

A valid Ed25519 signature over an embedded `signature.publicKey` proves integrity, **not** signer authorization. To prevent an untrusted party from minting receipts with an arbitrary keypair, resource servers SHOULD publish their active Ed25519 public keys over HTTPS at either `/.well-known/x402-keys.json` **or** a W3C `did:web` DID document at `/.well-known/did.json` (`JsonWebKey2020` `OKP` `Ed25519`, matching `coinbase/x402` `extension-offer-and-receipt.md` §4.5.1; fallback: `/.well-known/paxiom-keys.json`):

```json
{
  "version": "x402-keys.v1",
  "issuer": "https://seller.example",
  "payTo": "0xSellerRecipientAddress...",
  "keys": [
    {
      "keyId": "seller-key-01",
      "algorithm": "ed25519",
      "publicKey": "base64-32-byte-ed25519-pubkey=="
    }
  ]
}
```

Both `discoverIssuerKeys` (`@paxiom/receipts`) and `discover_issuer_keys` (`paxiom-receipts`) also resolve W3C `did:web` documents automatically by extracting `verificationMethod[].publicKeyJwk` (`kty: "OKP"`, `crv: "Ed25519"`, RFC 8037 base64url `x`) and normalizing the 32-byte key for deterministic offline verification.

Buyers and routers verify signer authorization via two orthogonal checks:
1. **Origin Key Pinning (`expectedIssuerPublicKeys`):** Fetch `https://<seller-origin>/.well-known/x402-keys.json` (with redirect blocking and size caps) and require `signature.publicKey` to match an active `ed25519` entry.
2. **Quote Recipient Binding (`expectedPayTo`):** Require `payload.payment.payTo` (or `payload.issuer.payTo`) to match the `payTo` address the buyer actually authorized in `PaymentRequirements` (case-insensitive for `0x` EVM hex; exact case-preserved match for Solana base58).

If the signature is valid but either authorization check fails, the verifier MUST return `trustState = "unauthorized_issuer"` (`valid: false`).

---

## 4. Canonicalization & Output Binding (`jcs-sha256` and `raw-sha256`)

### 4.1 Envelope Signing Input

The Ed25519 signature (`signature.value`, canonical 64-byte base64 with `S < L` low-order scalar enforcement per RFC 8032) is computed over the UTF-8 bytes of the deterministic RFC 8785 JCS canonical serialization of:

```json
{
  "payload": { "...": "..." },
  "receiptVersion": "paxiom.receipt.v0"
}
```

### 4.2 Dual Payload Hashing Modes (`delivery.canonicalization`)

| Mode | Target `Content-Type` | `delivery.outputHash` Preimage |
|------|-----------------------|--------------------------------|
| `jcs-sha256` *(default)* | `application/json`, `application/*+json` | `sha256( utf8( canonicalize(parsedJson) ) )` |
| `raw-sha256` | `text/markdown`, `text/plain`, `text/csv`, `image/*`, `application/pdf`, `application/octet-stream` | `sha256( exactDeliveredBodyBytes )` |

All digests are formatted as `0x` + 64 lowercase hex characters (`^0x[0-9a-f]{64}$`). `delivery.statusCode` (`100..599`) optionally binds the exact HTTP status code alongside `delivery.mimeType` and `delivery.outputHash`.

---

## 5. Multi-Chain & `x402` v2 Header Binding

`payload.payment` is chain-agnostic:
- `network`: CAIP-2 string (`eip155:8453`, `eip155:84532`, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, etc.).
- `payer` / `payTo`: Optional string identifiers supporting EVM `0x` addresses, Solana base58 pubkeys, or CAIP-10 account IDs.
- `settlement.transactionHash`: Nullable transaction identifier supporting both EVM 32-byte tx hashes (`^0x[0-9a-f]{64}$`, normalized lowercase) and Solana 64-byte Ed25519 transaction signatures (`^[1-9A-HJ-NP-Za-km-z]{64,88}$`, case-preserved).
- `paymentRequirementsHash`: `sha256( canonicalize(PaymentRequirements) )` decoded from `PAYMENT-REQUIRED` or `PAYMENT-SIGNATURE.accepted`.
- `paymentPayloadHash`: `sha256( canonicalize(PaymentPayload) )` decoded from `PAYMENT-SIGNATURE` (fallback `X-PAYMENT`).

---

## 6. Deterministic Non-Boolean Trust States

Offline verification MUST NOT collapse unverified on-chain claims into `valid: true`. Verifiers evaluate checks in strict precedence order and return `valid: trustState === "verified"`:

| Precedence | `trustState` | Meaning |
|------------|--------------|---------|
| 1 | `unsupported_format` | Unrecognized `receiptVersion`. |
| 2 | `schema_invalid` | Envelope violates JSON Schema (`additionalProperties: false`, strict bounds). |
| 3 | `invalid_signature` | Ed25519 signature invalid, malleable (`S >= L`), or `issuer.keyId != signature.keyId`. |
| 4 | `unauthorized_issuer` | Valid signature, but `signature.publicKey` or `payTo` does not match pinned seller expectations. |
| 5 | `expired` | `payload.expiresAt` is in the past. |
| 6–7 | `request_binding_missing` / `payment_binding_missing` | Missing request or payment digest bindings. |
| 8 | `output_hash_mismatch` | Delivered payload digest does not match `delivery.outputHash`. |
| 9 | `settlement_failed` | `settlement.status === "failed"`. |
| 10 | `proof_invalid` / `proof_unavailable` | Attached execution evidence failed or could not be retrieved. |
| 11 | `settlement_claimed_not_checked` | Signature and output hash pass, **but** the receipt claims an on-chain settlement (`claimed_not_checked`, non-null `transactionHash` under `verify_only`, or `verified_settled` without a signature from a key in `trustedVerifierPublicKeys`). |
| 12 | `valid_signature_only` | Signature valid, but caller did not supply `output` or `settlement.status === "unknown"`. |
| 13 | `verified` | Schema, signature, optional signer authorization, output hash binding, and settlement rules all pass. |

When an independent verifier confirms the on-chain transfer log (e.g., via JSON-RPC receipt & ERC-20 `Transfer` / SPL Token inspection), it counter-signs a receipt setting `settlement.status = "verified_settled"` and `settlement.checkedByVerifier = true` (with its public key published at `/.well-known/x402-keys.json`).

---

## 7. Composition & Interoperability with `offer-receipt` (`v0.6`) and `settlement-attestation-receipt`

`delivery-receipt` is designed to compose directly with upstream `coinbase/x402` extension drafts rather than duplicate them:

1. **Relationship to `extension-offer-and-receipt.md` (`v0.6`):**
   - `offer-receipt` binds pre-payment commercial terms (`Offer`) and post-settlement payment acknowledgment (`Receipt: { version, network, resourceUrl, payer, issuedAt, transaction }`). It intentionally omits request-input and response-output digests for privacy-minimal review attestations.
   - `delivery-receipt` shares W3C `did:web` (`/.well-known/did.json` `JsonWebKey2020` `Ed25519`) signer discovery with `offer-receipt` §4.5.1 while adding the 4-way execution commitment (`request` + `payment` + `settlement` + `delivery.outputHash`) needed for machine-verifiable payload delivery.
2. **HTTP Middleware Ordering (`PAYMENT-RESPONSE` vs. Post-Handler `Payment-Receipt`):**
   - In standard `x402` HTTP middlewares (`@x402/express`, `@x402/fetch`, FastAPI ASGI), `PAYMENT-RESPONSE` (`SettlementResponse`) is constructed at payment-settlement time *before* the route handler finishes serializing the `2xx` HTTP response body. Carrying `outputHash` inside `PAYMENT-RESPONSE` requires delaying settlement or rewriting facilitator headers post-handler.
   - Emitting a dedicated post-handler `Payment-Receipt` HTTP header allows non-invasive response-wrapping middleware (`withPaxiomReceipt`, `createReceiptMiddleware`, `PaxiomReceiptMiddleware`) to hash the exact `2xx` body without altering facilitator settlement plumbing.
3. **Request-Input Binding (`request.requestHash` / `bodyHash`):**
   - Binding only `(resourceUrl, outputHash)` leaves parameterized `POST` endpoints (e.g., `POST /v1/infer`) open to cross-prompt cache substitution where a server returns a valid `outputHash` computed over a cheaper or cached prompt's output. `payload.request` commits to method, canonical URL, and request body hash.
4. **Explicit Preimage Disambiguation (`jcs-sha256` vs. `raw-sha256`):**
   - SDK callers and MCP tools typically inspect parsed JSON (`res.json()`), where wire whitespace has already been discarded, whereas binary/Markdown/streaming consumers — or JSON payloads containing integers outside IEEE-754 `2^53 - 1` — require exact wire-byte hashing. Explicit `delivery.canonicalization` (`"jcs-sha256" | "raw-sha256"`) prevents silent cross-implementation hash forks.
5. **Cross-SDK Reproducible Test Vector (`examples/valid.receipt.json` + `examples/valid.output.json`):**
   - Input JSON (`examples/valid.output.json`): `{"demo":true,"message":"Paxiom receipt demo output. This is the bytes the payment bought.","service":"Paxiom Receipt Demo","value":"42"}`
   - `jcs-sha256` digest: `0x36b33b7db29c8eacf3acc6bbff312ebbeabbaf53b70b956b5fc02d2c1281baf6`
   - Ed25519 public key (`paxiom-demo-key-001`): `cZASqM+TIUtIt4+ejhPvIOYxOeDBX/ofbG86H/NNLpQ=`
   - Ed25519 signature over RFC 8785 JCS `{ payload, receiptVersion }`: `P/1YDKMwtFmODNZ8p449sdpRdOJILW2Yc07lSInDu8+jMWdsdS8c+om/RTQnXvy0t9tdHmGcqimX/Wu4Nan9Cw==`

---

## 8. Reference Implementations & Conformance Vectors

- **JSON Schema:** [`paxiom.receipt.v0.schema.json`](./paxiom.receipt.v0.schema.json)
- **Canonicalization Rules:** [`canonicalization.md`](./canonicalization.md)
- **Trust State Precedence:** [`trust-states.md`](./trust-states.md)
- **Reproducible Cryptographic Fixtures:** [`examples/`](./examples/) (`valid.receipt.json`, `valid.output.json`, `output-mismatch.output.json`, `settlement-claimed-not-checked.receipt.json`)
- **TypeScript / Node.js / Fetch / Express SDK (zero dependencies, MIT):** `@paxiom/receipts` (`standards/receipts/v0/src/`)
- **Python 3.10+ / FastAPI / ASGI SDK (zero dependencies, MIT):** `paxiom-receipts` (`standards/receipts/v0/python/`)
- **Live Free Public Reference Verifier & `did:web` Endpoint:** `https://api.paxiom.org` (`GET /.well-known/did.json`, `GET /.well-known/x402-keys.json`)
