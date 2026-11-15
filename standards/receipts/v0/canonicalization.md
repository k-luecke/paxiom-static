# Paxiom v0 canonicalization & payload hashing (`0.2.0`)

Signature verification and output binding must be reproducible byte-for-byte across JavaScript/TypeScript, Python, Rust, and Go without external library drift. `paxiom.receipt.v0` (`0.2.0`) defines:
1. **Envelope signing canonicalization** compatible with RFC 8785 JSON Canonicalization Scheme (JCS).
2. **Dual delivery output hashing modes** (`delivery.canonicalization`):
   - `"jcs-sha256"` *(default)* — deterministic canonical JSON hashing for `application/json` and `+json` responses.
   - `"raw-sha256"` — exact byte-stream SHA-256 hashing for Markdown, plain text, CSV, images, PDFs, audio, and binary responses.

## Canonical JSON Rules (`jcs-sha256` & Signing Input)

1. Encode output as **UTF-8**.
2. **Object keys sorted lexicographically by UTF-16 code units** (matching RFC 8785 §3.2.3 and JavaScript default string sort), recursively, at every level.
3. **Array order is preserved** (arrays are ordered data, never reordered).
4. **No insignificant whitespace** — no spaces, no newlines between tokens.
5. **Money and hashes are strings, never JSON numbers.** All amounts (`amountAtomic`, `amountDisplay`) and all hashes are strings. Non-string scalars in the envelope are limited to booleans (`checkedByVerifier`, legacy `checkedByPaxiom`) and bounded integer HTTP status codes (`delivery.statusCode`, `100..599`). `-0` normalizes to `0`; `NaN` and `±Infinity` are rejected.
6. **Hashes** are SHA-256, **lowercase hex, `0x`-prefixed** (66 chars total).
7. `null` serializes as `null`; keys with `null` values are retained (they are part of the signed structure — e.g. `settlement.transactionHash`).

## Reference implementation

```js
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('Non-finite number');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
```

A conforming verifier MUST reject non-finite numbers and `undefined`, and SHOULD bound recursion depth (capped at `256` in `@paxiom/receipts` and `paxiom-receipts`) so pathological untrusted outputs return `trustState: "error"` rather than overflowing the stack.

## Envelope signing input

The Ed25519 signature covers the canonical JSON of **exactly** this object:

```json
{ "payload": { "…": "…" }, "receiptVersion": "paxiom.receipt.v0" }
```

i.e. `signingInput = utf8( canonicalize({ receiptVersion, payload }) )`.

- `signature` itself is **not** part of the signed preimage.
- `signature.publicKey` (32 bytes) and `signature.value` (64 bytes) MUST be canonical RFC 4648 base64, and `signature.value` MUST satisfy strict RFC 8032 `S < L` non-malleability.
- `receiptHash` is a non-authoritative display digest derived by verifiers as `"0x" + sha256hex(signingInput)`.

## Hash preimages

| Field | Mode | Preimage |
|-------|------|----------|
| `delivery.outputHash` | `"jcs-sha256"` *(default)* | `sha256( utf8( canonicalize(parsedJsonOutput) ) )` |
| `delivery.outputHash` | `"raw-sha256"` | `sha256( rawDeliveredBytes )` |
| `request.bodyHash` | JSON or raw | `sha256( utf8( canonicalize(jsonBody) ) )` or `sha256( rawBodyBytes )` |
| `request.resourceHash` | URI | `sha256( utf8(resourceUrl) )` |
| `request.requestHash` | Request tuple | `sha256( utf8( canonicalize({ bodyHash, method, resource }) ) )` |
| `payment.paymentRequirementsHash` | `x402` terms | `sha256( utf8( canonicalize(x402PaymentRequirements) ) )` |
| `payment.paymentPayloadHash` | `x402` payload | `sha256( utf8( canonicalize(x402PaymentPayload) ) )` |

All `sha256(...)` results are lowercase hex, `0x`-prefixed.
