# Paxiom v0 canonical JSON profile

Signature verification must be reproducible byte-for-byte, so v0 defines a small,
self-contained canonical JSON profile. It is intentionally simple. A future
version may adopt a formal external canonicalization standard (e.g. RFC 8785 JCS)
if interoperability requires it; v0 does not, to avoid getting bogged down.

## Rules

1. Encode output as **UTF-8**.
2. **Object keys sorted lexicographically** (by UTF-16 code unit, i.e. JavaScript
   default string sort), recursively, at every level.
3. **Array order is preserved** (arrays are ordered data, never reordered).
4. **No insignificant whitespace** — no spaces, no newlines between tokens.
5. **Money and hashes are strings, never JSON numbers.** All amounts
   (`amountAtomic`, `amountDisplay`) and all hashes are strings. v0 payloads SHOULD
   avoid JSON numbers entirely; the boolean `checkedByPaxiom` is the only non-string
   scalar. Any JSON number that does appear is serialized in shortest round-trip
   form (JavaScript `JSON.stringify` default).
6. **Hashes** are SHA-256, **lowercase hex, `0x`-prefixed** (66 chars total).
7. `null` serializes as `null`; keys with `null` values are retained (they are part
   of the signed structure — e.g. `settlement.transactionHash`).

## Reference implementation

```js
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
```

## Signing input

The signature covers the canonical JSON of **exactly** this object:

```json
{ "receiptVersion": "paxiom.receipt.v0", "payload": { "…": "…" } }
```

i.e. `signingInput = utf8( canonicalize({ receiptVersion, payload }) )`.

- The `signature` object itself is **not** signed (it is the output of signing).
- `receiptHash` is **not** part of the signed payload in v0. A verifier MAY derive
  a display hash as `"0x" + sha256hex(signingInput)`; it is not authoritative and
  not carried in the receipt.

Sign / verify with Ed25519:

```js
const signingInput = Buffer.from(canonicalize({ receiptVersion, payload }), 'utf8');
const sigValue = crypto.sign(null, signingInput, privateKey).toString('base64'); // -> signature.value

// verify with only the embedded public key:
const pub = crypto.createPublicKey({ format: 'jwk',
  key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(signature.publicKey, 'base64').toString('base64url') } });
const ok = crypto.verify(null, signingInput, pub, Buffer.from(signature.value, 'base64'));
```

## Hash preimages used by the fixtures

The example receipts compute their hashes over these preimages so the fixtures are
internally consistent (a verifier only needs `delivery.outputHash` vs the supplied
output; the request/payment hashes below document how the demo values were derived):

| Field | Preimage |
|-------|----------|
| `delivery.outputHash` | `sha256( canonicalize(output) )` where `output` is `valid.output.json` |
| `request.bodyHash` | `sha256( canonicalize(requestBody) )` |
| `request.resourceHash` | `sha256( utf8(resourceUrl) )` |
| `request.requestHash` | `sha256( canonicalize({ bodyHash, method, resource }) )` |
| `payment.paymentRequirementsHash` | `sha256( canonicalize(x402PaymentRequirements) )` |
| `payment.paymentPayloadHash` | `sha256( canonicalize(x402PaymentPayload) )` |

All `sha256(...)` results are lowercase hex, `0x`-prefixed.

> v0 note: only `outputHash` is checked against externally-supplied data by the v0
> verifier (the delivered output). The request/payment hashes are *bindings* — the
> verifier confirms they are present and well-formed; confirming their preimages
> against a live x402 exchange is a later (hosted) capability.
