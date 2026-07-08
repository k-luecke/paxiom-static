# Paxiom Receipt v0 — developer preview

**Status:** v0 draft · developer preview · conformance target. Not a production
standard, not a legal or compliance certificate.

> **x402 proves a payment. Paxiom proves what the payment bought.**

A **Paxiom receipt** binds *payment, request, output, settlement metadata, and
optional evidence* into a single signed, machine-verifiable object. It is
**provider-neutral**: any x402-paid API can emit one, and any agent can verify one
with only a public key.

This directory is the public **spec** — the shared artifact the verifier (CLI /
HTTP, shipping next) and the product pages build on. It contains no verifier
implementation yet.

## Why this exists

x402 (and most receipt-issuing services today) prove that a *payment happened*.
They do not, in a neutral and interoperable way, prove *what was delivered in
return*. Every incumbent signs only its own output in its own ad-hoc format
(Ed25519 here, HMAC there, EIP-712 elsewhere, SHA-256 trust-hash somewhere else).
There is no shared receipt that binds **payment + request + output + settlement +
proof** so that any agent can verify any seller uniformly. Paxiom v0 is a first,
deliberately small draft of that shared object.

## What a v0 receipt does and does NOT claim

**Does:** binds payment, request, resource, output, settlement *metadata*, and
optional evidence into one Ed25519-signed object with explicit, honest status
fields.

**Does NOT claim:**
- that all receipts are settled onchain,
- that all proofs are cryptographically verified,
- that any x402 implementation is secure,
- that a receipt is a legal or compliance certificate.

The verifier's job is to explain **what was actually checked** and **what was only
claimed**. Honesty about settlement is a core promise: a receipt that merely
*asserts* an onchain settlement the verifier did not confirm is reported as
`settlement_claimed_not_checked`, never as fully `verified`.

> **Schema-valid ≠ receipt-verified.** The JSON Schema validates receipt *shape*
> only. It does not prove settlement, signature validity, output binding, or proof
> correctness. Those checks are performed by a Paxiom verifier and reported through
> trust states. A structurally valid receipt can still be `invalid_signature`,
> `output_hash_mismatch`, `settlement_claimed_not_checked`, and so on.

## Top-level shape

```json
{
  "receiptVersion": "paxiom.receipt.v0",
  "payload": { "...": "..." },
  "signature": { "algorithm": "ed25519", "keyId": "...", "publicKey": "...", "value": "..." }
}
```

The signature signs the **canonical JSON** of `{ receiptVersion, payload }` — see
[`canonicalization.md`](./canonicalization.md). `receiptHash` is intentionally
**not** part of the signed payload in v0; the verifier derives it.

### Payload groups

| Group | Purpose |
|-------|---------|
| `receiptId` | Issuer-scoped unique id for this receipt. |
| `issuedAt` (+ optional `expiresAt`) | RFC 3339 timestamps. |
| `issuer` | `name`, optional `uri`, and `keyId` naming the signing key. |
| `service` | `name`, `resource` (URL), `method`. |
| `request` | `requestHash`, `resourceHash`, `bodyHash` — binds the exact call. |
| `payment` | x402 payment metadata + explicit `settlement` sub-object. |
| `delivery` | `outputHash` (of the delivered bytes) + `mimeType`. |
| `evidence` | Array of optional proof records; `[{type:"none",status:"not_provided",...}]` when absent. |

### Settlement status (enum)

`not_required` · `disabled` · `verify_only` · `claimed_not_checked` ·
`verified_settled` · `failed` · `unknown`

`claimed_not_checked` means: *the receipt carries settlement metadata, but the
Paxiom verifier did not independently check the chain or facilitator.* A hosted
verifier may later upgrade this to `verified_settled` after an onchain or
facilitator-backed check.

See [`trust-states.md`](./trust-states.md) for the full verifier verdict set and
how settlement status maps to a verdict.

## Files

```
standards/receipts/v0/
  README.md                          # this file
  paxiom.receipt.v0.schema.json      # JSON Schema (structure only)
  canonicalization.md                # Paxiom v0 canonical JSON profile + signing input
  trust-states.md                    # verifier verdict enum + resolution order
  examples/
    valid.output.json                        # delivered output bytes
    valid.receipt.json                       # REAL Ed25519 receipt -> `verified` (verify_only)
    output-mismatch.output.json              # different output -> output_hash_mismatch vs valid.receipt.json
    settlement-claimed-not-checked.receipt.json  # REAL Ed25519 receipt -> settlement_claimed_not_checked
```

### About the example fixtures

`valid.receipt.json` and `settlement-claimed-not-checked.receipt.json` are
**cryptographically real**: they were signed by a freshly generated Ed25519 key
whose private half was discarded. Each embeds its own raw public key
(base64, 32 bytes) so a verifier can check the signature with nothing else. No
real payment credentials, wallets, or API keys appear in any fixture — the payment
and request hashes are computed over harmless demo preimages.

To regenerate the fixtures (manual tool; fresh keypair each run, so this is
non-deterministic and rewrites the committed vectors — see the script header):

```bash
node standards/receipts/v0/scripts/gen-fixtures.mjs standards/receipts/v0/examples
```

### Conformance self-test

A zero-dependency check (JSON validity, schema conformance, cross-file hash
consistency, real Ed25519 signature verification, tamper detection, documented
trust-state outcomes) runs with plain Node:

```bash
node standards/receipts/v0/scripts/validate.mjs   # run from repo root
```

## Conformance targets (what "verify" will mean)

A verifier consuming a v0 receipt and the delivered output should:
1. validate structure against `paxiom.receipt.v0.schema.json`;
2. recompute canonical JSON of `{ receiptVersion, payload }` and verify `signature`;
3. recompute `delivery.outputHash` over the supplied output and compare;
4. confirm request/payment binding fields are present;
5. resolve settlement + evidence status **without overclaiming**;
6. emit a single trust state plus a per-check breakdown.

That verifier (CLI first, then HTTP) is the next sprint step and will live outside
this spec directory.

## Versioning

`receiptVersion` is a hard gate: a verifier that does not recognise the exact
string returns `unsupported_format`. Future dialects (including adapters that map
*non-Paxiom* receipt formats into this shape) will bump the version or ship as
named adapters; v0 makes no forward-compatibility promise.
