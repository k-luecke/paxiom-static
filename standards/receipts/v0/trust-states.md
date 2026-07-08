# Trust states — Paxiom Receipt v0

A verifier consumes a receipt (and, where relevant, the delivered output) and emits
**exactly one** trust state plus a per-check breakdown. Trust states are the
honesty contract: they say what was actually checked and what was only claimed.

## The enum

| Trust state | Meaning |
|-------------|---------|
| `verified` | Everything the offline verifier can check passed, and settlement is not an unconfirmed onchain claim. |
| `valid_signature_only` | Signature valid, but the verifier could not reach `verified` for a non-fatal reason (e.g. output not supplied, or `settlement.status = unknown`). |
| `schema_invalid` | Receipt does not conform to `paxiom.receipt.v0.schema.json`. |
| `unsupported_format` | `receiptVersion` is not `paxiom.receipt.v0`. |
| `invalid_signature` | Signature does not verify against the embedded public key over the canonical signing input. |
| `request_binding_missing` | Required `request` binding fields absent or malformed. |
| `payment_binding_missing` | Required `payment` binding fields absent or malformed. |
| `output_hash_mismatch` | Supplied output's hash does not equal `delivery.outputHash`. |
| `settlement_claimed_not_checked` | Signature + output verified, but the receipt asserts an onchain settlement this verifier did not independently confirm. |
| `settlement_failed` | `settlement.status = failed`. |
| `proof_not_provided` | Evidence array is empty / all `not_provided` (informational; does not by itself block `verified`). |
| `proof_unavailable` | An evidence record points somewhere the verifier could not retrieve. |
| `proof_invalid` | An evidence record was retrieved and failed verification. |
| `expired` | `expiresAt` is present and in the past. |
| `error` | The verifier itself failed (I/O, unexpected exception). |

## Resolution order (v0, offline verifier)

Evaluate top-to-bottom; **return the first that applies**. This ordering is why,
for example, a tampered output is reported as `output_hash_mismatch` rather than
`verified`.

1. Verifier exception → `error`.
2. `receiptVersion` unrecognised → `unsupported_format`.
3. Schema invalid → `schema_invalid`.
4. Signature fails over `canonicalize({ receiptVersion, payload })` → `invalid_signature`.
5. `expiresAt` present and past → `expired`.
6. `request` bindings missing/malformed → `request_binding_missing`.
7. `payment` bindings missing/malformed → `payment_binding_missing`.
8. Output supplied **and** its hash ≠ `delivery.outputHash` → `output_hash_mismatch`.
9. `settlement.status = failed` → `settlement_failed`.
10. Evidence retrieved and invalid → `proof_invalid`; referenced but unreachable → `proof_unavailable`.
11. `settlement.status ∈ { claimed_not_checked, verified_settled }` → **`settlement_claimed_not_checked`**
    (the offline verifier cannot confirm an onchain settlement; `verified_settled`
    is treated as an issuer *claim*, not proof).
12. Output **not** supplied, or `settlement.status = unknown` → `valid_signature_only`.
13. Otherwise → **`verified`**.

### What `verified` requires

- schema valid, **and**
- signature valid, **and**
- supplied output's hash matches `delivery.outputHash`, **and**
- `request` and `payment` binding fields present and well-formed, **and**
- `settlement.status` ∈ `{ not_required, disabled, verify_only }`
  (i.e. no unconfirmed onchain settlement is being asserted), **and**
- not expired.

Evidence being `not_provided` does **not** block `verified` in v0 — proof is
optional. The breakdown still reports `proof_not_provided` so consumers see it.

## Example outcomes (using the fixtures in `examples/`)

| Receipt | Output supplied | Expected trust state |
|---------|-----------------|----------------------|
| `valid.receipt.json` | `valid.output.json` | `verified` |
| `valid.receipt.json` | `output-mismatch.output.json` | `output_hash_mismatch` |
| `valid.receipt.json` | *(none)* | `valid_signature_only` |
| `settlement-claimed-not-checked.receipt.json` | `valid.output.json` | `settlement_claimed_not_checked` |

## Per-check breakdown

Alongside the single trust state, a verifier should return a structured breakdown
so consumers can see each dimension independently, e.g.:

```json
{
  "trustState": "settlement_claimed_not_checked",
  "checks": {
    "schema": "pass",
    "signature": "pass",
    "outputHash": "pass",
    "requestBinding": "pass",
    "paymentBinding": "pass",
    "settlement": "claimed_not_checked",
    "proof": "not_provided"
  },
  "summary": "Signature and output hash verified. Receipt claims an onchain settlement that this verifier did not check."
}
```

Every trust state in this file is also a value that may appear in the README's
conformance discussion; verifiers MUST NOT emit trust states not listed here.
