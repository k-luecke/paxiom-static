# Trust states — Paxiom Receipt v0 (`0.2.0`)

A verifier consumes a receipt (and, where relevant, the delivered output and expected seller signer pins) and emits **exactly one** trust state plus a per-check breakdown. Trust states are the honesty contract: they say what was actually checked and what was only claimed.

## The enum

| Trust state | Meaning |
|-------------|---------|
| `verified` | Everything the verifier checked passed, and settlement is either non-onchain (`verify_only`, `not_required`, `disabled`) or counter-attested by a trusted verifier key. |
| `valid_signature_only` | Signature valid, but the verifier could not reach `verified` for a non-fatal reason (e.g. output not supplied, or `settlement.status = unknown`). |
| `schema_invalid` | Receipt does not conform to `paxiom.receipt.v0.schema.json`. |
| `unsupported_format` | `receiptVersion` is not `paxiom.receipt.v0`. |
| `invalid_signature` | Signature does not verify against the embedded public key over the canonical signing input, is non-canonical (`S >= L`), or `issuer.keyId != signature.keyId`. |
| `unauthorized_issuer` | Signature is valid, **but** `signature.publicKey` is not in caller-supplied `expectedIssuerPublicKeys` (e.g. from `/.well-known/x402-keys.json`) or `payTo` does not match `expectedPayTo`. |
| `request_binding_missing` | Required `request` binding fields absent or malformed. |
| `payment_binding_missing` | Required `payment` binding fields absent or malformed. |
| `output_hash_mismatch` | Supplied output's hash (`jcs-sha256` or `raw-sha256`) does not equal `delivery.outputHash`. |
| `settlement_claimed_not_checked` | Signature + output verified, but the receipt asserts an onchain settlement this offline verifier did not independently confirm. |
| `settlement_failed` | `settlement.status = failed`. |
| `proof_not_provided` | Evidence array is empty / all `not_provided` (informational; does not by itself block `verified`). |
| `proof_unavailable` | An evidence record points somewhere the verifier could not retrieve. |
| `proof_invalid` | An evidence record was retrieved and failed verification. |
| `expired` | `expiresAt` is present and in the past. |
| `error` | The verifier itself failed (I/O, non-serializable output, unexpected exception). |

## Resolution order (v0, offline verifier)

Evaluate top-to-bottom; **return the first that applies**. This ordering ensures that tampered signatures, unauthorized signers, and mismatched outputs are surfaced accurately before settlement state is evaluated.

1. Verifier exception → `error`.
2. `receiptVersion` unrecognised → `unsupported_format`.
3. Schema invalid → `schema_invalid`.
4. Signature fails over `canonicalize({ receiptVersion, payload })` or `issuer.keyId != signature.keyId` → `invalid_signature`.
5. `expectedIssuerPublicKeys` or `expectedPayTo` supplied and mismatched → `unauthorized_issuer`.
6. `expiresAt` present and past → `expired`.
7. `request` bindings missing/malformed → `request_binding_missing`.
8. `payment` bindings missing/malformed → `payment_binding_missing`.
9. Output supplied **and** its hash (`jcs-sha256` or `raw-sha256`) ≠ `delivery.outputHash` → `output_hash_mismatch`.
10. `settlement.status = failed` → `settlement_failed`.
11. Evidence retrieved and invalid → `proof_invalid`; referenced but unreachable → `proof_unavailable`.
12. `settlement.status ∈ { claimed_not_checked, verified_settled }` (unless `verified_settled` + `checkedByVerifier: true` signed by a key in `trustedVerifierPublicKeys`), or non-null `transactionHash` under `{ not_required, disabled, verify_only }` → **`settlement_claimed_not_checked`**.
13. Output **not** supplied, or `settlement.status = unknown` → `valid_signature_only`.
14. Otherwise → **`verified`**.

### What `verified` requires

- schema valid, **and**
- signature valid, **and**
- if `expectedIssuerPublicKeys` or `expectedPayTo` was supplied, `checks.issuerAuthorization = "pass"` (otherwise `"unpinned"`), **and**
- supplied output's hash matches `delivery.outputHash`, **and**
- `request` and `payment` binding fields present and well-formed, **and**
- `settlement.status` ∈ `{ not_required, disabled, verify_only }` with `transactionHash: null` (or `verified_settled` + `checkedByVerifier: true` signed by a key in `trustedVerifierPublicKeys`), **and**
- not expired.

## Example outcomes (using the fixtures in `examples/`)

| Receipt | Output supplied | Expected trust state |
|---------|-----------------|----------------------|
| `valid.receipt.json` | `valid.output.json` | `verified` |
| `valid.receipt.json` | `output-mismatch.output.json` | `output_hash_mismatch` |
| `valid.receipt.json` | *(none)* | `valid_signature_only` |
| `settlement-claimed-not-checked.receipt.json` | `valid.output.json` | `settlement_claimed_not_checked` |

## Per-check breakdown

Alongside the single trust state, a verifier returns a structured breakdown so consumers can inspect each dimension independently:

```json
{
  "valid": false,
  "trustState": "settlement_claimed_not_checked",
  "checks": {
    "schema": "pass",
    "signature": "pass",
    "issuerAuthorization": "unpinned",
    "outputHash": "pass",
    "requestBinding": "pass",
    "paymentBinding": "pass",
    "settlement": "claimed_not_checked",
    "proof": "not_provided"
  },
  "summary": "Signature and output hash verified. Receipt claims an onchain settlement that this offline verifier did not check."
}
```
