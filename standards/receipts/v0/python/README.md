# `paxiom-receipts` (Python Reference SDK — `v0.4.0`)

Zero-dependency Python 3.10+ reference implementation of **`paxiom.receipt.v0`** — open MIT cryptographic proof-of-delivery receipts (`Payment-Receipt` / `X-Paxiom-Receipt`), two-gate buyer policy firewall & `AuthCaptureEscrow` arbiter (`paxiom_receipts.guard`), offline Ethereum MPT / EIP-1186 state & EVM receipt-trie USDC settlement verifier (`paxiom_receipts.proofs`), seller key discovery (`/.well-known/x402-keys.json`), pre-payment `x402` seller readiness checks, live Base USDC settlement verification, and FastAPI / Starlette ASGI middleware.

- **Zero required dependencies:** Ships pure-stdlib RFC 8032 Ed25519, 24-round Ethereum Keccak-256, strict Yellow Paper RLP, and Modified Merkle-Patricia Trie (MPT) implementations.
- **100% byte-compatible with [`@paxiom/receipts`](https://www.npmjs.com/package/@paxiom/receipts) (`0.4.0`, Node.js / WebCrypto):** Shares identical PKCS#8 PEM keys, RFC 8785 JCS (`jcs-sha256`) and non-JSON (`raw-sha256`) payload hashing, `paxiom.root.v0` signed block root attestations, offline EIP-1186 & EVM receipt-trie proofs (Ethereum, Base, Arbitrum, Optimism, Polygon, Circle Arc), `x402` v2 header auto-parsing (CAIP-2 EVM & Solana), `Payment-Receipt` + `X-Paxiom-Receipt` headers, and all deterministic trust states.
- **Inline PEP 561 types (`py.typed`):** Full type hints for `mypy`, `pyright`, and IDE autocomplete.

## Install

```bash
# From PyPI:
pip install paxiom-receipts

# Optional OpenSSL Ed25519 acceleration:
pip install "paxiom-receipts[fast]"
```

## Seller Quickstart (FastAPI / Starlette / Litestar ASGI)

`PaxiomReceiptMiddleware` automatically decodes `x402` v2 `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers, hashes JSON (`jcs-sha256`) or Markdown/text/binary (`raw-sha256`) 2xx responses up to 256 KiB, and attaches signed `Payment-Receipt` and `X-Paxiom-Receipt` headers:

```python
import os
from fastapi import FastAPI
from paxiom_receipts import PaxiomReceiptMiddleware

app = FastAPI()

if os.environ.get("PAXIOM_PRIVATE_KEY_PEM"):
    app.add_middleware(
        PaxiomReceiptMiddleware,
        private_key=os.environ["PAXIOM_PRIVATE_KEY_PEM"],
        issuer={
            "name": "acme-python-api",
            "uri": "https://api.acme.dev",
            "keyId": "seller-01",
            "payTo": "0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4",
            "keysUri": "https://api.acme.dev/.well-known/x402-keys.json",
        },
        service_name="Inference API",
    )

@app.post("/v1/infer")
async def infer():
    return {"answer": "42"}  # Emits signed Payment-Receipt + X-Paxiom-Receipt headers
```

## Buyer Quickstart (LangGraph / CrewAI / `httpx` / `requests`)

```python
from paxiom_receipts import (
    discover_issuer_keys,
    preflight_x402,
    verify_response_receipt,
    verify_receipt_live,
)

# 1. Free pre-payment seller safety scan via api.paxiom.org/v1/x402/preflight
scan = preflight_x402("https://seller.example/v1/infer", max_budget_atomic="50000")

# 2. Discover seller's published Ed25519 keys (/.well-known/x402-keys.json)
keys_doc = discover_issuer_keys("https://seller.example")

# 3. Offline verification with signer + payTo authorization on any httpx / requests response
check = verify_response_receipt(
    paid_response,
    output=paid_response.json(),
    expected_issuer_public_keys=keys_doc["publicKeys"] if keys_doc["ok"] else None,
    expected_pay_to="0xSellerAddress...",
)

# 4. Free live Base USDC settlement + counter-attestation via api.paxiom.org/v1/receipt/verify-live
if check["trustState"] == "settlement_claimed_not_checked":
    live = verify_receipt_live(
        check["receipt"],
        output=paid_response.json(),
        expected_pay_to="0xSellerAddress...",
    )
```

## Links

- **`x402` Extension Spec:** <https://paxiom.org/standards/receipts/v0/x402-delivery-receipt-extension.md>
- **Specification & Vectors:** <https://paxiom.org/receipts.html>
- **Free Public Verifier & Keys:** <https://api.paxiom.org/.well-known/x402-keys.json>
- **MCP Server (`0.4.0`):** <https://api.paxiom.org/mcp>
- **TypeScript / Node.js SDK:** [`@paxiom/receipts`](https://www.npmjs.com/package/@paxiom/receipts)
