# `paxiom-receipts` (Python Reference SDK — `v0.1.3`)

Zero-dependency Python 3.10+ reference implementation of **`paxiom.receipt.v0`** — cryptographic proof-of-delivery receipts, pre-payment x402 seller readiness checks, live Base USDC settlement verification, and FastAPI / Starlette ASGI middleware.

- **Zero required dependencies:** Ships a pure-stdlib RFC 8032 Ed25519 implementation (automatically accelerating via OpenSSL `cryptography` when installed in the environment).
- **100% byte-compatible with `@paxiom/receipts` (Node.js):** Shares identical PKCS#8 PEM keys, RFC 8785 JCS canonicalization, base64url `X-Paxiom-Receipt` headers, and all 15 deterministic trust states.

## Install

```bash
pip install ./standards/receipts/v0/python
```

## Seller Quickstart (FastAPI / Starlette ASGI)

```python
import os
from fastapi import FastAPI
from paxiom_receipts import PaxiomReceiptMiddleware

app = FastAPI()
app.add_middleware(
    PaxiomReceiptMiddleware,
    private_key=os.environ["PAXIOM_PRIVATE_KEY_PEM"],
    issuer={"name": "acme-python-api", "uri": "https://api.acme.dev", "keyId": "seller-01"},
    service_name="Inference API",
)

@app.post("/v1/infer")
async def infer():
    return {"answer": "42"}  # Automatically emits signed X-Paxiom-Receipt header!
```

## Buyer Quickstart (LangGraph / CrewAI / `httpx` / `requests`)

```python
from paxiom_receipts import (
    preflight_x402,
    verify_response_receipt,
    verify_receipt_live,
)

# 1. Pre-payment seller safety scan ($0.01 USDC via x402 or PAXIOM_API_KEY)
scan = preflight_x402(
    "https://seller.example/v1/infer",
    max_budget_atomic="50000",
    api_key=os.environ.get("PAXIOM_API_KEY"),
)

# 2. Free offline verification on any httpx / requests / dict response
check = verify_response_receipt(paid_response, output=paid_response.json())

# 3. Live Base USDC settlement + Paxiom root counter-attestation ($0.002 USDC)
if check["trustState"] == "settlement_claimed_not_checked":
    live = verify_receipt_live(
        check["receipt"],
        output=paid_response.json(),
        expected_pay_to="0xSellerAddress...",
        api_key=os.environ.get("PAXIOM_API_KEY"),
    )
```

## Test

```bash
python3 -m unittest discover -s standards/receipts/v0/python/tests -v
```
