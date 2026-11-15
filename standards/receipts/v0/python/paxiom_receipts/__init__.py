"""Zero-dependency Python Reference SDK for paxiom.receipt.v0."""
from .asgi import PaxiomReceiptMiddleware, parse_x402_headers
from .canonicalize import MAX_DEPTH, canonicalize, hash_canonical, sha256_hex, signing_input
from .client import (
    DEFAULT_PAXIOM_API_URL,
    PAXIOM_LIVE_VERIFIER_PUBLIC_KEY,
    PAXIOM_TRUSTED_PUBLIC_KEYS,
    PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS,
    RECEIPT_HEADER_NAME,
    STANDARD_RECEIPT_HEADER_NAME,
    discover_issuer_keys,
    preflight_x402,
    resolve_safe_api_origin,
    verify_receipt_live,
    verify_response_receipt,
)
from .issue import (
    decode_receipt_header,
    generate_receipt_keypair,
    issue_receipt,
    normalize_transaction_id,
    public_key_from_private_key,
)
from .verify import RECEIPT_VERSION, explain, verify_from_files, verify_receipt

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "RECEIPT_VERSION",
    "STANDARD_RECEIPT_HEADER_NAME",
    "RECEIPT_HEADER_NAME",
    "MAX_DEPTH",
    "DEFAULT_PAXIOM_API_URL",
    "PAXIOM_LIVE_VERIFIER_PUBLIC_KEY",
    "PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS",
    "PAXIOM_TRUSTED_PUBLIC_KEYS",
    "canonicalize",
    "signing_input",
    "sha256_hex",
    "hash_canonical",
    "verify_receipt",
    "verify_from_files",
    "explain",
    "generate_receipt_keypair",
    "normalize_transaction_id",
    "public_key_from_private_key",
    "issue_receipt",
    "decode_receipt_header",
    "parse_x402_headers",
    "resolve_safe_api_origin",
    "discover_issuer_keys",
    "verify_response_receipt",
    "preflight_x402",
    "verify_receipt_live",
    "PaxiomReceiptMiddleware",
]
