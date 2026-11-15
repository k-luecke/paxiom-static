"""Ed25519 receipt issuer & header encoder/decoder matching src/issue.mjs."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
import re
from typing import Any
import uuid

from .canonicalize import hash_canonical, sha256_hex, signing_input
from .ed25519_pure import (
    _b64url_decode_nopad,
    _b64url_encode_nopad,
    ed25519_public_key_from_seed,
    ed25519_sign,
    extract_ed25519_seed,
    seed_to_pkcs8_pem,
)
from .verify import RECEIPT_VERSION

_SHA256_HEX_RE = re.compile(r"\A0x[0-9a-f]{64}\Z")
_EVM_TX_HASH_RE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z")
_SOLANA_TX_SIG_RE = re.compile(r"\A[1-9A-HJ-NP-Za-km-z]{64,88}\Z")
_SENTINEL = object()


def normalize_transaction_id(raw_tx: Any) -> str | None:
    if raw_tx is None:
        return None
    s = str(raw_tx)
    if _EVM_TX_HASH_RE.match(s):
        return s.lower()
    if _SOLANA_TX_SIG_RE.match(s):
        return s
    raise TypeError(
        f"settlement.transactionHash must be 0x + 64 hex chars (EVM), 64-88 base58 chars (Solana), or null, got {raw_tx}"
    )


def public_key_from_private_key(private_key: Any) -> str:
    seed = extract_ed25519_seed(private_key)
    pub_raw = ed25519_public_key_from_seed(seed)
    return base64.b64encode(pub_raw).decode("ascii")


def generate_receipt_keypair(key_id: str | None = None) -> dict[str, Any]:
    kid = key_id or f"key_{os.urandom(6).hex()}"
    seed = os.urandom(32)
    pub_raw = ed25519_public_key_from_seed(seed)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    pem = seed_to_pkcs8_pem(seed)
    return {
        "keyId": kid,
        "algorithm": "ed25519",
        "publicKey": pub_b64,
        "privateKeyPem": pem,
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_encode_nopad(pub_raw),
            "kid": kid,
        },
    }


def _resolve_digest_or_value(explicit_hash: str | None, value: Any = _SENTINEL, fallback_empty: str = "") -> str:
    if isinstance(explicit_hash, str):
        norm = explicit_hash.lower()
        if not _SHA256_HEX_RE.match(norm):
            raise TypeError(f"Invalid sha256Hex digest: {explicit_hash}")
        return norm
    if value is _SENTINEL:
        return sha256_hex(fallback_empty.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return sha256_hex(value)
    if isinstance(value, str):
        return sha256_hex(value.encode("utf-8"))
    return hash_canonical(value)


def issue_receipt(
    *,
    private_key: Any,
    issuer: dict[str, Any],
    service: dict[str, Any],
    request: dict[str, Any] | None = None,
    payment: dict[str, Any] | None = None,
    output: Any = _SENTINEL,
    output_hash: str | None = None,
    mime_type: str = "application/json",
    canonicalization: str | None = None,
    status_code: int | None = None,
    evidence: list[dict[str, Any]] | None = None,
    receipt_id: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(issuer, dict) or not issuer.get("name") or not issuer.get("keyId"):
        raise TypeError("issuer.name and issuer.keyId are required")
    if not isinstance(service, dict) or not service.get("name") or not service.get("resource") or not service.get("method"):
        raise TypeError("service.name, service.resource, and service.method are required")

    seed = extract_ed25519_seed(private_key)
    pub_b64 = base64.b64encode(ed25519_public_key_from_seed(seed)).decode("ascii")

    req = request or {}
    pay = payment or {}

    method = str(req.get("method") or service["method"]).upper()
    resource = str(req.get("resource") or service["resource"])
    resource_hash = _resolve_digest_or_value(req.get("resourceHash"), resource)
    body_val = req["body"] if "body" in req else _SENTINEL
    body_hash = _resolve_digest_or_value(req.get("bodyHash"), body_val, "")
    request_hash = (
        _resolve_digest_or_value(req["requestHash"])
        if req.get("requestHash")
        else hash_canonical({"bodyHash": body_hash, "method": method, "resource": resource})
    )

    pay_req_val = pay["paymentRequirements"] if "paymentRequirements" in pay else _SENTINEL
    payment_requirements_hash = _resolve_digest_or_value(pay.get("paymentRequirementsHash"), pay_req_val, "none")
    pay_payload_val = pay["paymentPayload"] if "paymentPayload" in pay else _SENTINEL
    payment_payload_hash = _resolve_digest_or_value(pay.get("paymentPayloadHash"), pay_payload_val, "none")

    settlement_in = pay.get("settlement") or {}
    tx_hash = normalize_transaction_id(settlement_in.get("transactionHash"))
    checked_by_verifier = bool(
        settlement_in["checkedByVerifier"]
        if "checkedByVerifier" in settlement_in
        else settlement_in.get("checkedByPaxiom", False)
    )

    settlement: dict[str, Any] = {
        "status": settlement_in.get("status") or ("claimed_not_checked" if tx_hash else "not_required"),
        "transactionHash": tx_hash,
        "checkedByVerifier": checked_by_verifier,
    }
    if "verifier" in settlement_in:
        settlement["verifier"] = settlement_in["verifier"]
    if "checkedByPaxiom" in settlement_in:
        settlement["checkedByPaxiom"] = bool(settlement_in["checkedByPaxiom"])

    is_raw_bytes = isinstance(output, (bytes, bytearray, memoryview))
    canon_mode = canonicalization or ("raw-sha256" if is_raw_bytes else None)
    if canon_mode is not None and canon_mode not in ("jcs-sha256", "raw-sha256"):
        raise TypeError(f"Invalid canonicalization mode: {canon_mode}")

    if output_hash:
        computed_output_hash = _resolve_digest_or_value(output_hash)
    elif output is not _SENTINEL:
        if canon_mode == "raw-sha256":
            if is_raw_bytes:
                computed_output_hash = sha256_hex(output)
            elif isinstance(output, str):
                computed_output_hash = sha256_hex(output.encode("utf-8"))
            else:
                raise TypeError('canonicalization="raw-sha256" requires bytes or str output')
        else:
            computed_output_hash = hash_canonical(output)
            if canon_mode is None:
                canon_mode = "jcs-sha256"
    else:
        raise TypeError("Either output or output_hash is required to issue a receipt")

    issuer_obj: dict[str, Any] = {
        "name": str(issuer["name"]),
        "keyId": str(issuer["keyId"]),
    }
    if issuer.get("uri"):
        issuer_obj["uri"] = str(issuer["uri"])
    if issuer.get("payTo"):
        issuer_obj["payTo"] = str(issuer["payTo"])
    if issuer.get("keysUri"):
        issuer_obj["keysUri"] = str(issuer["keysUri"])

    delivery_obj: dict[str, Any] = {
        "outputHash": computed_output_hash,
        "mimeType": str(mime_type),
    }
    if canon_mode:
        delivery_obj["canonicalization"] = canon_mode
    if status_code is not None:
        delivery_obj["statusCode"] = int(status_code)

    payment_obj: dict[str, Any] = {
        "scheme": str(pay.get("scheme") or "x402"),
        "network": str(pay.get("network") or "eip155:8453"),
        "asset": str(pay.get("asset") or "USDC"),
        "amountAtomic": str(pay.get("amountAtomic", "0")),
        "amountDisplay": str(pay.get("amountDisplay", "0")),
        "paymentRequirementsHash": payment_requirements_hash,
        "paymentPayloadHash": payment_payload_hash,
        "settlement": settlement,
    }
    if pay.get("payer"):
        payment_obj["payer"] = str(pay["payer"])
    if pay.get("payTo"):
        payment_obj["payTo"] = str(pay["payTo"])

    now_iso = issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    rid = receipt_id or f"rcpt_{uuid.uuid4().hex}"

    payload: dict[str, Any] = {
        "receiptId": str(rid),
        "issuedAt": str(now_iso),
        "issuer": issuer_obj,
        "service": {
            "name": str(service["name"]),
            "resource": str(service["resource"]),
            "method": str(service["method"]).upper(),
        },
        "request": {
            "requestHash": request_hash,
            "resourceHash": resource_hash,
            "bodyHash": body_hash,
        },
        "payment": payment_obj,
        "delivery": delivery_obj,
        "evidence": (
            evidence
            if isinstance(evidence, list) and len(evidence) > 0
            else [{"type": "none", "status": "not_provided", "hash": None, "uri": None}]
        ),
    }
    if expires_at:
        payload["expiresAt"] = str(expires_at)

    unsigned_doc = {"receiptVersion": RECEIPT_VERSION, "payload": payload}
    sig_bytes = ed25519_sign(seed, signing_input(unsigned_doc))

    receipt = {
        "receiptVersion": RECEIPT_VERSION,
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": issuer_obj["keyId"],
            "publicKey": pub_b64,
            "value": base64.b64encode(sig_bytes).decode("ascii"),
        },
    }
    receipt_header = _b64url_encode_nopad(json.dumps(receipt, separators=(",", ":")).encode("utf-8"))
    return {"receipt": receipt, "receiptHeader": receipt_header}


def decode_receipt_header(header_value: str) -> dict[str, Any]:
    if not isinstance(header_value, str) or not header_value.strip():
        raise TypeError("Receipt header must be a non-empty base64url string")
    raw = _b64url_decode_nopad(header_value.strip())
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decoded receipt header must be a JSON object")
    return parsed
