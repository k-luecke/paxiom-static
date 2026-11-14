"""Zero-dependency buyer client helpers matching standards/receipts/v0/src/client.mjs."""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

from .issue import decode_receipt_header
from .verify import verify_receipt

RECEIPT_HEADER_NAME = "x-paxiom-receipt"
DEFAULT_PAXIOM_API_URL = "https://api.paxiom.org"
PAXIOM_LIVE_VERIFIER_PUBLIC_KEY = "hsRfDKd2AWxv0KwTs3gsDLMY7nPtVGky1Tc6NWgSxIY="
PAXIOM_TRUSTED_PUBLIC_KEYS: tuple[str, ...] = (PAXIOM_LIVE_VERIFIER_PUBLIC_KEY,)

DEFAULT_CLIENT_TIMEOUT_SECONDS = 15.0
MAX_CLIENT_RESPONSE_BYTES = 1024 * 1024  # 1 MiB safety cap
_ALLOWED_PREFLIGHT_METHODS = frozenset({"POST", "GET", "HEAD"})
_DEC_UINT_RE = re.compile(r"\A[0-9]+\Z")
_EVM_ADDRESS_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")
_SENTINEL = object()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, f"Refusing HTTP {code} redirect", headers, fp)


def _is_loopback_host(hostname: str | None) -> bool:
    bare = (hostname or "").strip("[]").lower()
    return bare in ("127.0.0.1", "localhost", "::1")


def resolve_safe_api_origin(raw_base_url: str = DEFAULT_PAXIOM_API_URL) -> str:
    if not isinstance(raw_base_url, str) or not raw_base_url.strip():
        raise TypeError("base_url must be a non-empty URL string")
    parsed = urllib.parse.urlsplit(raw_base_url.strip())
    if not parsed.scheme or not parsed.netloc or not parsed.hostname:
        raise TypeError(f"Invalid base_url: {raw_base_url}")
    if parsed.username or parsed.password:
        raise TypeError("base_url must not contain embedded credentials")
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (scheme == "http" and _is_loopback_host(parsed.hostname)):
        raise TypeError("base_url must use https:// (plaintext http:// is permitted only on loopback for local tests)")
    return f"{scheme}://{parsed.netloc}"


def _extract_header_value(response_or_headers: Any, header_name: str) -> str | None:
    if response_or_headers is None:
        return None
    target = getattr(response_or_headers, "headers", response_or_headers)
    lower = header_name.lower()
    if isinstance(target, dict):
        for k, v in target.items():
            if str(k).lower() == lower and v is not None:
                return str(v[0]) if isinstance(v, (list, tuple)) and v else str(v)
        return None
    if hasattr(target, "items") and callable(target.items):
        for k, v in target.items():
            if str(k).lower() == lower and v is not None:
                return str(v)
    if hasattr(target, "get") and callable(target.get):
        val = target.get(header_name) or target.get(lower)
        return None if val is None else str(val)
    return None


def _decode_base64_json_object(raw: str | None) -> dict[str, Any] | None:
    if not raw or not isinstance(raw, str) or not raw.strip():
        return None
    trimmed = raw.strip()
    pad = "=" * ((4 - (len(trimmed) % 4)) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            parsed = json.loads(decoder(trimmed + pad).decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _default_urllib_transport(
    url: str,
    headers: dict[str, str],
    body_bytes: bytes,
    timeout_seconds: float,
    max_bytes: int,
) -> tuple[int, dict[str, str], str]:
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")

    def _read_bounded(stream: Any) -> str:
        raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"Verifier response exceeded {max_bytes} bytes")
        return raw.decode("utf-8")

    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            status = int(getattr(resp, "status", 200))
            if 300 <= status < 400:
                raise RuntimeError(f"Refusing HTTP {status} redirect from Paxiom verifier endpoint")
            resp_headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            return status, resp_headers, _read_bounded(resp)
    except urllib.error.HTTPError as http_err:
        status = int(http_err.code)
        if 300 <= status < 400:
            raise RuntimeError(f"Refusing HTTP {status} redirect from Paxiom verifier endpoint") from http_err
        resp_headers = {str(k).lower(): str(v) for k, v in (http_err.headers.items() if http_err.headers else [])}
        body_text = _read_bounded(http_err.fp) if http_err.fp is not None else ""
        return status, resp_headers, body_text


def _build_auth_headers(api_key: str | None, payment_header: str | None) -> dict[str, str]:
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "paxiom-receipts-python/0.1.3",
    }
    if api_key is not None and str(api_key).strip():
        headers["x-api-key"] = str(api_key).strip()
    if payment_header is not None and str(payment_header).strip():
        headers["payment-signature"] = str(payment_header).strip()
    return headers


def verify_response_receipt(
    response_or_headers: Any,
    *,
    output: Any = _SENTINEL,
    trusted_paxiom_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
) -> dict[str, Any]:
    """Inspect a response or headers mapping for X-Paxiom-Receipt and verify offline. Never raises."""
    raw_hdr = _extract_header_value(response_or_headers, RECEIPT_HEADER_NAME)
    if not raw_hdr or not raw_hdr.strip():
        return {
            "present": False,
            "valid": False,
            "trustState": None,
            "receipt": None,
            "verdict": None,
        }
    try:
        receipt = decode_receipt_header(raw_hdr)
    except Exception as err:
        return {
            "present": True,
            "valid": False,
            "trustState": "malformed_header",
            "receipt": None,
            "verdict": None,
            "error": str(err),
        }

    trusted = (
        trusted_paxiom_public_keys
        if trusted_paxiom_public_keys is not None
        else PAXIOM_TRUSTED_PUBLIC_KEYS
    )
    verdict = (
        verify_receipt(receipt, output=output, trusted_paxiom_public_keys=trusted)
        if output is not _SENTINEL
        else verify_receipt(receipt, trusted_paxiom_public_keys=trusted)
    )
    return {
        "present": True,
        "valid": verdict["valid"],
        "trustState": verdict["trustState"],
        "receipt": receipt,
        "verdict": verdict,
    }


def preflight_x402(
    target_url: str,
    *,
    method: str = "POST",
    max_budget_atomic: str | int | None = None,
    expected_network: str | None = None,
    base_url: str = DEFAULT_PAXIOM_API_URL,
    api_key: str | None = None,
    payment_header: str | None = None,
    timeout_seconds: float = DEFAULT_CLIENT_TIMEOUT_SECONDS,
    trusted_paxiom_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    transport: Callable[[str, dict[str, str], bytes, float, int], tuple[int, dict[str, str], str]] | None = None,
) -> dict[str, Any]:
    if not isinstance(target_url, str) or not target_url.strip():
        raise TypeError("target_url must be a non-empty https:// URL string")
    parsed_target = urllib.parse.urlsplit(target_url.strip())
    if parsed_target.scheme.lower() != "https" or not parsed_target.hostname:
        raise TypeError("target_url must use https://")

    origin = resolve_safe_api_origin(base_url)
    method_upper = str(method).upper()
    if method_upper not in _ALLOWED_PREFLIGHT_METHODS:
        raise TypeError("method must be POST, GET, or HEAD")

    req_body: dict[str, Any] = {"url": target_url.strip(), "method": method_upper}
    if max_budget_atomic is not None and str(max_budget_atomic) != "":
        budget_str = str(max_budget_atomic)
        if not _DEC_UINT_RE.match(budget_str):
            raise TypeError("max_budget_atomic must be a non-negative base-10 integer string")
        req_body["maxBudgetAtomic"] = budget_str
    if expected_network is not None and str(expected_network) != "":
        req_body["expectedNetwork"] = str(expected_network)

    call_fn = transport or _default_urllib_transport
    status, resp_headers, body_text = call_fn(
        f"{origin}/v1/x402/preflight",
        _build_auth_headers(api_key, payment_header),
        json.dumps(req_body).encode("utf-8"),
        float(timeout_seconds) if timeout_seconds > 0 else DEFAULT_CLIENT_TIMEOUT_SECONDS,
        MAX_CLIENT_RESPONSE_BYTES,
    )
    if 300 <= status < 400:
        raise RuntimeError(f"Refusing HTTP {status} redirect from Paxiom verifier endpoint")
    if len(body_text.encode("utf-8")) > MAX_CLIENT_RESPONSE_BYTES:
        raise ValueError(f"Verifier response exceeded {MAX_CLIENT_RESPONSE_BYTES} bytes")

    try:
        body_json = json.loads(body_text) if body_text else None
    except Exception:
        body_json = None

    if status == 402:
        hdr_challenge = _decode_base64_json_object(_extract_header_value(resp_headers, "payment-required"))
        return {
            "ok": False,
            "status": 402,
            "paymentRequired": True,
            "challenge": hdr_challenge or body_json,
            "report": None,
            "receiptVerification": None,
            "paymentResponse": None,
        }

    if status < 200 or status >= 300 or not isinstance(body_json, dict):
        err_obj = body_json.get("error") if isinstance(body_json, dict) else None
        return {
            "ok": False,
            "status": status,
            "paymentRequired": False,
            "error": err_obj or {"code": "preflight_http_error", "message": f"HTTP {status}"},
            "report": None,
            "receiptVerification": None,
            "paymentResponse": None,
        }

    receipt_ver = verify_response_receipt(
        resp_headers,
        output=body_json,
        trusted_paxiom_public_keys=trusted_paxiom_public_keys,
    )
    pay_resp = _decode_base64_json_object(
        _extract_header_value(resp_headers, "payment-response")
        or _extract_header_value(resp_headers, "x-payment-response")
    )
    return {
        "ok": True,
        "status": status,
        "paymentRequired": False,
        "verdict": body_json.get("verdict"),
        "riskLevel": body_json.get("riskLevel"),
        "report": body_json,
        "receiptVerification": receipt_ver,
        "paymentResponse": pay_resp,
    }


def verify_receipt_live(
    receipt: dict[str, Any],
    *,
    output: Any = _SENTINEL,
    expected_pay_to: str | None = None,
    base_url: str = DEFAULT_PAXIOM_API_URL,
    api_key: str | None = None,
    payment_header: str | None = None,
    timeout_seconds: float = DEFAULT_CLIENT_TIMEOUT_SECONDS,
    trusted_paxiom_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    transport: Callable[[str, dict[str, str], bytes, float, int], tuple[int, dict[str, str], str]] | None = None,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a parsed paxiom.receipt.v0 dict")

    origin = resolve_safe_api_origin(base_url)
    req_body: dict[str, Any] = {"receipt": receipt}
    has_output = output is not _SENTINEL
    if has_output:
        req_body["output"] = output
    if expected_pay_to is not None and str(expected_pay_to) != "":
        pay_to_str = str(expected_pay_to)
        if not _EVM_ADDRESS_RE.match(pay_to_str):
            raise TypeError("expected_pay_to must be a 0x-prefixed 20-byte EVM hex address")
        req_body["expectedPayTo"] = pay_to_str

    call_fn = transport or _default_urllib_transport
    status, resp_headers, body_text = call_fn(
        f"{origin}/v1/receipt/verify-live",
        _build_auth_headers(api_key, payment_header),
        json.dumps(req_body).encode("utf-8"),
        float(timeout_seconds) if timeout_seconds > 0 else DEFAULT_CLIENT_TIMEOUT_SECONDS,
        MAX_CLIENT_RESPONSE_BYTES,
    )
    if 300 <= status < 400:
        raise RuntimeError(f"Refusing HTTP {status} redirect from Paxiom verifier endpoint")
    if len(body_text.encode("utf-8")) > MAX_CLIENT_RESPONSE_BYTES:
        raise ValueError(f"Verifier response exceeded {MAX_CLIENT_RESPONSE_BYTES} bytes")

    try:
        body_json = json.loads(body_text) if body_text else None
    except Exception:
        body_json = None

    if status == 402:
        hdr_challenge = _decode_base64_json_object(_extract_header_value(resp_headers, "payment-required"))
        return {
            "ok": False,
            "status": 402,
            "paymentRequired": True,
            "challenge": hdr_challenge or body_json,
            "result": None,
            "counterAttestedReceipt": None,
            "counterAttestedVerification": None,
            "paymentResponse": None,
        }

    if status < 200 or status >= 300 or not isinstance(body_json, dict):
        err_obj = body_json.get("error") if isinstance(body_json, dict) else None
        return {
            "ok": False,
            "status": status,
            "paymentRequired": False,
            "error": err_obj or {"code": "verify_live_http_error", "message": f"HTTP {status}"},
            "result": None,
            "counterAttestedReceipt": None,
            "counterAttestedVerification": None,
            "paymentResponse": None,
        }

    trusted = (
        trusted_paxiom_public_keys
        if trusted_paxiom_public_keys is not None
        else PAXIOM_TRUSTED_PUBLIC_KEYS
    )
    counter_rcpt = body_json.get("counterAttestedReceipt")
    counter_ver = (
        (
            verify_receipt(counter_rcpt, output=output, trusted_paxiom_public_keys=trusted)
            if has_output
            else verify_receipt(counter_rcpt, trusted_paxiom_public_keys=trusted)
        )
        if isinstance(counter_rcpt, dict)
        else None
    )
    pay_resp = _decode_base64_json_object(
        _extract_header_value(resp_headers, "payment-response")
        or _extract_header_value(resp_headers, "x-payment-response")
    )
    return {
        "ok": True,
        "status": status,
        "paymentRequired": False,
        "valid": bool(body_json.get("valid")),
        "trustState": body_json.get("trustState"),
        "result": body_json,
        "counterAttestedReceipt": counter_rcpt,
        "counterAttestedVerification": counter_ver,
        "paymentResponse": pay_resp,
    }
