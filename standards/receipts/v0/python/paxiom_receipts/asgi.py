"""Zero-dependency ASGI 3.0 middleware (FastAPI / Starlette / Litestar) for paxiom.receipt.v0."""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable

from .client import RECEIPT_HEADER_NAME, STANDARD_RECEIPT_HEADER_NAME
from .ed25519_pure import extract_ed25519_seed
from .issue import issue_receipt, normalize_transaction_id

_SAFE_HOST_RE = re.compile(r"\A(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::\d{1,5})?\Z")
_DEC_UINT_RE = re.compile(r"\A[0-9]+\Z")
MAX_ASGI_CAPTURE_BYTES = 256 * 1024  # 256 KiB safety bound matching FERMI-PAX-04


def _decode_b64_json(raw_b64: str | None) -> dict[str, Any] | None:
    if not raw_b64 or not isinstance(raw_b64, str) or not raw_b64.strip():
        return None
    trimmed = raw_b64.strip()
    pad = "=" * ((4 - (len(trimmed) % 4)) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = json.loads(decoder(trimmed + pad).decode("utf-8"))
            if isinstance(decoded, dict):
                return decoded
        except Exception:
            continue
    return None


def _normalize_caip2_network(raw_net: Any) -> str | None:
    if not isinstance(raw_net, str) or not raw_net.strip():
        return None
    trimmed = raw_net.strip()
    lower = trimmed.lower()
    if lower == "base":
        return "eip155:8453"
    if lower == "base-sepolia":
        return "eip155:84532"
    if lower in ("solana", "solana-mainnet"):
        return "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    if lower == "solana-devnet":
        return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    return trimmed


def _format_usdc_display(atomic_str: str) -> str:
    if not _DEC_UINT_RE.match(atomic_str):
        return "0"
    n = int(atomic_str)
    whole = n // 1_000_000
    frac = f"{n % 1_000_000:06d}".rstrip("0")
    return f"{whole}.{frac}" if frac else str(whole)


def _extract_hdr(hdrs: Any, name: str) -> str:
    if not hdrs:
        return ""
    if hasattr(hdrs, "get") and not isinstance(hdrs, dict):
        val = hdrs.get(name)
        return str(val) if val is not None else ""
    if isinstance(hdrs, dict):
        lower = name.lower()
        for k, v in hdrs.items():
            if str(k).lower() == lower and v is not None:
                return str(v[0] if isinstance(v, list) and v else v)
    return ""


def parse_x402_headers(
    request_headers: Any = None,
    response_headers: Any = None,
    *,
    payment_signature: str = "",
    payment_response: str = "",
    payment_required: str = "",
) -> dict[str, str | None]:
    if request_headers is not None or response_headers is not None:
        payment_signature = payment_signature or _extract_hdr(request_headers, "payment-signature") or _extract_hdr(request_headers, "x-payment")
        payment_required = payment_required or _extract_hdr(request_headers, "payment-required") or _extract_hdr(response_headers, "payment-required")
        payment_response = payment_response or _extract_hdr(response_headers, "payment-response") or _extract_hdr(response_headers, "x-payment-response") or _extract_hdr(request_headers, "payment-response")
    sig_obj = _decode_b64_json(payment_signature)
    res_obj = _decode_b64_json(payment_response)
    req_obj = _decode_b64_json(payment_required)

    accepted = None
    if sig_obj and isinstance(sig_obj.get("accepted"), dict):
        accepted = sig_obj["accepted"]
    elif req_obj and isinstance(req_obj.get("accepts"), list) and req_obj["accepts"]:
        first_acc = req_obj["accepts"][0]
        if isinstance(first_acc, dict):
            accepted = first_acc

    auth = None
    if sig_obj and isinstance(sig_obj.get("payload"), dict):
        maybe_auth = sig_obj["payload"].get("authorization")
        if isinstance(maybe_auth, dict):
            auth = maybe_auth

    tx_hash: str | None = None
    if res_obj:
        raw_tx = res_obj.get("transaction") or res_obj.get("txHash") or res_obj.get("transactionHash")
        if isinstance(raw_tx, str) and raw_tx.strip():
            try:
                tx_hash = normalize_transaction_id(raw_tx.strip())
            except Exception:
                tx_hash = None

    raw_net = (
        (res_obj and (res_obj.get("network") or res_obj.get("networkId")))
        or (accepted and accepted.get("network"))
        or (sig_obj and sig_obj.get("network"))
    )
    network = _normalize_caip2_network(raw_net)

    scheme = (accepted and accepted.get("scheme")) or (sig_obj and sig_obj.get("scheme"))
    asset = accepted and accepted.get("asset")
    raw_amount = None
    if accepted:
        raw_amount = accepted.get("amount") if accepted.get("amount") is not None else accepted.get("maxAmountRequired")
    if raw_amount is None and auth:
        raw_amount = auth.get("value")
    amount_atomic = str(raw_amount) if raw_amount is not None and _DEC_UINT_RE.match(str(raw_amount)) else None

    pay_to = (accepted and accepted.get("payTo")) or (auth and auth.get("to"))
    payer = (res_obj and res_obj.get("payer")) or (auth and auth.get("from"))

    return {
        "txHash": tx_hash,
        "transactionHash": tx_hash,
        "network": network,
        "scheme": str(scheme) if isinstance(scheme, str) and scheme else None,
        "asset": str(asset) if isinstance(asset, str) and asset else None,
        "amountAtomic": amount_atomic,
        "amountDisplay": _format_usdc_display(amount_atomic) if amount_atomic else None,
        "payer": str(payer) if isinstance(payer, str) and payer else None,
        "payTo": str(pay_to) if isinstance(pay_to, str) and pay_to else None,
    }


def _is_json_ct(ct: str) -> bool:
    return not ct or ct == "application/json" or ct.endswith("+json")


class PaxiomReceiptMiddleware:
    """ASGI 3.0 middleware that signs 2xx JSON (`jcs-sha256`) and non-JSON (`raw-sha256`) responses with Payment-Receipt + X-Paxiom-Receipt."""

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        private_key: Any,
        issuer: dict[str, Any],
        service_name: str | None = None,
        base_url: str = "",
        payment_defaults: dict[str, Any] | None = None,
        on_receipt: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if not isinstance(issuer, dict) or not issuer.get("name") or not issuer.get("keyId"):
            raise TypeError("PaxiomReceiptMiddleware requires issuer={'name': ..., 'keyId': ...}")
        self._seed = extract_ed25519_seed(private_key)
        self.app = app
        self.issuer = issuer
        self.service_name = service_name or str(issuer["name"])
        self.base_url = base_url.rstrip("/")
        self.payment_defaults = dict(payment_defaults or {})
        self.on_receipt = on_receipt

    def _resolve_resource(self, scope: dict[str, Any], req_headers: dict[str, str]) -> str:
        raw_path = str(scope.get("path") or "/")
        safe_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        qs = scope.get("query_string") or b""
        suffix = f"{safe_path}?{qs.decode('latin-1')}" if qs else safe_path
        if self.base_url:
            return f"{self.base_url}{suffix}"
        host = req_headers.get("host", "").strip()
        scheme = "https" if scope.get("scheme") == "https" else "http"
        if host and _SAFE_HOST_RE.match(host):
            return f"{scheme}://{host}{suffix}"
        return f"http://localhost{suffix}"

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        req_chunks: list[bytes] = []
        req_total = 0
        req_capped = False

        async def wrapped_receive() -> dict[str, Any]:
            nonlocal req_total, req_capped
            msg = await receive()
            if msg.get("type") == "http.request" and not req_capped:
                chunk = bytes(msg.get("body") or b"")
                if req_total + len(chunk) > MAX_ASGI_CAPTURE_BYTES:
                    req_capped = True
                    req_chunks.clear()
                else:
                    req_chunks.append(chunk)
                    req_total += len(chunk)
            return msg

        start_msg: dict[str, Any] | None = None
        res_chunks: list[bytes] = []
        res_total = 0
        passthrough = False

        async def wrapped_send(msg: dict[str, Any]) -> None:
            nonlocal start_msg, res_total, passthrough
            mtype = msg.get("type")
            if mtype == "http.response.start":
                status = int(msg.get("status", 200))
                hdrs = [(bytes(k), bytes(v)) for k, v in (msg.get("headers") or [])]
                if req_capped or status < 200 or status >= 300:
                    passthrough = True
                    await send(msg)
                else:
                    start_msg = {"type": "http.response.start", "status": status, "headers": hdrs}
                return

            if mtype == "http.response.body":
                if passthrough or start_msg is None:
                    await send(msg)
                    return
                body_part = bytes(msg.get("body") or b"")
                more_body = bool(msg.get("more_body", False))
                if res_total + len(body_part) > MAX_ASGI_CAPTURE_BYTES:
                    passthrough = True
                    await send(start_msg)
                    for prev in res_chunks:
                        await send({"type": "http.response.body", "body": prev, "more_body": True})
                    res_chunks.clear()
                    await send(msg)
                    return

                res_chunks.append(body_part)
                res_total += len(body_part)
                if more_body:
                    return

                full_res_bytes = b"".join(res_chunks)
                hdrs = list(start_msg["headers"])
                try:
                    res_headers_map = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in hdrs}
                    ct_raw = res_headers_map.get("content-type", "").split(";")[0].strip().lower()
                    json_mode = _is_json_ct(ct_raw)
                    skip_sign = False
                    if json_mode:
                        try:
                            output_for_issue: Any = json.loads(full_res_bytes.decode("utf-8"))
                            canon_mode = "jcs-sha256"
                        except Exception:
                            if not ct_raw:
                                output_for_issue = full_res_bytes
                                canon_mode = "raw-sha256"
                            else:
                                skip_sign = True
                    else:
                        output_for_issue = full_res_bytes
                        canon_mode = "raw-sha256"

                    if not skip_sign:
                        req_headers = {
                            bytes(k).decode("latin-1").lower(): bytes(v).decode("latin-1")
                            for k, v in (scope.get("headers") or [])
                        }
                        pay_sig = req_headers.get("payment-signature") or req_headers.get("x-payment") or ""
                        pay_res = res_headers_map.get("payment-response") or res_headers_map.get("x-payment-response") or ""
                        pay_req = res_headers_map.get("payment-required") or ""
                        parsed_x402 = parse_x402_headers(
                            payment_signature=pay_sig,
                            payment_response=pay_res,
                            payment_required=pay_req,
                        )
                        tx_hash = parsed_x402["txHash"]

                        default_settlement = dict(self.payment_defaults.get("settlement") or {})
                        payment_cfg: dict[str, Any] = {
                            "scheme": parsed_x402["scheme"] or "x402",
                            "network": parsed_x402["network"] or "eip155:8453",
                            "asset": parsed_x402["asset"] or "USDC",
                            "amountAtomic": parsed_x402["amountAtomic"] or "0",
                            "amountDisplay": parsed_x402["amountDisplay"] or "0",
                            "paymentPayload": pay_sig or "none",
                        }
                        if parsed_x402["payer"]:
                            payment_cfg["payer"] = parsed_x402["payer"]
                        if parsed_x402["payTo"]:
                            payment_cfg["payTo"] = parsed_x402["payTo"]
                        if pay_req:
                            payment_cfg["paymentRequirements"] = pay_req
                        payment_cfg.update(self.payment_defaults)
                        payment_cfg["settlement"] = {
                            "status": "claimed_not_checked" if tx_hash else ("verify_only" if pay_sig else "not_required"),
                            "transactionHash": tx_hash,
                            "checkedByVerifier": False,
                            **default_settlement,
                        }

                        method = str(scope.get("method") or "GET").upper()
                        resource = self._resolve_resource(scope, req_headers)
                        req_body_bytes = b"".join(req_chunks)
                        mime = ct_raw or ("application/json" if canon_mode == "jcs-sha256" else "application/octet-stream")
                        issued = issue_receipt(
                            private_key=self._seed,
                            issuer=self.issuer,
                            service={"name": self.service_name, "resource": resource, "method": method},
                            request={
                                "method": method,
                                "resource": resource,
                                "body": req_body_bytes if req_body_bytes else "",
                            },
                            payment=payment_cfg,
                            output=output_for_issue,
                            mime_type=mime,
                            canonicalization=canon_mode,
                            status_code=start_msg["status"],
                        )
                        hdr_val_bytes = issued["receiptHeader"].encode("ascii")
                        hdrs.append((STANDARD_RECEIPT_HEADER_NAME.encode("ascii"), hdr_val_bytes))
                        hdrs.append((RECEIPT_HEADER_NAME.encode("ascii"), hdr_val_bytes))
                        expose_idx = next(
                            (i for i, (k, _) in enumerate(hdrs) if k.lower() == b"access-control-expose-headers"),
                            None,
                        )
                        expose_pair = "Payment-Receipt, X-Paxiom-Receipt"
                        if expose_idx is None:
                            hdrs.append((b"access-control-expose-headers", expose_pair.encode("ascii")))
                        else:
                            cur_exp = hdrs[expose_idx][1].decode("latin-1")
                            parts = [p.strip() for p in cur_exp.split(",") if p.strip()]
                            lower_parts = {p.lower() for p in parts}
                            for hname in ("Payment-Receipt", "X-Paxiom-Receipt"):
                                if hname.lower() not in lower_parts:
                                    parts.append(hname)
                            hdrs[expose_idx] = (hdrs[expose_idx][0], ", ".join(parts).encode("latin-1"))

                        if callable(self.on_receipt):
                            try:
                                self.on_receipt(issued["receipt"])
                            except Exception:
                                pass
                except Exception:
                    pass

                await send({"type": "http.response.start", "status": start_msg["status"], "headers": hdrs})
                await send({"type": "http.response.body", "body": full_res_bytes, "more_body": False})
                return

            await send(msg)

        await self.app(scope, wrapped_receive, wrapped_send)
