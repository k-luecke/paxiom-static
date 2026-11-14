"""Zero-dependency ASGI 3.0 middleware (FastAPI / Starlette / Litestar) for paxiom.receipt.v0."""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable

from .client import RECEIPT_HEADER_NAME
from .ed25519_pure import extract_ed25519_seed
from .issue import issue_receipt

_SAFE_HOST_RE = re.compile(r"\A(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::\d{1,5})?\Z")
_TX_HASH_RE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z")
MAX_ASGI_CAPTURE_BYTES = 256 * 1024  # 256 KiB safety bound matching FERMI-PAX-04


def _try_decode_payment_response_tx(raw_b64: str | None) -> str | None:
    if not raw_b64:
        return None
    try:
        pad = "=" * ((4 - (len(raw_b64) % 4)) % 4)
        decoded = json.loads(base64.b64decode(raw_b64 + pad).decode("utf-8"))
        if isinstance(decoded, dict):
            tx = decoded.get("transaction") or decoded.get("txHash") or decoded.get("transactionHash")
            if isinstance(tx, str) and _TX_HASH_RE.match(tx):
                return tx.lower()
    except Exception:
        return None
    return None


class PaxiomReceiptMiddleware:
    """ASGI 3.0 middleware that signs 2xx JSON responses with X-Paxiom-Receipt."""

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
        # Fail fast at startup if private_key is missing or invalid
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
                ct = ""
                for k, v in hdrs:
                    if k.lower() == b"content-type":
                        ct = v.decode("latin-1").split(";")[0].strip().lower()
                        break
                if req_capped or status < 200 or status >= 300 or (ct and ct != "application/json"):
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
                    # Exceeded capture bound -> flush buffered start + chunks untouched without signing
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
                    parsed_output = json.loads(full_res_bytes.decode("utf-8"))
                    req_headers = {
                        bytes(k).decode("latin-1").lower(): bytes(v).decode("latin-1")
                        for k, v in (scope.get("headers") or [])
                    }
                    res_headers_map = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in hdrs}
                    pay_sig = req_headers.get("payment-signature") or req_headers.get("x-payment") or ""
                    pay_res = res_headers_map.get("payment-response") or res_headers_map.get("x-payment-response") or ""
                    tx_hash = _try_decode_payment_response_tx(pay_res)

                    default_settlement = dict(self.payment_defaults.get("settlement") or {})
                    payment_cfg = {
                        "scheme": "x402",
                        "network": "base",
                        "asset": "USDC",
                        "amountAtomic": "0",
                        "amountDisplay": "0",
                        "paymentPayload": pay_sig or "none",
                        **self.payment_defaults,
                        "settlement": {
                            "status": "claimed_not_checked" if tx_hash else ("verify_only" if pay_sig else "not_required"),
                            "transactionHash": tx_hash,
                            "checkedByPaxiom": False,
                            **default_settlement,
                        },
                    }
                    method = str(scope.get("method") or "GET").upper()
                    resource = self._resolve_resource(scope, req_headers)
                    req_body_bytes = b"".join(req_chunks)
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
                        output=parsed_output,
                        mime_type=res_headers_map.get("content-type", "application/json").split(";")[0].strip() or "application/json",
                    )
                    hdrs.append((RECEIPT_HEADER_NAME.encode("ascii"), issued["receiptHeader"].encode("ascii")))
                    expose_idx = next((i for i, (k, _) in enumerate(hdrs) if k.lower() == b"access-control-expose-headers"), None)
                    if expose_idx is None:
                        hdrs.append((b"access-control-expose-headers", RECEIPT_HEADER_NAME.encode("ascii")))
                    else:
                        cur_exp = hdrs[expose_idx][1].decode("latin-1")
                        if RECEIPT_HEADER_NAME not in cur_exp.lower():
                            hdrs[expose_idx] = (
                                hdrs[expose_idx][0],
                                f"{cur_exp}, {RECEIPT_HEADER_NAME}".encode("latin-1"),
                            )
                    if callable(self.on_receipt):
                        try:
                            self.on_receipt(issued["receipt"])
                        except Exception:
                            pass
                except Exception:
                    # Non-JSON body -> emit response untouched
                    pass

                await send({"type": "http.response.start", "status": start_msg["status"], "headers": hdrs})
                await send({"type": "http.response.body", "body": full_res_bytes, "more_body": False})
                return

            await send(msg)

        await self.app(scope, wrapped_receive, wrapped_send)
