"""Zero-dependency Buyer Policy Firewall (Gate 1) & AuthCaptureEscrow Delivery Arbiter (Gate 2)."""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from .canonicalize import hash_canonical, sha256_hex
from .issue import decode_receipt_header
from .verify import verify_receipt

DEC_UINT_RE = re.compile(r"^[0-9]+$")
EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

STANDARD_RECEIPT_HEADER_NAME = "payment-receipt"
RECEIPT_HEADER_NAME = "x-paxiom-receipt"

ESCROW_SCHEMES = ("auth-capture", "auth_capture", "commerce-escrow", "escrow")
DEFAULT_ALLOWED_SCHEMES = ("exact", "auth-capture", "upto", "batch-settlement")

DEFAULT_WINDOW_MS = 60 * 60 * 1000
DEFAULT_COOLDOWN_MS = 5 * 60 * 1000
DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MIN_AUTH_WINDOW_SEC = 30
DEFAULT_MAX_AUTH_WINDOW_SEC = 7 * 24 * 60 * 60
MAX_FEE_BPS_CEILING = 10_000


def _normalize_pay_to(addr: str) -> str:
    s = str(addr).strip()
    return s.lower() if EVM_ADDRESS_RE.match(s) else s


def _canonical_scheme(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    low = raw.strip().lower()
    return "auth-capture" if low in ESCROW_SCHEMES else low


def normalize_caip2_network_id(raw_net: Any) -> str | None:
    if not isinstance(raw_net, str) or not raw_net.strip():
        return None
    trimmed = raw_net.strip()
    low = trimmed.lower()
    if low == "base":
        return "eip155:8453"
    if low == "base-sepolia":
        return "eip155:84532"
    if low in ("ethereum", "mainnet"):
        return "eip155:1"
    if low in ("solana", "solana-mainnet"):
        return "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    if low == "solana-devnet":
        return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    return trimmed


def parse_atomic_int(value: Any, label: str = "amount") -> int:
    if isinstance(value, bool):
        raise TypeError(f"{label} must be an int or decimal string, not bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{label} must be non-negative")
        return value
    if isinstance(value, str):
        trimmed = value.strip()
        if not DEC_UINT_RE.match(trimmed):
            raise TypeError(f'{label} must be a canonical non-negative integer string, got "{value}"')
        return int(trimmed, 10)
    raise TypeError(f"{label} must be a non-negative int or integer string")


def _try_parse_atomic_int(value: Any) -> int | None:
    try:
        return parse_atomic_int(value)
    except (TypeError, ValueError):
        return None


def resolve_firewall_origin(raw_url: str, *, allow_loopback_http: bool = False) -> dict[str, Any]:
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {"ok": False, "code": "invalid_origin", "reason": "Target URL must be a non-empty string."}
    parsed = urlsplit(raw_url.strip())
    if not parsed.scheme or not parsed.netloc or not parsed.hostname:
        return {"ok": False, "code": "invalid_origin", "reason": f"Invalid target URL: {raw_url}"}
    if parsed.username or parsed.password:
        return {"ok": False, "code": "invalid_origin", "reason": "Target URL must not contain embedded credentials."}
    host_low = parsed.hostname.strip("[]").lower()
    is_loopback = host_low in ("127.0.0.1", "localhost", "::1")
    scheme_low = parsed.scheme.lower()
    if scheme_low != "https" and not (allow_loopback_http and scheme_low == "http" and is_loopback):
        return {
            "ok": False,
            "code": "insecure_transport",
            "reason": "Target URL must use https:// (http:// is allowed only on loopback when allow_loopback_http is True).",
        }
    port_suffix = f":{parsed.port}" if parsed.port and not (
        (scheme_low == "https" and parsed.port == 443) or (scheme_low == "http" and parsed.port == 80)
    ) else ""
    host_fmt = f"[{host_low}]" if ":" in host_low else host_low
    origin = f"{scheme_low}://{host_fmt}{port_suffix}"
    return {"ok": True, "origin": origin, "parsed": parsed}


def _decode_flexible_b64_json(raw: str) -> dict[str, Any] | None:
    s = raw.strip()
    if not s:
        return None
    pad = "=" * ((4 - len(s) % 4) % 4)
    for candidate in (s + pad, s.replace("-", "+").replace("_", "/") + pad):
        try:
            decoded = base64.b64decode(candidate, validate=False).decode("utf-8")
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _extract_header(headers_or_resp: Any, name: str) -> str | None:
    if headers_or_resp is None:
        return None
    hdrs = getattr(headers_or_resp, "headers", None)
    if hdrs is None and isinstance(headers_or_resp, dict):
        hdrs = headers_or_resp.get("headers", headers_or_resp)
    if not isinstance(hdrs, dict) and hasattr(hdrs, "items"):
        hdrs = dict(hdrs.items())
    if not isinstance(hdrs, dict):
        return None
    target = name.lower()
    for k, v in hdrs.items():
        if str(k).lower() == target and v is not None:
            return str(v[0] if isinstance(v, list) else v)
    return None


def _normalize_single_requirement(req_obj: Any, envelope: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not isinstance(req_obj, dict):
        return None
    env = envelope or {}
    scheme = _canonical_scheme(req_obj.get("scheme") or env.get("scheme"))
    network = normalize_caip2_network_id(req_obj.get("network") or req_obj.get("networkId") or env.get("network"))
    raw_asset = req_obj.get("asset") if req_obj.get("asset") is not None else req_obj.get("token")
    asset = raw_asset.strip() if isinstance(raw_asset, str) and raw_asset.strip() else None
    extra = req_obj.get("extra") if isinstance(req_obj.get("extra"), dict) else {}
    pay_info = extra.get("paymentInfo") if isinstance(extra.get("paymentInfo"), dict) else extra
    raw_pay_to = req_obj.get("payTo") or req_obj.get("receiver") or extra.get("receiver")
    pay_to = raw_pay_to.strip() if isinstance(raw_pay_to, str) and raw_pay_to.strip() else None

    raw_amt = (
        req_obj.get("amount")
        if req_obj.get("amount") is not None
        else (
            req_obj.get("maxAmountRequired")
            if req_obj.get("maxAmountRequired") is not None
            else (req_obj.get("maxAmount") if req_obj.get("maxAmount") is not None else extra.get("maxAmount"))
        )
    )
    amt_int = _try_parse_atomic_int(raw_amt) if raw_amt is not None else None

    auth_capture = None
    if scheme == "auth-capture" or pay_info.get("operator") or req_obj.get("operator"):
        raw_op = pay_info.get("operator") or req_obj.get("operator")
        raw_min_fee = pay_info.get("minFeeBps", req_obj.get("minFeeBps", 0))
        raw_max_fee = pay_info.get("maxFeeBps", req_obj.get("maxFeeBps"))
        raw_auth_exp = pay_info.get("authorizationExpiry", req_obj.get("authorizationExpiry"))
        raw_info_hash = pay_info.get("paymentInfoHash") or extra.get("paymentInfoHash") or req_obj.get("paymentInfoHash")
        auth_capture = {
            "operator": raw_op.strip() if isinstance(raw_op, str) and raw_op.strip() else None,
            "minFeeBps": _try_parse_atomic_int(raw_min_fee) if raw_min_fee is not None else None,
            "maxFeeBps": _try_parse_atomic_int(raw_max_fee) if raw_max_fee is not None else None,
            "authorizationExpiry": _try_parse_atomic_int(raw_auth_exp) if raw_auth_exp is not None else None,
            "paymentInfoHash": raw_info_hash.strip().lower()
            if isinstance(raw_info_hash, str) and HEX32_RE.match(raw_info_hash.strip())
            else None,
        }

    return {
        "scheme": scheme,
        "network": network,
        "asset": asset,
        "payTo": pay_to,
        "amountAtomic": amt_int,
        "amountAtomicString": str(amt_int) if amt_int is not None else None,
        "authCapture": auth_capture,
        "rawRequirement": req_obj,
    }


def extract_payment_challenges(source: Any) -> list[dict[str, Any]]:
    if not source:
        return []
    obj: dict[str, Any] | None = None
    if isinstance(source, str):
        obj = _decode_flexible_b64_json(source)
        if obj is None:
            try:
                parsed = json.loads(source)
                if isinstance(parsed, dict):
                    obj = parsed
            except Exception:
                obj = None
    elif isinstance(source, dict):
        hdr = _extract_header(source, "payment-required") or _extract_header(source, "x-payment-required")
        if hdr:
            obj = _decode_flexible_b64_json(hdr)
        if obj is None and isinstance(source.get("body"), dict):
            obj = source["body"]
        if obj is None and "headers" not in source:
            obj = source
    else:
        hdr = _extract_header(source, "payment-required") or _extract_header(source, "x-payment-required")
        if hdr:
            obj = _decode_flexible_b64_json(hdr)

    if not isinstance(obj, dict):
        return []
    if isinstance(obj.get("accepts"), list):
        return [c for c in (_normalize_single_requirement(it, obj) for it in obj["accepts"]) if c is not None]
    single = _normalize_single_requirement(obj, obj)
    return [single] if single is not None else []


@dataclass
class _OriginState:
    entries: list[tuple[int, int]] = field(default_factory=list)
    reserved_atomic: int = 0
    consecutive_failures: int = 0
    cooldown_until_ms: int = 0
    last_failure_reason: str | None = None


class MemorySpendLedger:
    """Reservation-safe atomic spend & per-origin circuit-breaker ledger."""

    def __init__(
        self,
        *,
        window_ms: int = DEFAULT_WINDOW_MS,
        max_tracked_origins: int = 1024,
        max_tracked_receipts: int = 4096,
    ) -> None:
        self.window_ms = max(1, int(window_ms))
        self._max_origins = max(1, int(max_tracked_origins))
        self._max_receipts = max(1, int(max_tracked_receipts))
        self._committed_session = 0
        self._reserved_session = 0
        self._seq = 0
        self._origins: dict[str, _OriginState] = {}
        self._reservations: dict[str, dict[str, Any]] = {}
        self._seen_receipts: dict[str, None] = {}

    def _now_ms(self, now_ms: int | None) -> int:
        return int(now_ms) if now_ms is not None else int(time.time() * 1000)

    def _origin_state(self, origin: str) -> _OriginState:
        key = origin.lower()
        st = self._origins.get(key)
        if st is None:
            if len(self._origins) >= self._max_origins:
                for old_k, old_st in list(self._origins.items()):
                    if old_st.reserved_atomic == 0:
                        del self._origins[old_k]
                        break
            st = _OriginState()
            self._origins[key] = st
        return st

    def _prune(self, st: _OriginState, now_ms: int) -> int:
        cutoff = now_ms - self.window_ms
        st.entries = [(ts, amt) for (ts, amt) in st.entries if ts > cutoff]
        return sum(amt for _, amt in st.entries)

    def is_circuit_open(self, origin: str, now_ms: int | None = None) -> dict[str, Any]:
        t = self._now_ms(now_ms)
        st = self._origins.get(origin.lower())
        if st is None:
            return {"open": False, "cooldownUntilMs": 0, "consecutiveFailures": 0, "lastFailureReason": None}
        is_open = st.cooldown_until_ms > t
        return {
            "open": is_open,
            "cooldownUntilMs": st.cooldown_until_ms if is_open else 0,
            "consecutiveFailures": st.consecutive_failures,
            "lastFailureReason": st.last_failure_reason,
        }

    def get_usage(self, origin: str, now_ms: int | None = None) -> dict[str, int]:
        t = self._now_ms(now_ms)
        st = self._origins.get(origin.lower())
        win = self._prune(st, t) if st else 0
        res = st.reserved_atomic if st else 0
        return {
            "committedSessionAtomic": self._committed_session,
            "reservedSessionAtomic": self._reserved_session,
            "activeSessionAtomic": self._committed_session + self._reserved_session,
            "originCommittedWindowAtomic": win,
            "originReservedAtomic": res,
            "activeOriginWindowAtomic": win + res,
        }

    def reserve(
        self,
        *,
        origin: str,
        amount_atomic: int | str,
        scheme: str = "exact",
        now_ms: int | None = None,
    ) -> str:
        t = self._now_ms(now_ms)
        amt = parse_atomic_int(amount_atomic, "amount_atomic")
        st = self._origin_state(origin)
        self._prune(st, t)
        self._seq += 1
        rid = f"rsv_{t}_{self._seq}"
        st.reserved_atomic += amt
        self._reserved_session += amt
        self._reservations[rid] = {
            "origin": origin.lower(),
            "amountAtomic": amt,
            "scheme": _canonical_scheme(scheme) or "exact",
        }
        return rid

    def commit(
        self,
        reservation_id: str,
        *,
        actual_amount_atomic: int | str | None = None,
        receipt_hash: str | None = None,
        now_ms: int | None = None,
    ) -> bool:
        t = self._now_ms(now_ms)
        rsv = self._reservations.pop(reservation_id, None)
        if rsv is None:
            return False
        st = self._origin_state(rsv["origin"])
        st.reserved_atomic -= rsv["amountAtomic"]
        self._reserved_session -= rsv["amountAtomic"]
        settled = (
            parse_atomic_int(actual_amount_atomic, "actual_amount_atomic")
            if actual_amount_atomic is not None
            else rsv["amountAtomic"]
        )
        if settled > 0:
            st.entries.append((t, settled))
            self._committed_session += settled
        st.consecutive_failures = 0
        st.cooldown_until_ms = 0
        st.last_failure_reason = None
        if receipt_hash:
            self.record_receipt(receipt_hash)
        return True

    def release(
        self,
        reservation_id: str,
        *,
        record_failure: bool = False,
        failure_reason: str | None = None,
        retain_outlay_in_budget: bool = False,
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
        cooldown_ms: int = DEFAULT_COOLDOWN_MS,
        now_ms: int | None = None,
    ) -> bool:
        t = self._now_ms(now_ms)
        rsv = self._reservations.pop(reservation_id, None)
        if rsv is None:
            return False
        st = self._origin_state(rsv["origin"])
        st.reserved_atomic -= rsv["amountAtomic"]
        self._reserved_session -= rsv["amountAtomic"]
        if retain_outlay_in_budget and rsv["amountAtomic"] > 0:
            st.entries.append((t, rsv["amountAtomic"]))
            self._committed_session += rsv["amountAtomic"]
        if record_failure:
            st.consecutive_failures += 1
            st.last_failure_reason = failure_reason or "delivery_rejected"
            if st.consecutive_failures >= max_consecutive_failures:
                st.cooldown_until_ms = t + cooldown_ms
        return True

    def record_origin_failure(
        self,
        origin: str,
        *,
        failure_reason: str = "delivery_rejected",
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
        cooldown_ms: int = DEFAULT_COOLDOWN_MS,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        t = self._now_ms(now_ms)
        st = self._origin_state(origin)
        st.consecutive_failures += 1
        st.last_failure_reason = failure_reason
        if st.consecutive_failures >= max_consecutive_failures:
            st.cooldown_until_ms = t + cooldown_ms
        return {
            "consecutiveFailures": st.consecutive_failures,
            "cooldownUntilMs": st.cooldown_until_ms,
            "circuitTripped": st.cooldown_until_ms > t,
        }

    def has_seen_receipt(self, receipt_hash: str) -> bool:
        return bool(receipt_hash) and receipt_hash.lower() in self._seen_receipts

    def record_receipt(self, receipt_hash: str) -> None:
        if not receipt_hash:
            return
        norm = receipt_hash.lower()
        if norm in self._seen_receipts:
            return
        if len(self._seen_receipts) >= self._max_receipts:
            oldest = next(iter(self._seen_receipts))
            del self._seen_receipts[oldest]
        self._seen_receipts[norm] = None

    def snapshot(self, now_ms: int | None = None) -> dict[str, Any]:
        t = self._now_ms(now_ms)
        origins_snap = {}
        for k, st in self._origins.items():
            win = self._prune(st, t)
            origins_snap[k] = {
                "committedWindowAtomic": win,
                "reservedAtomic": st.reserved_atomic,
                "consecutiveFailures": st.consecutive_failures,
                "cooldownUntilMs": st.cooldown_until_ms,
                "circuitOpen": st.cooldown_until_ms > t,
                "lastFailureReason": st.last_failure_reason,
            }
        return {
            "committedSessionAtomic": self._committed_session,
            "reservedSessionAtomic": self._reserved_session,
            "activeSessionAtomic": self._committed_session + self._reserved_session,
            "activeReservations": len(self._reservations),
            "trackedReceiptHashes": len(self._seen_receipts),
            "origins": origins_snap,
        }


def _evaluate_candidate(
    cand: dict[str, Any],
    origin: str,
    policy: dict[str, Any],
    caps: dict[str, int | None],
    now_sec: int,
) -> tuple[bool, str, str]:
    if not cand.get("scheme") or not cand.get("network") or not cand.get("payTo") or cand.get("amountAtomic") is None:
        return False, "malformed_challenge", "402 challenge missing scheme, network, payTo, or integer amount."
    amt: int = cand["amountAtomic"]
    if amt == 0 and not policy.get("allowZeroAmount", False):
        return False, "malformed_challenge", "Zero-amount 402 payment challenge is disallowed."

    raw_schemes = policy.get("allowedSchemes")
    allowed_schemes = (
        [_canonical_scheme(s) for s in raw_schemes if _canonical_scheme(s)]
        if isinstance(raw_schemes, list) and raw_schemes
        else list(DEFAULT_ALLOWED_SCHEMES)
    )
    if cand["scheme"] not in allowed_schemes:
        return False, "scheme_not_allowed", f'Scheme "{cand["scheme"]}" is not in allowedSchemes.'

    raw_nets = policy.get("allowedNetworks")
    if isinstance(raw_nets, list) and raw_nets:
        norm_nets = {normalize_caip2_network_id(n) for n in raw_nets}
        if cand["network"] not in norm_nets:
            return False, "network_not_allowed", f'Network "{cand["network"]}" is not in allowedNetworks.'

    raw_assets = policy.get("allowedAssets")
    if isinstance(raw_assets, list) and raw_assets:
        norm_assets = {_normalize_pay_to(str(a)) for a in raw_assets}
        if not cand.get("asset") or _normalize_pay_to(str(cand["asset"])) not in norm_assets:
            return False, "asset_not_allowed", f'Asset "{cand.get("asset")}" is not in allowedAssets.'

    norm_cand_pay_to = _normalize_pay_to(cand["payTo"])
    pinned_map = policy.get("pinnedPayToByOrigin")
    if isinstance(pinned_map, dict):
        for k, v in pinned_map.items():
            if str(k).lower() == origin:
                vals = v if isinstance(v, list) else [v]
                if norm_cand_pay_to not in {_normalize_pay_to(str(x)) for x in vals}:
                    return False, "untrusted_pay_to", f'payTo ({cand["payTo"]}) does not match pinnedPayToByOrigin.'
                break

    allowed_pay_to = policy.get("allowedPayTo")
    if isinstance(allowed_pay_to, list) and allowed_pay_to:
        if norm_cand_pay_to not in {_normalize_pay_to(str(x)) for x in allowed_pay_to}:
            return False, "untrusted_pay_to", f'payTo ({cand["payTo"]}) is not in allowedPayTo.'

    if caps["maxPerCallAtomic"] is not None and amt > caps["maxPerCallAtomic"]:
        return False, "per_call_cap_exceeded", f"Amount ({amt}) exceeds maxPerCallAtomic ({caps['maxPerCallAtomic']})."

    if cand["scheme"] == "exact" and caps["maxUnescrowedExactAtomic"] is not None and amt > caps["maxUnescrowedExactAtomic"]:
        return (
            False,
            "escrow_required_above_microcap",
            f"Irreversible exact amount ({amt}) exceeds maxUnescrowedExactAtomic ({caps['maxUnescrowedExactAtomic']}).",
        )

    if cand["scheme"] == "auth-capture":
        ac = cand.get("authCapture") or {}
        op = ac.get("operator")
        if not op or not EVM_ADDRESS_RE.match(op):
            return False, "invalid_escrow_terms", "auth-capture challenge missing valid EVM operator."
        trusted_ops = policy.get("trustedOperators")
        if isinstance(trusted_ops, list) and trusted_ops:
            if _normalize_pay_to(op) not in {_normalize_pay_to(x) for x in trusted_ops}:
                return False, "untrusted_escrow_operator", f"Escrow operator ({op}) is not in trustedOperators."
        elif not policy.get("allowUnpinnedEscrowOperator", False):
            return False, "untrusted_escrow_operator", "auth-capture requires trustedOperators."

        min_fee = ac.get("minFeeBps")
        max_fee = ac.get("maxFeeBps")
        if min_fee is None or max_fee is None or min_fee > max_fee:
            return False, "invalid_escrow_terms", "auth-capture requires integer minFeeBps <= maxFeeBps."
        fee_cap = caps["maxAllowedFeeBps"] if caps["maxAllowedFeeBps"] is not None else MAX_FEE_BPS_CEILING
        if max_fee > fee_cap:
            return False, "escrow_fee_cap_exceeded", f"Escrow maxFeeBps ({max_fee}) exceeds maxAllowedFeeBps ({fee_cap})."

        min_win = int(policy.get("minAuthWindowSec", DEFAULT_MIN_AUTH_WINDOW_SEC))
        max_win = int(policy.get("maxAuthWindowSec", DEFAULT_MAX_AUTH_WINDOW_SEC))
        auth_exp = ac.get("authorizationExpiry")
        if auth_exp is None or auth_exp < now_sec + min_win or auth_exp > now_sec + max_win:
            return False, "escrow_expiry_out_of_bounds", f"Escrow authorizationExpiry ({auth_exp}) out of bounds."

    return True, "allowed", "ok"


def evaluate_pre_sign_policy(
    input_data: dict[str, Any],
    policy: dict[str, Any],
    ledger: MemorySpendLedger | None = None,
) -> dict[str, Any]:
    """Gate 1: Evaluate a 402 payment challenge before invoking any wallet signer."""
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict")
    caps: dict[str, int | None] = {
        k: parse_atomic_int(policy[k], k) if policy.get(k) is not None else None
        for k in (
            "maxPerCallAtomic",
            "maxPerOriginWindowAtomic",
            "maxSessionAtomic",
            "maxUnescrowedExactAtomic",
            "maxAllowedFeeBps",
        )
    }
    if caps["maxAllowedFeeBps"] is not None and caps["maxAllowedFeeBps"] > MAX_FEE_BPS_CEILING:
        raise ValueError("maxAllowedFeeBps cannot exceed 10000")

    now_ms = int(input_data.get("nowMs", int(time.time() * 1000)))
    now_sec = now_ms // 1000

    def deny(code: str, reason: str, origin: str | None = None, challenge: Any = None) -> dict[str, Any]:
        return {
            "allow": False,
            "code": code,
            "reason": reason,
            "origin": origin,
            "challenge": challenge,
            "reservationId": None,
            "reservedAtomic": 0,
        }

    orig_res = resolve_firewall_origin(
        str(input_data.get("url", "")),
        allow_loopback_http=bool(policy.get("allowLoopbackHttp", False)),
    )
    if not orig_res["ok"]:
        return deny(orig_res["code"], orig_res["reason"])
    origin: str = orig_res["origin"]

    denied = policy.get("deniedOrigins")
    if isinstance(denied, list) and origin in {str(x).lower() for x in denied}:
        return deny("origin_denied", f"Origin {origin} is denied.", origin)
    allowed = policy.get("allowedOrigins")
    if isinstance(allowed, list) and allowed and origin not in {str(x).lower() for x in allowed}:
        return deny("origin_not_allowed", f"Origin {origin} is not in allowedOrigins.", origin)

    if ledger is not None:
        cb = ledger.is_circuit_open(origin, now_ms)
        if cb["open"]:
            return deny("circuit_breaker_open", f"Circuit breaker open for {origin}.", origin)

    candidates = extract_payment_challenges(input_data.get("challenge") or input_data.get("response"))
    if not candidates:
        return deny("malformed_challenge", "No decodable x402 payment challenge found.", origin)

    if caps["maxUnescrowedExactAtomic"] is not None:
        candidates = sorted(
            candidates,
            key=lambda c: 0
            if (c.get("amountAtomic") or 0) > caps["maxUnescrowedExactAtomic"] and c.get("scheme") == "auth-capture"
            else 1,
        )

    selected = None
    first_err: tuple[str, str, dict[str, Any]] | None = None
    for cand in candidates:
        ok, code, reason = _evaluate_candidate(cand, origin, policy, caps, now_sec)
        if ok:
            selected = cand
            break
        if first_err is None:
            first_err = (code, reason, cand)

    if selected is None:
        assert first_err is not None
        return deny(first_err[0], first_err[1], origin, first_err[2])

    amt = selected["amountAtomic"]
    if ledger is not None:
        usage = ledger.get_usage(origin, now_ms)
        if caps["maxPerOriginWindowAtomic"] is not None and usage["activeOriginWindowAtomic"] + amt > caps["maxPerOriginWindowAtomic"]:
            return deny("origin_window_cap_exceeded", "Origin rolling cap exceeded.", origin, selected)
        if caps["maxSessionAtomic"] is not None and usage["activeSessionAtomic"] + amt > caps["maxSessionAtomic"]:
            return deny("session_budget_exceeded", "Session budget ceiling exceeded.", origin, selected)
        rid = ledger.reserve(origin=origin, amount_atomic=amt, scheme=selected["scheme"], now_ms=now_ms)
    else:
        rid = None

    return {
        "allow": True,
        "code": "allowed",
        "reason": f'Authorized {selected["scheme"]} challenge for {amt} atomic units.',
        "origin": origin,
        "challenge": selected,
        "reservationId": rid,
        "reservedAtomic": amt,
    }


def evaluate_delivery_arbiter(
    input_data: dict[str, Any],
    *,
    ledger: MemorySpendLedger | None = None,
    expected_issuer_public_keys: list[str] | set[str] | None = None,
    expected_pay_to: str | None = None,
    trusted_verifier_public_keys: list[str] | None = None,
    require_receipt: bool = True,
    allow_unchecked_settlement_claim: bool = True,
    validate_content: Callable[[Any, dict[str, Any]], Any] | None = None,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
    cooldown_ms: int = DEFAULT_COOLDOWN_MS,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Gate 2: Deterministic CAPTURE vs VOID arbiter over HTTP delivery + Payment-Receipt + predicate."""
    t_ms = int(now_ms) if now_ms is not None else int(time.time() * 1000)
    reservation_id = input_data.get("reservationId")
    challenge = input_data.get("challenge")
    scheme = _canonical_scheme((challenge or {}).get("scheme") or input_data.get("scheme") or "auth-capture") or "auth-capture"
    finality = "irreversible_exact" if scheme == "exact" else "escrow_hold"
    pay_info_hash = ((challenge or {}).get("authCapture") or {}).get("paymentInfoHash") or input_data.get("paymentInfoHash")

    origin = input_data.get("origin")
    req_spec = input_data.get("request")
    if not origin and isinstance(req_spec, dict) and req_spec.get("url"):
        orig_check = resolve_firewall_origin(str(req_spec["url"]), allow_loopback_http=True)
        if orig_check["ok"]:
            origin = orig_check["origin"]

    resp = input_data.get("response") or {}
    status = int(resp.get("status", 200)) if isinstance(resp, dict) else int(getattr(resp, "status_code", 200))
    raw_body = input_data.get("bodyBytes", input_data.get("body", b""))
    if isinstance(raw_body, (bytes, bytearray)):
        raw_bytes = bytes(raw_body)
    elif isinstance(raw_body, str):
        raw_bytes = raw_body.encode("utf-8")
    else:
        raw_bytes = json.dumps(raw_body).encode("utf-8")

    def settle_void(
        code: str,
        reason: str,
        *,
        receipt: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
        raw_header: str | None = None,
        parsed_out: Any = None,
    ) -> dict[str, Any]:
        if ledger is not None:
            if reservation_id:
                ledger.release(
                    reservation_id,
                    record_failure=True,
                    failure_reason=code,
                    retain_outlay_in_budget=(finality == "irreversible_exact"),
                    max_consecutive_failures=max_consecutive_failures,
                    cooldown_ms=cooldown_ms,
                    now_ms=t_ms,
                )
            elif origin:
                ledger.record_origin_failure(
                    origin,
                    failure_reason=code,
                    max_consecutive_failures=max_consecutive_failures,
                    cooldown_ms=cooldown_ms,
                    now_ms=t_ms,
                )
        checks = (verification or {}).get("checks") or {}
        non_repudiable = checks.get("signature") == "pass" and checks.get("outputHash") == "pass"
        sig_block = (receipt or {}).get("signature") or {}
        payload_block = (receipt or {}).get("payload") or {}
        fraud = {
            "recordedAt": datetime.fromtimestamp(t_ms / 1000, tz=timezone.utc).isoformat(),
            "reasonCode": code,
            "reason": reason,
            "nonRepudiable": non_repudiable,
            "origin": origin,
            "status": status,
            "paymentInfoHash": pay_info_hash,
            "settlementFinality": finality,
            "issuerKeyId": sig_block.get("keyId"),
            "issuerPublicKey": sig_block.get("publicKey"),
            "receiptId": payload_block.get("receiptId"),
            "receiptHash": (verification or {}).get("receiptHash"),
            "claimedOutputHash": (payload_block.get("delivery") or {}).get("outputHash"),
            "observedBodySha256": sha256_hex(raw_bytes),
            "rawReceiptHeader": raw_header,
        }
        return {
            "action": "VOID",
            "ok": False,
            "reasonCode": code,
            "reason": reason,
            "settlementFinality": finality,
            "paymentInfoHash": pay_info_hash,
            "captureAmountAtomic": 0,
            "receipt": receipt,
            "receiptHash": (verification or {}).get("receiptHash"),
            "verification": verification,
            "parsedOutput": parsed_out,
            "fraudEvidence": fraud,
        }

    if status < 200 or status >= 300:
        return settle_void("http_error_after_auth", f"Upstream returned HTTP {status}.")
    if len(raw_bytes) > max_response_bytes:
        return settle_void("response_too_large", "Response body exceeds max_response_bytes.")

    raw_hdr = (
        _extract_header(resp, STANDARD_RECEIPT_HEADER_NAME)
        or _extract_header(resp, RECEIPT_HEADER_NAME)
        or input_data.get("receiptHeader")
    )
    receipt = input_data.get("receipt")
    if receipt is None and raw_hdr:
        try:
            receipt = decode_receipt_header(raw_hdr)
        except Exception as exc:
            return settle_void("malformed_receipt_header", f"Malformed Payment-Receipt: {exc}", raw_header=raw_hdr)

    if receipt is None and require_receipt:
        return settle_void("missing_delivery_receipt", "Seller omitted required Payment-Receipt header.")

    parsed_output: Any = raw_bytes
    verification: dict[str, Any] | None = None

    if receipt is not None:
        canon_mode = ((receipt.get("payload") or {}).get("delivery") or {}).get("canonicalization") or "jcs-sha256"
        if canon_mode == "jcs-sha256":
            try:
                parsed_output = json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                return settle_void("invalid_json_output", "Invalid UTF-8 JSON for jcs-sha256 receipt.", receipt=receipt, raw_header=raw_hdr)

        eff_pay_to = expected_pay_to or (challenge or {}).get("payTo")
        verification = verify_receipt(
            receipt,
            output=parsed_output if canon_mode == "jcs-sha256" else raw_bytes,
            expected_issuer_public_keys=list(expected_issuer_public_keys) if expected_issuer_public_keys is not None else None,
            expected_pay_to=eff_pay_to,
            trusted_verifier_public_keys=trusted_verifier_public_keys,
        )
        ts = verification.get("trustState")
        checks = verification.get("checks") or {}
        accepted = ts == "verified" or (
            allow_unchecked_settlement_claim
            and ts == "settlement_claimed_not_checked"
            and checks.get("signature") == "pass"
            and checks.get("outputHash") == "pass"
            and checks.get("issuerAuthorization") != "fail"
        )
        if not accepted:
            return settle_void(
                f"receipt_{ts}",
                str(verification.get("summary") or ts),
                receipt=receipt,
                verification=verification,
                raw_header=raw_hdr,
                parsed_out=parsed_output,
            )

        r_hash = verification.get("receiptHash")
        if ledger is not None and r_hash and ledger.has_seen_receipt(r_hash):
            return settle_void(
                "replayed_receipt",
                f"Replay detected for receiptHash {r_hash}.",
                receipt=receipt,
                verification=verification,
                raw_header=raw_hdr,
                parsed_out=parsed_output,
            )

        if isinstance(req_spec, dict):
            svc = (receipt.get("payload") or {}).get("service") or {}
            req_blk = (receipt.get("payload") or {}).get("request") or {}
            if req_spec.get("method") and str(svc.get("method", "")).upper() != str(req_spec["method"]).upper():
                return settle_void("request_binding_mismatch", "HTTP method mismatch.", receipt=receipt, verification=verification)
            if req_spec.get("url"):
                p_url = urlsplit(str(req_spec["url"]))
                path_q = f"{p_url.path or '/'}{('?' + p_url.query) if p_url.query else ''}"
                got_res = str(svc.get("resource", ""))
                if got_res not in (str(req_spec["url"]), path_q):
                    return settle_void("request_binding_mismatch", "Request URL/resource mismatch.", receipt=receipt, verification=verification)
                if sha256_hex(got_res.encode("utf-8")) != req_blk.get("resourceHash"):
                    return settle_void("request_binding_mismatch", "resourceHash mismatch.", receipt=receipt, verification=verification)
            if "body" in req_spec or "bodyBytes" in req_spec:
                raw_req_in = req_spec.get("bodyBytes") if "bodyBytes" in req_spec else req_spec.get("body")
                if raw_req_in is None:
                    raw_req_b = b""
                elif isinstance(raw_req_in, (bytes, bytearray)):
                    raw_req_b = bytes(raw_req_in)
                elif isinstance(raw_req_in, str):
                    raw_req_b = raw_req_in.encode("utf-8")
                else:
                    raw_req_b = json.dumps(raw_req_in).encode("utf-8")
                body_ok = req_blk.get("bodyHash") == sha256_hex(raw_req_b)
                if not body_ok and raw_req_b:
                    try:
                        body_ok = req_blk.get("bodyHash") == hash_canonical(json.loads(raw_req_b.decode("utf-8")))
                    except Exception:
                        body_ok = False
                if not body_ok:
                    return settle_void("request_binding_mismatch", "bodyHash mismatch.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
            exp_req_hash = hash_canonical({
                "bodyHash": req_blk.get("bodyHash"),
                "method": str(svc.get("method", "")).upper(),
                "resource": str(svc.get("resource", "")),
            })
            if exp_req_hash != req_blk.get("requestHash"):
                return settle_void("request_binding_mismatch", "requestHash mismatch.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)

        if isinstance(challenge, dict):
            pay_blk = (receipt.get("payload") or {}).get("payment") or {}
            if challenge.get("network"):
                want_net = normalize_caip2_network_id(challenge["network"])
                got_net = normalize_caip2_network_id(pay_blk.get("network"))
                if want_net and got_net != want_net:
                    return settle_void("payment_binding_mismatch", "Receipt network mismatch.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
            if challenge.get("payTo"):
                got_pt = pay_blk.get("payTo") or ((receipt.get("payload") or {}).get("issuer") or {}).get("payTo")
                if not got_pt or _normalize_pay_to(str(got_pt)) != _normalize_pay_to(str(challenge["payTo"])):
                    return settle_void("payment_binding_mismatch", "Receipt payTo mismatch.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
            if challenge.get("amountAtomic") is not None:
                want_amt = parse_atomic_int(challenge["amountAtomic"], "challenge.amountAtomic")
                got_amt = _try_parse_atomic_int(pay_blk.get("amountAtomic"))
                if got_amt is None or got_amt > want_amt or (want_amt > 0 and got_amt == 0):
                    return settle_void("payment_binding_mismatch", "Receipt amountAtomic inconsistent with challenge.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)

    capture_amt = (
        int(challenge["amountAtomic"])
        if isinstance(challenge, dict) and challenge.get("amountAtomic") is not None
        else (_try_parse_atomic_int(((receipt or {}).get("payload") or {}).get("payment", {}).get("amountAtomic")) or 0)
    )

    if validate_content is not None:
        try:
            pred = validate_content(
                parsed_output,
                {"request": req_spec, "response": resp, "receipt": receipt, "verification": verification, "rawBodyBytes": raw_bytes},
            )
        except Exception as exc:
            return settle_void("content_rejected", f"Validator raised: {exc}", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
        if pred is False or (isinstance(pred, dict) and pred.get("ok") is False):
            reason = str(pred.get("reason") if isinstance(pred, dict) and pred.get("reason") else "Content rejected by predicate.")
            return settle_void("content_rejected", reason, receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
        if isinstance(pred, dict) and pred.get("captureAmountAtomic") is not None:
            override_amt = parse_atomic_int(pred["captureAmountAtomic"], "captureAmountAtomic")
            if isinstance(challenge, dict) and challenge.get("amountAtomic") is not None and override_amt > int(challenge["amountAtomic"]):
                return settle_void("capture_exceeds_authorized", "captureAmountAtomic exceeds authorized challenge amount.", receipt=receipt, verification=verification, raw_header=raw_hdr, parsed_out=parsed_output)
            capture_amt = override_amt

    if ledger is not None:
        r_hash = (verification or {}).get("receiptHash")
        if reservation_id:
            ledger.commit(reservation_id, actual_amount_atomic=capture_amt, receipt_hash=r_hash, now_ms=t_ms)
        elif r_hash:
            ledger.record_receipt(r_hash)

    return {
        "action": "CAPTURE",
        "ok": True,
        "reasonCode": "verified_delivery",
        "reason": "Delivery verified.",
        "settlementFinality": finality,
        "paymentInfoHash": pay_info_hash,
        "captureAmountAtomic": capture_amt,
        "receipt": receipt,
        "receiptHash": (verification or {}).get("receiptHash"),
        "verification": verification,
        "parsedOutput": parsed_output,
        "fraudEvidence": None,
    }
