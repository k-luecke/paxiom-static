"""Paxiom v0 / RFC 8785 JCS canonical JSON serializer matching src/canonicalize.mjs."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_DEPTH = 256


def _format_jcs_float(val: float) -> str:
    if not math.isfinite(val):
        raise TypeError("canonicalize: non-finite numbers (NaN, Infinity) are not representable")
    if val == 0.0:
        return "0"
    # Match ECMAScript Number::toString / JSON.stringify for finite IEEE-754 doubles
    if val.is_integer() and abs(val) < 1e21:
        return str(int(val))
    s = repr(val)
    if "e" in s or "E" in s:
        mant, exp_str = s.lower().split("e")
        exp = int(exp_str)
        if mant.endswith(".0"):
            mant = mant[:-2]
        sign = "+" if exp >= 0 else "-"
        return f"{mant}e{sign}{abs(exp)}"
    return s


def canonicalize(value: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise ValueError(f"canonicalize: nesting exceeds max depth {MAX_DEPTH}")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return _format_jcs_float(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if hasattr(value, "isoformat") and callable(getattr(value, "isoformat")):
        return canonicalize(value.isoformat(), depth + 1)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise TypeError("canonicalize: object keys must be strings")
        # Sort by UTF-16BE code units to match JavaScript Array.prototype.sort() / RFC 8785 §3.2.3
        sorted_keys = sorted(value.keys(), key=lambda s: s.encode("utf-16-be"))
        parts = [
            json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canonicalize(value[k], depth + 1)
            for k in sorted_keys
        ]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"canonicalize: {type(value).__name__} is not representable in canonical JSON")


def signing_input(receipt: dict[str, Any]) -> bytes:
    return canonicalize(
        {"receiptVersion": receipt["receiptVersion"], "payload": receipt["payload"]}
    ).encode("utf-8")


def sha256_hex(data: bytes | bytearray | memoryview | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return "0x" + hashlib.sha256(raw).hexdigest()


def hash_canonical(value: Any) -> str:
    return sha256_hex(canonicalize(value).encode("utf-8"))
