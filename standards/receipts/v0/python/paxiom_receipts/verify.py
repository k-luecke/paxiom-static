"""Offline deterministic paxiom.receipt.v0 verifier matching src/verify.mjs."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from .canonicalize import MAX_DEPTH, hash_canonical, sha256_hex, signing_input
from .ed25519_pure import ed25519_verify
from .proofs import ALLOWED_FINALITY_TIERS, evaluate_receipt_offline_proofs

RECEIPT_VERSION = "paxiom.receipt.v0"

_EMBEDDED_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://paxiom.org/standards/receipts/v0/paxiom.receipt.v0.schema.json",
    "title": "Paxiom Receipt v0",
    "type": "object",
    "additionalProperties": False,
    "required": ["receiptVersion", "payload", "signature"],
    "properties": {
        "receiptVersion": {"type": "string", "const": "paxiom.receipt.v0"},
        "payload": {
            "type": "object",
            "additionalProperties": False,
            "required": ["receiptId", "issuedAt", "issuer", "service", "request", "payment", "delivery", "evidence"],
            "properties": {
                "receiptId": {"type": "string", "minLength": 1},
                "issuedAt": {"type": "string", "format": "date-time"},
                "expiresAt": {"type": "string", "format": "date-time"},
                "issuer": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "keyId"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "uri": {"type": "string"},
                        "keyId": {"type": "string", "minLength": 1},
                        "payTo": {"type": "string", "minLength": 1},
                        "keysUri": {"type": "string", "minLength": 1},
                    },
                },
                "service": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "resource", "method"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "resource": {"type": "string", "minLength": 1},
                        "method": {"type": "string", "minLength": 1},
                    },
                },
                "request": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["requestHash", "resourceHash", "bodyHash"],
                    "properties": {
                        "requestHash": {"$ref": "#/$defs/sha256Hex"},
                        "resourceHash": {"$ref": "#/$defs/sha256Hex"},
                        "bodyHash": {"$ref": "#/$defs/sha256Hex"},
                    },
                },
                "payment": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "scheme",
                        "network",
                        "asset",
                        "amountAtomic",
                        "amountDisplay",
                        "paymentRequirementsHash",
                        "paymentPayloadHash",
                        "settlement",
                    ],
                    "properties": {
                        "scheme": {"type": "string", "minLength": 1},
                        "network": {"type": "string", "minLength": 1},
                        "asset": {"type": "string", "minLength": 1},
                        "amountAtomic": {"type": "string", "pattern": "^[0-9]+$"},
                        "amountDisplay": {"type": "string", "minLength": 1},
                        "payer": {"type": "string", "minLength": 1},
                        "payTo": {"type": "string", "minLength": 1},
                        "paymentRequirementsHash": {"$ref": "#/$defs/sha256Hex"},
                        "paymentPayloadHash": {"$ref": "#/$defs/sha256Hex"},
                        "settlement": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["status", "transactionHash"],
                            "properties": {
                                "status": {
                                    "type": "string",
                                    "enum": [
                                        "not_required",
                                        "disabled",
                                        "verify_only",
                                        "claimed_not_checked",
                                        "verified_settled",
                                        "failed",
                                        "unknown",
                                    ],
                                },
                                "transactionHash": {
                                    "oneOf": [{"$ref": "#/$defs/transactionId"}, {"type": "null"}]
                                },
                                "checkedByVerifier": {"type": "boolean"},
                                "verifier": {
                                    "oneOf": [{"type": "string", "minLength": 1}, {"type": "null"}]
                                },
                                "checkedByPaxiom": {"type": "boolean"},
                            },
                        },
                    },
                },
                "delivery": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["outputHash", "mimeType"],
                    "properties": {
                        "outputHash": {"$ref": "#/$defs/sha256Hex"},
                        "mimeType": {"type": "string", "minLength": 1},
                        "canonicalization": {
                            "type": "string",
                            "enum": ["jcs-sha256", "raw-sha256"],
                        },
                        "statusCode": {
                            "type": "integer",
                            "minimum": 100,
                            "maximum": 599,
                        },
                    },
                },
                "evidence": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["type", "status", "hash", "uri"],
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": ["none", "zk", "attestation", "tee", "archive", "other"],
                            },
                            "status": {
                                "type": "string",
                                "enum": ["not_provided", "provided", "unavailable", "invalid", "verified"],
                            },
                            "hash": {"oneOf": [{"$ref": "#/$defs/sha256Hex"}, {"type": "null"}]},
                            "uri": {"oneOf": [{"type": "string"}, {"type": "null"}]},
                        },
                    },
                },
            },
        },
        "signature": {
            "type": "object",
            "additionalProperties": False,
            "required": ["algorithm", "keyId", "publicKey", "value"],
            "properties": {
                "algorithm": {"type": "string", "const": "ed25519"},
                "keyId": {"type": "string", "minLength": 1},
                "publicKey": {"type": "string", "minLength": 1},
                "value": {"type": "string", "minLength": 1},
            },
        },
    },
    "$defs": {
        "sha256Hex": {
            "type": "string",
            "pattern": "^0x[0-9a-f]{64}$",
        },
        "transactionId": {
            "type": "string",
            "pattern": "^(?:0x[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{64,88})$",
        },
    },
}

_ISO_DATETIME_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_STRICT_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")
_EVM_ADDR_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")

_SENTINEL = object()


def _normalize_pay_to(addr: str) -> str:
    s = str(addr or "").strip()
    return s.lower() if _EVM_ADDR_RE.match(s) else s


def _parse_iso_epoch_seconds(value: str) -> float | None:
    if not isinstance(value, str) or not _ISO_DATETIME_RE.match(value):
        return None
    norm = value[:-1] + "+00:00" if value.endswith("Z") else value
    if "." in norm:
        head, tail = norm.split(".", 1)
        tz_idx = max(tail.find("+"), tail.find("-"))
        frac, tz_part = (tail[:tz_idx], tail[tz_idx:]) if tz_idx != -1 else (tail, "")
        frac6 = (frac + "000000")[:6]
        norm = f"{head}.{frac6}{tz_part}"
    try:
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _strict_decode_base64(value: Any, expected_len: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) == 0 or len(value) % 4 != 0 or not _STRICT_BASE64_RE.match(value):
        raise ValueError(f"{label} must be canonical base64")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != expected_len or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{label} must decode to {expected_len} canonical bytes")
    return raw


def _kind(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return type(val).__name__


def _validate_schema(node: Any, sch: dict[str, Any], path: str, root: dict[str, Any], depth: int = 0) -> list[str]:
    if depth > MAX_DEPTH:
        return [f"{path}: nesting exceeds max depth {MAX_DEPTH}"]
    errs: list[str] = []
    stype = sch.get("type")
    if stype == "object":
        if _kind(node) != "object":
            return [f"{path}: expected object"]
        for req_key in sch.get("required", []):
            if req_key not in node:
                errs.append(f"{path}.{req_key}: required")
        props = sch.get("properties") or {}
        if sch.get("additionalProperties") is False:
            for k in node.keys():
                if k not in props:
                    errs.append(f"{path}.{k}: not allowed")
        for k, sub in props.items():
            if k in node:
                errs.extend(_validate_schema(node[k], sub, f"{path}.{k}", root, depth + 1))
    elif stype == "array":
        if _kind(node) != "array":
            return [f"{path}: expected array"]
        arr_length = len(node)
        if "maxItems" in sch and arr_length > sch["maxItems"]:
            errs.append(f"{path}: too many items")
        item_sch = sch.get("items")
        if item_sch:
            for i, it in enumerate(node):
                errs.extend(_validate_schema(it, item_sch, f"{path}[{i}]", root, depth + 1))
    elif stype == "string":
        if _kind(node) != "string":
            return [f"{path}: expected string"]
        length = len(node)
        if "minLength" in sch and length < sch["minLength"]:
            errs.append(f"{path}: too short")
        if "maxLength" in sch and length > sch["maxLength"]:
            errs.append(f"{path}: too long")
        if "const" in sch and node != sch["const"]:
            errs.append(f"{path}: expected {sch['const']}")
        if "enum" in sch and node not in sch["enum"]:
            errs.append(f"{path}: not in enum")
        if "pattern" in sch:
            raw_pat = sch["pattern"]
            py_pat = (raw_pat[:-1] + r"\Z") if raw_pat.endswith("$") else raw_pat
            if raw_pat.startswith("^"):
                py_pat = r"\A" + py_pat[1:]
            if not re.search(py_pat, node):
                errs.append(f"{path}: pattern mismatch")
        if sch.get("format") == "date-time" and _parse_iso_epoch_seconds(node) is None:
            errs.append(f"{path}: invalid date-time")
    elif stype == "integer":
        if _kind(node) != "integer":
            errs.append(f"{path}: expected integer")
        else:
            if "minimum" in sch and node < sch["minimum"]:
                errs.append(f"{path}: below minimum")
            if "maximum" in sch and node > sch["maximum"]:
                errs.append(f"{path}: above maximum")
    elif stype == "boolean":
        if _kind(node) != "boolean":
            errs.append(f"{path}: expected boolean")
    elif stype == "null":
        if node is not None:
            errs.append(f"{path}: expected null")

    if "$ref" in sch:
        cur: Any = root
        for part in sch["$ref"].split("/")[1:]:
            cur = cur.get(part) if isinstance(cur, dict) and part in cur else None
        if not isinstance(cur, dict):
            return [f"{path}: unresolved $ref {sch['$ref']}"]
        errs.extend(_validate_schema(node, cur, path, root, depth + 1))

    if "oneOf" in sch:
        passes = sum(1 for sub in sch["oneOf"] if len(_validate_schema(node, sub, path, root, depth + 1)) == 0)
        if passes != 1:
            errs.append(f"{path}: oneOf matched {passes}")

    return errs


def verify_receipt(
    receipt: Any,
    *,
    output: Any = _SENTINEL,
    expected_issuer_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    expected_pay_to: str | None = None,
    expected_payer: str | None = None,
    trusted_verifier_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    trusted_paxiom_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    trusted_root_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    trusted_roots: Any = None,
    allowed_finality_tiers: list[str] | tuple[str, ...] | set[str] | None = None,
    settlement_proof: Any = None,
    claim_proof: Any = None,
    root_attestation: Any = None,
    now: float | datetime | str | None = None,
) -> dict[str, Any]:
    has_output = output is not _SENTINEL
    has_expected_keys = expected_issuer_public_keys is not None
    has_expected_pay_to = bool(expected_pay_to is not None and str(expected_pay_to).strip())
    checks: dict[str, str] = {
        "schema": "not_checked",
        "signature": "not_checked",
        "issuerAuthorization": "not_checked" if (has_expected_keys or has_expected_pay_to) else "unpinned",
        "outputHash": "not_checked" if has_output else "not_provided",
        "requestBinding": "not_checked",
        "paymentBinding": "not_checked",
        "settlement": "not_checked",
        "proof": "not_checked",
    }
    receipt_hash: str | None = None

    def done(trust_state: str, summary: str) -> dict[str, Any]:
        return {
            "valid": trust_state == "verified",
            "trustState": trust_state,
            "checks": checks,
            "receiptHash": receipt_hash,
            "summary": summary,
        }

    if not isinstance(receipt, dict) or receipt.get("receiptVersion") != RECEIPT_VERSION:
        ver = receipt.get("receiptVersion") if isinstance(receipt, dict) else None
        return done("unsupported_format", f"Unsupported receiptVersion: {ver}. Expected {RECEIPT_VERSION}.")

    schema_errs = _validate_schema(receipt, _EMBEDDED_SCHEMA, "receipt", _EMBEDDED_SCHEMA)
    if schema_errs:
        checks["schema"] = "fail"
        return done("schema_invalid", f"Receipt does not conform to {RECEIPT_VERSION} schema: {schema_errs[0]}.")
    checks["schema"] = "pass"

    msg_bytes = signing_input(receipt)
    receipt_hash = sha256_hex(msg_bytes)

    issuer_kid = receipt["payload"]["issuer"]["keyId"]
    sig_kid = receipt["signature"]["keyId"]
    if issuer_kid != sig_kid:
        checks["signature"] = "fail"
        return done("invalid_signature", f"payload.issuer.keyId ({issuer_kid}) does not match signature.keyId ({sig_kid}).")

    sig_ok = False
    try:
        pub_bytes = _strict_decode_base64(receipt["signature"]["publicKey"], 32, "Ed25519 publicKey")
        sig_bytes = _strict_decode_base64(receipt["signature"]["value"], 64, "Ed25519 signature.value")
        sig_ok = ed25519_verify(pub_bytes, msg_bytes, sig_bytes)
    except Exception:
        sig_ok = False

    if not sig_ok:
        checks["signature"] = "fail"
        return done("invalid_signature", "Ed25519 signature does not verify over the canonical signing input.")
    checks["signature"] = "pass"

    p = receipt["payload"]

    if has_expected_keys:
        allowed_keys = set(expected_issuer_public_keys or ())
        if receipt["signature"]["publicKey"] not in allowed_keys:
            checks["issuerAuthorization"] = "fail"
            return done(
                "unauthorized_issuer",
                "Receipt signature is valid, but signature.publicKey is not in expected_issuer_public_keys for this resource.",
            )

    if has_expected_pay_to:
        want_pay_to = _normalize_pay_to(str(expected_pay_to))
        rcpt_pay_to = p["payment"].get("payTo") or p["issuer"].get("payTo")
        if not rcpt_pay_to or _normalize_pay_to(str(rcpt_pay_to)) != want_pay_to:
            checks["issuerAuthorization"] = "fail"
            return done(
                "unauthorized_issuer",
                f"Receipt payTo ({rcpt_pay_to}) does not match expected_pay_to ({expected_pay_to})."
                if rcpt_pay_to
                else f"Caller pinned expected_pay_to ({expected_pay_to}), but receipt does not bind a payTo address.",
            )

    if has_expected_keys or has_expected_pay_to:
        checks["issuerAuthorization"] = "pass"

    if "expiresAt" in p and p["expiresAt"]:
        exp_ts = _parse_iso_epoch_seconds(p["expiresAt"])
        if now is None:
            now_ts = datetime.now(timezone.utc).timestamp()
        elif isinstance(now, datetime):
            now_ts = (now if now.tzinfo else now.replace(tzinfo=timezone.utc)).timestamp()
        elif isinstance(now, str):
            parsed_now = _parse_iso_epoch_seconds(now)
            now_ts = parsed_now if parsed_now is not None else datetime.now(timezone.utc).timestamp()
        else:
            now_ts = float(now)
        if exp_ts is not None and exp_ts < now_ts:
            return done("expired", f"Receipt expired at {p['expiresAt']}.")

    checks["requestBinding"] = "pass"
    checks["paymentBinding"] = "pass"

    if has_output:
        mode = p["delivery"].get("canonicalization") or "jcs-sha256"
        try:
            if mode == "raw-sha256":
                if isinstance(output, (bytes, bytearray, memoryview)):
                    recomputed = sha256_hex(output)
                elif isinstance(output, str):
                    recomputed = sha256_hex(output.encode("utf-8"))
                else:
                    raise TypeError('delivery.canonicalization="raw-sha256" requires bytes or str output')
            else:
                recomputed = hash_canonical(output)
        except Exception as err:
            checks["outputHash"] = "error"
            return done("error", f"Could not hash supplied output ({mode}): {err}.")
        if recomputed != p["delivery"]["outputHash"]:
            checks["outputHash"] = "fail"
            return done(
                "output_hash_mismatch",
                f"Supplied output hash {recomputed} != receipt delivery.outputHash {p['delivery']['outputHash']}.",
            )
        checks["outputHash"] = "pass"

    evidence = p.get("evidence") or []
    any_invalid = any(e.get("status") == "invalid" for e in evidence)
    any_unavailable = any(e.get("status") == "unavailable" for e in evidence)
    any_provided = any(e.get("type") != "none" and e.get("status") != "not_provided" for e in evidence)
    checks["proof"] = (
        "invalid"
        if any_invalid
        else "unavailable"
        if any_unavailable
        else "provided"
        if any_provided
        else "not_provided"
    )

    settlement = p["payment"]["settlement"]
    st = settlement["status"]
    checks["settlement"] = st

    if st == "failed":
        return done("settlement_failed", "Receipt reports a failed settlement.")
    if any_invalid:
        return done("proof_invalid", "A provided evidence record failed verification.")
    if any_unavailable:
        return done("proof_unavailable", "A referenced evidence record could not be retrieved.")

    raw_trusted = trusted_verifier_public_keys if trusted_verifier_public_keys is not None else trusted_paxiom_public_keys
    raw_root_keys = trusted_root_public_keys if trusted_root_public_keys is not None else raw_trusted

    if allowed_finality_tiers is not None and not isinstance(allowed_finality_tiers, (list, tuple, set)):
        return done("error", f"allowed_finality_tiers must be a sequence of {ALLOWED_FINALITY_TIERS}")

    offline_settled = False
    unanchored_note: str | None = None
    if claim_proof is not None or settlement_proof is not None:
        proof_eval = evaluate_receipt_offline_proofs(
            receipt=receipt,
            settlement_proof=settlement_proof,
            claim_proof=claim_proof,
            trusted_roots=trusted_roots,
            root_attestation=root_attestation,
            trusted_root_public_keys=raw_root_keys,
            allowed_finality_tiers=allowed_finality_tiers,
            expected_pay_to=expected_pay_to,
            expected_payer=expected_payer,
            now=now,
        )
        if proof_eval["outcome"] == "fail":
            if proof_eval.get("checkSettlement"):
                checks["settlement"] = proof_eval["checkSettlement"]
            if proof_eval.get("checkProof"):
                checks["proof"] = proof_eval["checkProof"]
            return done(proof_eval["trustState"], proof_eval["summary"])
        if proof_eval["outcome"] == "verified_settled":
            offline_settled = True
            checks["settlement"] = "verified_settled"
            checks["proof"] = "verified"
        elif proof_eval["outcome"] == "unanchored_settlement_proof":
            checks["proof"] = proof_eval["checkProof"]
            unanchored_note = proof_eval["summary"]
        elif proof_eval["outcome"] == "claim_verified":
            checks["proof"] = "verified"

    trusted_set = set(raw_trusted) if raw_trusted is not None else None
    is_trusted_verifier = bool(trusted_set and receipt["signature"]["publicKey"] in trusted_set)
    asserts_verifier = bool(settlement.get("checkedByVerifier") or settlement.get("checkedByPaxiom"))

    if not offline_settled:
        if asserts_verifier and not is_trusted_verifier:
            return done(
                "settlement_claimed_not_checked",
                unanchored_note or "Receipt asserts independent verifier settlement check, but signer is not in trusted_verifier_public_keys.",
            )

        if st in ("not_required", "disabled", "verify_only") and settlement.get("transactionHash") is not None:
            return done(
                "settlement_claimed_not_checked",
                unanchored_note or "Receipt carries a non-null settlement.transactionHash under a non-settled status that this offline verifier did not check.",
            )

        counter_verified = st == "verified_settled" and asserts_verifier and is_trusted_verifier
        if st == "claimed_not_checked" or (st == "verified_settled" and not counter_verified):
            return done(
                "settlement_claimed_not_checked",
                unanchored_note
                or (
                    "Signature and output hash verified. Receipt claims an onchain settlement that this offline verifier did not check."
                    if has_output
                    else "Signature verified. Receipt claims an onchain settlement that this offline verifier did not check."
                ),
            )

    if not has_output:
        return done(
            "valid_signature_only",
            "Signature valid. No output supplied, so payment-to-output binding was not checked.",
        )
    if st == "unknown" and not offline_settled:
        return done("valid_signature_only", "Signature and output verified, but settlement status is unknown.")

    eff_st = "verified_settled (offline MPT proof)" if offline_settled else st
    return done(
        "verified",
        f"Receipt verified: schema, Ed25519 signature, output binding, and settlement ({eff_st}) all consistent.",
    )


def verify_from_files(
    receipt_path: str | Path,
    output_path: str | Path | None = None,
    *,
    expected_issuer_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    expected_pay_to: str | None = None,
    trusted_verifier_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    trusted_paxiom_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
) -> dict[str, Any]:
    receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    if output_path is not None:
        raw_bytes = Path(output_path).read_bytes()
        mode = ((receipt.get("payload") or {}).get("delivery") or {}).get("canonicalization") or "jcs-sha256"
        output: Any = raw_bytes if mode == "raw-sha256" else json.loads(raw_bytes.decode("utf-8"))
        return verify_receipt(
            receipt,
            output=output,
            expected_issuer_public_keys=expected_issuer_public_keys,
            expected_pay_to=expected_pay_to,
            trusted_verifier_public_keys=trusted_verifier_public_keys,
            trusted_paxiom_public_keys=trusted_paxiom_public_keys,
        )
    return verify_receipt(
        receipt,
        expected_issuer_public_keys=expected_issuer_public_keys,
        expected_pay_to=expected_pay_to,
        trusted_verifier_public_keys=trusted_verifier_public_keys,
        trusted_paxiom_public_keys=trusted_paxiom_public_keys,
    )


def explain(result: dict[str, Any]) -> str:
    icon = "✓" if result.get("valid") else "✗"
    ts = str(result.get("trustState", "error")).upper()
    lines = [f"{icon} {ts} — {result.get('summary', '')}"]
    checks = result.get("checks") or {}
    for k in (
        "schema",
        "signature",
        "issuerAuthorization",
        "outputHash",
        "requestBinding",
        "paymentBinding",
        "settlement",
        "proof",
    ):
        if k in checks:
            lines.append(f"  {k}: {checks[k]}")
    if result.get("receiptHash"):
        lines.append(f"  receiptHash: {result['receiptHash']}")
    return "\n".join(lines)
