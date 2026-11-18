"""Zero-dependency Offline Cryptographic Proof Verifier & Builder (paxiom_receipts.proofs).

1:1 Python parity with src/proofs.mjs:
  1. Pure-Python Ethereum Keccak-256 (24-round Keccak-f[1600], 0x01 pad — NOT NIST SHA3-256)
  2. Strict Canonical RLP encoder & decoder (Yellow Paper Appendix B)
  3. Ethereum Modified Merkle-Patricia Trie (MPT) verifier & builder (Yellow Paper Appendix D)
  4. Offline EIP-1186 Account & Storage Proof verifier + Solidity / EIP-3009 slot helpers
  5. Offline EVM Receipt-Trie & Canonical USDC Settlement Proof builder & verifier
     (Legacy + EIP-2718 0x01/0x02/0x03/0x04 + OP-Stack 0x7e Deposit receipts;
      Ethereum, Base, Base Sepolia, Arbitrum, Optimism, Polygon, and Circle Arc)
  6. Ed25519 Signed Block Root Attestations (paxiom.root.v0) via pure-Python RFC 8032 Ed25519
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import re
import time
from typing import Any

from .canonicalize import MAX_DEPTH, canonicalize
from .ed25519_pure import (
    ed25519_public_key_from_seed,
    ed25519_sign,
    ed25519_verify,
    extract_ed25519_seed,
)

ROOT_ATTESTATION_VERSION = "paxiom.root.v0"
EMPTY_TRIE_ROOT_HEX = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
EMPTY_CODE_HASH_HEX = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
ERC20_TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

ALLOWED_FINALITY_TIERS: tuple[str, ...] = (
    "l1-sync-finalized",
    "l2-sequencer-attested",
    "bft-finalized",
    "rpc-head",
)

CANONICAL_USDC_BY_NETWORK: dict[str, str] = {
    "eip155:1": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "eip155:11155111": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "eip155:42161": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    "eip155:421614": "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
    "eip155:10": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
    "eip155:137": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
    "eip155:5042": "0x3600000000000000000000000000000000000000",
    "eip155:5042002": "0x3600000000000000000000000000000000000000",
}

_MAX_RLP_DEPTH = 64
_MASK64 = 0xFFFFFFFFFFFFFFFF
_EVM_ADDR_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")
_HEX32_RE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z")
_HEX_ANY_RE = re.compile(r"\A0x[0-9a-fA-F]+\Z")
_DEC_UINT_RE = re.compile(r"\A[0-9]+\Z")
_STRICT_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")
_ISO_DATETIME_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_SENTINEL = object()

# ─── 1. Pure-Python Keccak-256 (Keccak-f[1600], 24 rounds, 0x01 pad) ───

_KECCAK_ROTC = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)

_KECCAK_PILN = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _keccak_f1600(s: list[int]) -> None:
    for rc in _KECCAK_RC:
        c = [s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] for x in range(5)]
        for x in range(5):
            c1 = c[(x + 1) % 5]
            d = c[(x + 4) % 5] ^ (((c1 << 1) | (c1 >> 63)) & _MASK64)
            s[x] ^= d
            s[x + 5] ^= d
            s[x + 10] ^= d
            s[x + 15] ^= d
            s[x + 20] ^= d

        cur = s[1]
        for t in range(24):
            r = _KECCAK_ROTC[t]
            pi = _KECCAK_PILN[t]
            nxt = s[pi]
            s[pi] = ((cur << r) | (cur >> (64 - r))) & _MASK64
            cur = nxt

        for row in (0, 5, 10, 15, 20):
            t0, t1, t2, t3, t4 = s[row], s[row + 1], s[row + 2], s[row + 3], s[row + 4]
            s[row] = t0 ^ ((~t1 & _MASK64) & t2)
            s[row + 1] = t1 ^ ((~t2 & _MASK64) & t3)
            s[row + 2] = t2 ^ ((~t3 & _MASK64) & t4)
            s[row + 3] = t3 ^ ((~t4 & _MASK64) & t0)
            s[row + 4] = t4 ^ ((~t0 & _MASK64) & t1)

        s[0] ^= rc


def keccak256_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("keccak256_bytes expects bytes, bytearray, or memoryview")
    raw = bytes(data)
    state = [0] * 25
    rate = 136
    offset = 0
    total = len(raw)
    while offset + rate <= total:
        for i in range(17):
            b = offset + i * 8
            state[i] ^= int.from_bytes(raw[b : b + 8], "little")
        _keccak_f1600(state)
        offset += rate

    last = bytearray(rate)
    rem = total - offset
    if rem > 0:
        last[:rem] = raw[offset:]
    last[rem] ^= 0x01
    last[rate - 1] ^= 0x80
    for i in range(17):
        b = i * 8
        state[i] ^= int.from_bytes(last[b : b + 8], "little")
    _keccak_f1600(state)

    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def keccak256_hex(data: bytes | bytearray | memoryview) -> str:
    return "0x" + keccak256_bytes(data).hex()


# ─── 2. Strict Canonical RLP (Ethereum Yellow Paper Appendix B) ─────────


def uint_to_minimal_bytes(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Expected non-negative integer")
    if value < 0:
        raise ValueError("RLP integer must be non-negative")
    if value == 0:
        return b""
    byte_len = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_len, "big")


def bytes_to_int(raw: bytes | bytearray | memoryview, *, strict_minimal: bool = False) -> int:
    b = bytes(raw)
    if len(b) == 0:
        return 0
    if strict_minimal and b[0] == 0:
        raise ValueError("Non-canonical RLP scalar: leading zero byte")
    return int.from_bytes(b, "big")


def _encode_len_prefix(length: int, short_offset: int, long_offset: int) -> bytes:
    if length <= 55:
        return bytes([short_offset + length])
    len_bytes = uint_to_minimal_bytes(length)
    return bytes([long_offset + len(len_bytes)]) + len_bytes


def rlp_encode(item: Any) -> bytes:
    if isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(c) for c in item)
        return _encode_len_prefix(len(payload), 0xC0, 0xF7) + payload
    if isinstance(item, (bytes, bytearray, memoryview)):
        b = bytes(item)
    elif isinstance(item, int) and not isinstance(item, bool):
        b = uint_to_minimal_bytes(item)
    else:
        raise TypeError(f"Unsupported RLP item type: {type(item).__name__}")
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _encode_len_prefix(len(b), 0x80, 0xB7) + b


def _decode_canonical_len(data: bytes, offset: int, len_of_len: int) -> int:
    if offset + len_of_len > len(data):
        raise ValueError("Truncated RLP length prefix")
    if data[offset] == 0:
        raise ValueError("Non-canonical RLP: leading zero byte in length prefix")
    length = int.from_bytes(data[offset : offset + len_of_len], "big")
    if length <= 55:
        raise ValueError("Non-canonical RLP: length <= 55 must use short prefix")
    return length


def _rlp_decode_item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > _MAX_RLP_DEPTH:
        raise ValueError(f"RLP nesting exceeds maximum depth ({_MAX_RLP_DEPTH})")
    if offset >= len(data):
        raise ValueError("Unexpected end of RLP input")
    prefix = data[offset]

    if prefix < 0x80:
        return data[offset : offset + 1], offset + 1

    if prefix <= 0xB7:
        length = prefix - 0x80
        start = offset + 1
        end = start + length
        if end > len(data):
            raise ValueError("Truncated RLP short byte string")
        if length == 1 and data[start] < 0x80:
            raise ValueError("Non-canonical RLP: single byte < 0x80 must not use 0x81 prefix")
        return data[start:end], end

    if prefix <= 0xBF:
        len_of_len = prefix - 0xB7
        length = _decode_canonical_len(data, offset + 1, len_of_len)
        start = offset + 1 + len_of_len
        end = start + length
        if end > len(data):
            raise ValueError("Truncated RLP long byte string")
        return data[start:end], end

    if prefix <= 0xF7:
        length = prefix - 0xC0
        start = offset + 1
        end = start + length
        if end > len(data):
            raise ValueError("Truncated RLP short list")
        items: list[Any] = []
        cur = start
        while cur < end:
            val, cur = _rlp_decode_item(data, cur, depth + 1)
            items.append(val)
        if cur != end:
            raise ValueError("Malformed RLP list boundary")
        return items, end

    len_of_len = prefix - 0xF7
    length = _decode_canonical_len(data, offset + 1, len_of_len)
    start = offset + 1 + len_of_len
    end = start + length
    if end > len(data):
        raise ValueError("Truncated RLP long list")
    items = []
    cur = start
    while cur < end:
        val, cur = _rlp_decode_item(data, cur, depth + 1)
        items.append(val)
    if cur != end:
        raise ValueError("Malformed RLP long list boundary")
    return items, end


def _hex_to_bytes_strict(hex_str: str, label: str = "hex") -> bytes:
    clean = str(hex_str or "").strip()
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]
    if len(clean) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]*", clean):
        raise ValueError(f"{label}: invalid even-length hex string")
    return bytes.fromhex(clean)


def rlp_decode(raw: bytes | bytearray | memoryview | str) -> Any:
    data = _hex_to_bytes_strict(raw, "rlp_input") if isinstance(raw, str) else bytes(raw)
    if len(data) == 0:
        raise ValueError("Cannot RLP-decode empty byte sequence")
    val, next_off = _rlp_decode_item(data, 0, 0)
    if next_off != len(data):
        raise ValueError(f"Trailing {len(data) - next_off} byte(s) after RLP payload")
    return val


# ─── 3. Network, Address & Solidity Slot Helpers ────────────────────────


def normalize_evm_network_id(raw_net: Any) -> str | None:
    if not isinstance(raw_net, str) or not raw_net.strip():
        return None
    trimmed = raw_net.strip()
    lower = trimmed.lower()
    if lower in ("ethereum", "mainnet", "eth"):
        return "eip155:1"
    if lower in ("sepolia", "ethereum-sepolia"):
        return "eip155:11155111"
    if lower in ("base", "base-mainnet"):
        return "eip155:8453"
    if lower == "base-sepolia":
        return "eip155:84532"
    if lower in ("arbitrum", "arbitrum-one"):
        return "eip155:42161"
    if lower == "arbitrum-sepolia":
        return "eip155:421614"
    if lower in ("optimism", "op-mainnet"):
        return "eip155:10"
    if lower in ("polygon", "polygon-pos"):
        return "eip155:137"
    if lower in ("arc", "arc-mainnet"):
        return "eip155:5042"
    if lower == "arc-testnet":
        return "eip155:5042002"
    return lower if lower.startswith("eip155:") else trimmed


def _as_bytes_flex(val: Any, label: str) -> bytes:
    if isinstance(val, (bytes, bytearray, memoryview)):
        return bytes(val)
    if isinstance(val, str):
        return _hex_to_bytes_strict(val, label)
    raise TypeError(f"{label}: expected hex string or bytes")


def _as_fixed_bytes(val: Any, expected_len: int, label: str) -> bytes:
    b = _as_bytes_flex(val, label)
    if len(b) != expected_len:
        raise ValueError(f"{label}: expected {expected_len} bytes, got {len(b)}")
    return b


def _to_word32_bytes(val: Any, label: str) -> bytes:
    if isinstance(val, int) and not isinstance(val, bool):
        if val < 0 or val >= (1 << 256):
            raise ValueError(f"{label}: uint256 out of range")
        return val.to_bytes(32, "big")
    if isinstance(val, str):
        trimmed = val.strip()
        if _DEC_UINT_RE.match(trimmed):
            return _to_word32_bytes(int(trimmed), label)
        clean = trimmed[2:] if trimmed.startswith(("0x", "0X")) else trimmed
        if not clean or len(clean) > 64 or not re.fullmatch(r"[0-9a-fA-F]+", clean):
            raise ValueError(f"{label}: expected <=32-byte hex or uint256")
        return bytes.fromhex(clean.zfill(64))
    if isinstance(val, (bytes, bytearray, memoryview)):
        b = bytes(val)
        if len(b) > 32:
            raise ValueError(f"{label}: byte sequence exceeds 32 bytes")
        return b.rjust(32, b"\x00")
    raise TypeError(f"{label}: unsupported 32-byte word input")


def _parse_uint256(val: Any, label: str) -> int:
    if isinstance(val, int) and not isinstance(val, bool):
        if val < 0 or val >= (1 << 256):
            raise ValueError(f"{label}: uint256 out of range")
        return val
    if isinstance(val, str):
        trimmed = val.strip()
        if trimmed in ("0x", "0X"):
            return 0
        if _HEX_ANY_RE.match(trimmed):
            n = int(trimmed, 16)
            if n >= (1 << 256):
                raise ValueError(f"{label}: uint256 out of range")
            return n
        if _DEC_UINT_RE.match(trimmed):
            n = int(trimmed, 10)
            if n >= (1 << 256):
                raise ValueError(f"{label}: uint256 out of range")
            return n
    if isinstance(val, (bytes, bytearray, memoryview)):
        b = bytes(val)
        if len(b) > 32:
            raise ValueError(f"{label}: exceeds 32 bytes")
        return bytes_to_int(b)
    raise ValueError(f"{label}: invalid uint256 value")


def derive_account_trie_key(address: Any) -> bytes:
    return keccak256_bytes(_as_fixed_bytes(address, 20, "address"))


def derive_storage_trie_key(slot: Any) -> bytes:
    return keccak256_bytes(_to_word32_bytes(slot, "slot"))


def compute_mapping_slot(key: Any, base_slot: Any) -> str:
    return keccak256_hex(_to_word32_bytes(key, "key") + _to_word32_bytes(base_slot, "base_slot"))


def compute_nested_mapping_slot(outer_key: Any, inner_key: Any, base_slot: Any) -> str:
    outer = compute_mapping_slot(outer_key, base_slot)
    return compute_mapping_slot(inner_key, outer)


def compute_eip3009_auth_state_slot(authorizer: Any, nonce_bytes32: Any, base_slot: Any) -> str:
    addr = _as_fixed_bytes(authorizer, 20, "authorizer")
    nonce = _as_fixed_bytes(nonce_bytes32, 32, "nonce_bytes32")
    return compute_nested_mapping_slot(addr, nonce, base_slot)


# ─── 4. Modified Merkle-Patricia Trie (MPT) Verifier & Builder ──────────


def _bytes_to_nibbles(data: bytes) -> tuple[int, ...]:
    out: list[int] = []
    for b in data:
        out.append(b >> 4)
        out.append(b & 0x0F)
    return tuple(out)


def _encode_compact_nibbles(nibbles: tuple[int, ...], is_leaf: bool) -> bytes:
    odd = (len(nibbles) & 1) == 1
    flag = (2 if is_leaf else 0) + (1 if odd else 0)
    if odd:
        out = bytearray(1 + ((len(nibbles) - 1) >> 1))
        out[0] = (flag << 4) | (nibbles[0] & 0x0F)
        for i in range(1, len(nibbles), 2):
            out[1 + ((i - 1) >> 1)] = ((nibbles[i] & 0x0F) << 4) | (nibbles[i + 1] & 0x0F)
        return bytes(out)
    out = bytearray(1 + (len(nibbles) >> 1))
    out[0] = flag << 4
    for i in range(0, len(nibbles), 2):
        out[1 + (i >> 1)] = ((nibbles[i] & 0x0F) << 4) | (nibbles[i + 1] & 0x0F)
    return bytes(out)


def _decode_compact_nibbles(hp: bytes) -> tuple[bool, tuple[int, ...]]:
    if not isinstance(hp, bytes) or len(hp) == 0:
        raise ValueError("Compact hex-prefix path must be non-empty bytes")
    first = hp[0]
    flag = first >> 4
    if flag > 3:
        raise ValueError(f"Invalid compact hex-prefix flag: {flag}")
    odd = (flag & 1) == 1
    is_leaf = (flag & 2) != 0
    if not odd and (first & 0x0F) != 0:
        raise ValueError("Non-canonical compact hex-prefix: non-zero low nibble on even path")
    nibs: list[int] = []
    if odd:
        nibs.append(first & 0x0F)
    for b in hp[1:]:
        nibs.append(b >> 4)
        nibs.append(b & 0x0F)
    return is_leaf, tuple(nibs)


def verify_mpt_proof(
    *,
    root_hash: Any,
    key: Any,
    proof: Any,
    expected_value: Any = _SENTINEL,
) -> dict[str, Any]:
    def fail(code: str, reason: str, r_hex: str | None = None, k_hex: str | None = None) -> dict[str, Any]:
        return {
            "ok": False,
            "verified": False,
            "code": code,
            "reason": reason,
            "rootHash": r_hex,
            "keyHex": k_hex,
            "value": None,
        }

    try:
        root_bytes = _as_fixed_bytes(root_hash, 32, "root_hash")
        key_bytes = _as_bytes_flex(key, "key")
    except Exception as exc:
        return fail("invalid_input", str(exc))

    root_hex = "0x" + root_bytes.hex()
    key_hex = "0x" + key_bytes.hex()

    if not isinstance(proof, (list, tuple)):
        return fail("invalid_proof", "proof must be a list of RLP-encoded trie nodes.", root_hex, key_hex)

    try:
        proof_nodes = [_as_bytes_flex(n, f"proof[{i}]") for i, n in enumerate(proof)]
    except Exception as exc:
        return fail("invalid_proof", str(exc), root_hex, key_hex)

    def check_expected(recovered: bytes | None) -> dict[str, Any]:
        if expected_value is _SENTINEL:
            return {
                "ok": True,
                "verified": True,
                "code": "verified_absent" if recovered is None else "verified",
                "reason": (
                    "Authenticated MPT exclusion proof verified (key absent under root)."
                    if recovered is None
                    else "Authenticated MPT inclusion proof verified."
                ),
                "rootHash": root_hex,
                "keyHex": key_hex,
                "value": recovered,
            }
        if expected_value is None:
            if recovered is not None:
                return fail(
                    "unexpected_inclusion",
                    f"Expected key {key_hex} to be absent, but MPT proof resolved to 0x{recovered.hex()}.",
                    root_hex,
                    key_hex,
                )
            return {
                "ok": True,
                "verified": True,
                "code": "verified_absent",
                "reason": "Authenticated MPT exclusion proof verified (key absent under root).",
                "rootHash": root_hex,
                "keyHex": key_hex,
                "value": None,
            }
        try:
            want_bytes = _as_bytes_flex(expected_value, "expected_value")
        except Exception as exc:
            return fail("invalid_input", str(exc), root_hex, key_hex)
        if recovered is None:
            return fail(
                "key_absent",
                f"Key {key_hex} is absent under {root_hex}, expected value 0x{want_bytes.hex()}.",
                root_hex,
                key_hex,
            )
        if recovered != want_bytes:
            return fail(
                "value_mismatch",
                f"MPT leaf value mismatch for {key_hex}: expected 0x{want_bytes.hex()}, got 0x{recovered.hex()}.",
                root_hex,
                key_hex,
            )
        return {
            "ok": True,
            "verified": True,
            "code": "verified",
            "reason": "Authenticated MPT inclusion proof and expected value verified.",
            "rootHash": root_hex,
            "keyHex": key_hex,
            "value": recovered,
        }

    if root_hex == EMPTY_TRIE_ROOT_HEX:
        valid_empty = len(proof_nodes) == 0 or (len(proof_nodes) == 1 and proof_nodes[0] == b"\x80")
        if not valid_empty:
            return fail("proof_root_mismatch", "Non-empty proof nodes supplied for empty trie root.", root_hex, key_hex)
        return check_expected(None)

    if len(proof_nodes) == 0:
        return fail("empty_proof", "MPT proof list is empty for non-empty rootHash.", root_hex, key_hex)

    node_by_hash: dict[str, bytes] = {}
    for i, raw in enumerate(proof_nodes):
        if len(raw) == 0:
            return fail("invalid_trie_node", f"proof[{i}] is empty.", root_hex, key_hex)
        node_by_hash[keccak256_hex(raw)] = raw

    root_raw = node_by_hash.get(root_hex)
    if root_raw is None:
        return fail("proof_root_mismatch", f"No proof node hashes to claimed rootHash {root_hex}.", root_hex, key_hex)

    try:
        cur_decoded = rlp_decode(root_raw)
    except Exception as exc:
        return fail("invalid_rlp", f"Failed to RLP-decode root trie node: {exc}", root_hex, key_hex)

    key_nibbles = _bytes_to_nibbles(key_bytes)
    nib_idx = 0

    def resolve_child(entry: Any) -> tuple[bool, str, str, Any]:
        if isinstance(entry, list):
            reenc = rlp_encode(entry)
            if len(reenc) >= 32:
                return False, "invalid_inline_node", f"Inline embedded trie node must be < 32 bytes (got {len(reenc)}).", None
            return True, "", "", entry
        if isinstance(entry, bytes):
            if len(entry) == 0:
                return True, "absent", "", None
            if len(entry) != 32:
                return False, "invalid_child_ref", f"Hashed trie child reference must be 32 bytes (got {len(entry)}).", None
            want_h = "0x" + entry.hex()
            nxt_raw = node_by_hash.get(want_h)
            if nxt_raw is None:
                return False, "incomplete_proof", f"Missing trie node in proof for child hash {want_h}.", None
            try:
                return True, "", "", rlp_decode(nxt_raw)
            except Exception as exc:
                return False, "invalid_rlp", f"Failed to RLP-decode child node {want_h}: {exc}", None
        return False, "invalid_trie_node", "Malformed trie child entry.", None

    for _ in range(len(key_nibbles) + 2):
        if not isinstance(cur_decoded, list):
            return fail("invalid_trie_node", "Decoded trie node must be an RLP list.", root_hex, key_hex)

        if len(cur_decoded) == 17:
            branch_val = cur_decoded[16]
            if not isinstance(branch_val, bytes):
                return fail("invalid_trie_node", "Branch node item[16] value must be RLP bytes.", root_hex, key_hex)
            if nib_idx == len(key_nibbles):
                return check_expected(None if len(branch_val) == 0 else branch_val)
            nib = key_nibbles[nib_idx]
            nib_idx += 1
            ok_c, code_c, reason_c, nxt_dec = resolve_child(cur_decoded[nib])
            if not ok_c:
                return fail(code_c, reason_c, root_hex, key_hex)
            if code_c == "absent":
                return check_expected(None)
            cur_decoded = nxt_dec
            continue

        if len(cur_decoded) == 2:
            try:
                is_leaf, hp_nibs = _decode_compact_nibbles(cur_decoded[0])
            except Exception as exc:
                return fail("invalid_trie_node", str(exc), root_hex, key_hex)

            rem = key_nibbles[nib_idx:]
            if is_leaf:
                leaf_val = cur_decoded[1]
                if not isinstance(leaf_val, bytes) or len(leaf_val) == 0:
                    return fail("invalid_trie_node", "Leaf node value must be non-empty RLP bytes.", root_hex, key_hex)
                if rem == hp_nibs:
                    return check_expected(leaf_val)
                return check_expected(None)

            if len(hp_nibs) == 0:
                return fail("invalid_trie_node", "Extension node must have at least 1 shared nibble.", root_hex, key_hex)
            if len(rem) < len(hp_nibs) or rem[: len(hp_nibs)] != hp_nibs:
                return check_expected(None)
            nib_idx += len(hp_nibs)
            ok_c, code_c, reason_c, nxt_dec = resolve_child(cur_decoded[1])
            if not ok_c:
                return fail(code_c, reason_c, root_hex, key_hex)
            if code_c == "absent":
                return fail("invalid_trie_node", "Extension node child reference cannot be empty.", root_hex, key_hex)
            cur_decoded = nxt_dec
            continue

        return fail("invalid_trie_node", f"Invalid trie node list length {len(cur_decoded)} (expected 2 or 17).", root_hex, key_hex)

    return fail("proof_depth_exceeded", "MPT walk exceeded key nibble length.", root_hex, key_hex)


def _build_trie_ast(items: list[tuple[tuple[int, ...], bytes]], depth: int) -> dict[str, Any]:
    if len(items) == 1:
        return {"kind": "leaf", "nibbles": items[0][0][depth:], "value": items[0][1]}
    lcp = len(items[0][0]) - depth
    for nibs, _ in items[1:]:
        rem = len(nibs) - depth
        if rem < lcp:
            lcp = rem
        for j in range(lcp):
            if nibs[depth + j] != items[0][0][depth + j]:
                lcp = j
                break
        if lcp == 0:
            break
    if lcp > 0:
        return {
            "kind": "ext",
            "nibbles": items[0][0][depth : depth + lcp],
            "child": _build_trie_ast(items, depth + lcp),
        }
    buckets: list[list[tuple[tuple[int, ...], bytes]]] = [[] for _ in range(16)]
    branch_val: bytes | None = None
    for nibs, val in items:
        if len(nibs) == depth:
            branch_val = val
        else:
            buckets[nibs[depth]].append((nibs, val))
    branches = [_build_trie_ast(b, depth + 1) if b else None for b in buckets]
    return {"kind": "branch", "branches": branches, "value": branch_val}


def _annotate_trie_ast(ast: dict[str, Any]) -> dict[str, Any]:
    kind = ast["kind"]
    if kind == "leaf":
        raw_list = [_encode_compact_nibbles(ast["nibbles"], True), ast["value"]]
        ast["raw_list"] = raw_list
        ast["rlp_bytes"] = rlp_encode(raw_list)
        return ast
    if kind == "ext":
        child = _annotate_trie_ast(ast["child"])
        child_ref = child["raw_list"] if len(child["rlp_bytes"]) < 32 else keccak256_bytes(child["rlp_bytes"])
        raw_list = [_encode_compact_nibbles(ast["nibbles"], False), child_ref]
        ast["raw_list"] = raw_list
        ast["rlp_bytes"] = rlp_encode(raw_list)
        return ast
    child_refs: list[Any] = []
    for b in ast["branches"]:
        if b is None:
            child_refs.append(b"")
        else:
            _annotate_trie_ast(b)
            child_refs.append(b["raw_list"] if len(b["rlp_bytes"]) < 32 else keccak256_bytes(b["rlp_bytes"]))
    raw_list = [*child_refs, ast["value"] if ast["value"] is not None else b""]
    ast["raw_list"] = raw_list
    ast["rlp_bytes"] = rlp_encode(raw_list)
    return ast


def build_mpt_proof(entries: list[dict[str, Any]], target_key: Any) -> dict[str, Any]:
    target_bytes = _as_bytes_flex(target_key, "target_key")
    key_hex = "0x" + target_bytes.hex()
    target_nibs = _bytes_to_nibbles(target_bytes)

    dedup: dict[str, tuple[tuple[int, ...], bytes]] = {}
    for i, e in enumerate(entries):
        k_bytes = _as_bytes_flex(e["key"], f"entries[{i}].key")
        v_bytes = _as_bytes_flex(e["value"], f"entries[{i}].value")
        k_hex = "0x" + k_bytes.hex()
        if len(v_bytes) == 0:
            dedup.pop(k_hex, None)
        else:
            dedup[k_hex] = (_bytes_to_nibbles(k_bytes), v_bytes)

    if not dedup:
        return {"rootHash": EMPTY_TRIE_ROOT_HEX, "keyHex": key_hex, "value": None, "proof": []}

    root_ast = _annotate_trie_ast(_build_trie_ast(list(dedup.values()), 0))
    root_hash = keccak256_hex(root_ast["rlp_bytes"])
    proof = ["0x" + root_ast["rlp_bytes"].hex()]

    cur: dict[str, Any] | None = root_ast
    idx = 0
    found: bytes | None = None
    while cur is not None:
        if cur["kind"] == "leaf":
            if target_nibs[idx:] == cur["nibbles"]:
                found = cur["value"]
            break
        if cur["kind"] == "ext":
            nibs = cur["nibbles"]
            if len(target_nibs) - idx < len(nibs) or target_nibs[idx : idx + len(nibs)] != nibs:
                break
            idx += len(nibs)
            nxt = cur["child"]
            if len(nxt["rlp_bytes"]) >= 32:
                proof.append("0x" + nxt["rlp_bytes"].hex())
            cur = nxt
            continue
        if idx == len(target_nibs):
            found = cur["value"]
            break
        nib = target_nibs[idx]
        idx += 1
        nxt = cur["branches"][nib]
        if nxt is None:
            break
        if len(nxt["rlp_bytes"]) >= 32:
            proof.append("0x" + nxt["rlp_bytes"].hex())
        cur = nxt

    return {"rootHash": root_hash, "keyHex": key_hex, "value": found, "proof": proof}


# ─── 5. Offline EIP-1186 Account & Storage Verifiers ────────────────────


def encode_evm_account(account: dict[str, Any]) -> bytes:
    nonce = _parse_uint256(account.get("nonce", 0), "account.nonce")
    balance = _parse_uint256(account.get("balance", 0), "account.balance")
    s_root = _as_fixed_bytes(
        account.get("storageRoot") or account.get("storageHash") or EMPTY_TRIE_ROOT_HEX,
        32,
        "account.storageRoot",
    )
    c_hash = _as_fixed_bytes(account.get("codeHash") or EMPTY_CODE_HASH_HEX, 32, "account.codeHash")
    return rlp_encode([uint_to_minimal_bytes(nonce), uint_to_minimal_bytes(balance), s_root, c_hash])


def decode_evm_account(raw_rlp: Any) -> dict[str, Any]:
    dec = rlp_decode(raw_rlp)
    if not isinstance(dec, list) or len(dec) != 4:
        raise ValueError("Account RLP must be a 4-item list [nonce, balance, storageRoot, codeHash]")
    n_b, bal_b, sr_b, ch_b = dec
    if not all(isinstance(x, bytes) for x in (n_b, bal_b, sr_b, ch_b)):
        raise ValueError("Account RLP fields must all be byte strings")
    if len(sr_b) != 32 or len(ch_b) != 32:
        raise ValueError("Account storageRoot and codeHash must each be 32 bytes")
    return {
        "nonce": bytes_to_int(n_b, strict_minimal=True),
        "balance": bytes_to_int(bal_b, strict_minimal=True),
        "storageRoot": "0x" + sr_b.hex(),
        "codeHash": "0x" + ch_b.hex(),
    }


def verify_account_proof(
    *,
    state_root: Any,
    address: Any,
    account_proof: Any,
    expected_account: Any = _SENTINEL,
) -> dict[str, Any]:
    try:
        addr_bytes = _as_fixed_bytes(address, 20, "address")
    except Exception as exc:
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_address",
            "reason": str(exc),
            "address": None,
            "stateRoot": None,
            "exists": False,
            "account": None,
        }
    norm_addr = "0x" + addr_bytes.hex()
    mpt = verify_mpt_proof(root_hash=state_root, key=keccak256_bytes(addr_bytes), proof=account_proof)
    if not mpt["ok"]:
        return {
            "ok": False,
            "verified": False,
            "code": mpt["code"],
            "reason": mpt["reason"],
            "address": norm_addr,
            "stateRoot": mpt["rootHash"],
            "exists": False,
            "account": None,
        }

    if mpt["value"] is None:
        if isinstance(expected_account, dict):
            return {
                "ok": False,
                "verified": False,
                "code": "account_not_found",
                "reason": f"Account {norm_addr} does not exist under stateRoot {mpt['rootHash']}.",
                "address": norm_addr,
                "stateRoot": mpt["rootHash"],
                "exists": False,
                "account": None,
            }
        return {
            "ok": True,
            "verified": True,
            "code": "verified_absent",
            "reason": f"Authenticated non-existence of account {norm_addr} under {mpt['rootHash']}.",
            "address": norm_addr,
            "stateRoot": mpt["rootHash"],
            "exists": False,
            "account": None,
        }

    if expected_account is None:
        return {
            "ok": False,
            "verified": False,
            "code": "unexpected_account_exists",
            "reason": f"Expected account {norm_addr} to be absent, but account exists in state trie.",
            "address": norm_addr,
            "stateRoot": mpt["rootHash"],
            "exists": True,
            "account": None,
        }

    try:
        acct = decode_evm_account(mpt["value"])
    except Exception as exc:
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_account_rlp",
            "reason": f"Malformed account RLP: {exc}",
            "address": norm_addr,
            "stateRoot": mpt["rootHash"],
            "exists": False,
            "account": None,
        }

    if isinstance(expected_account, dict):
        try:
            if "nonce" in expected_account and expected_account["nonce"] is not None:
                want_n = _parse_uint256(expected_account["nonce"], "expected_account.nonce")
                if acct["nonce"] != want_n:
                    return {
                        "ok": False,
                        "verified": False,
                        "code": "account_field_mismatch",
                        "reason": f"Account nonce mismatch: expected {want_n}, got {acct['nonce']}.",
                        "address": norm_addr,
                        "stateRoot": mpt["rootHash"],
                        "exists": True,
                        "account": acct,
                    }
            if "balance" in expected_account and expected_account["balance"] is not None:
                want_b = _parse_uint256(expected_account["balance"], "expected_account.balance")
                if acct["balance"] != want_b:
                    return {
                        "ok": False,
                        "verified": False,
                        "code": "account_field_mismatch",
                        "reason": f"Account balance mismatch: expected {want_b}, got {acct['balance']}.",
                        "address": norm_addr,
                        "stateRoot": mpt["rootHash"],
                        "exists": True,
                        "account": acct,
                    }
            raw_sr = expected_account.get("storageRoot", expected_account.get("storageHash"))
            if raw_sr is not None:
                want_sr = "0x" + _as_fixed_bytes(raw_sr, 32, "expected_account.storageRoot").hex()
                if acct["storageRoot"] != want_sr:
                    return {
                        "ok": False,
                        "verified": False,
                        "code": "account_field_mismatch",
                        "reason": f"Account storageRoot mismatch: expected {want_sr}, got {acct['storageRoot']}.",
                        "address": norm_addr,
                        "stateRoot": mpt["rootHash"],
                        "exists": True,
                        "account": acct,
                    }
            if expected_account.get("codeHash") is not None:
                want_ch = "0x" + _as_fixed_bytes(expected_account["codeHash"], 32, "expected_account.codeHash").hex()
                if acct["codeHash"] != want_ch:
                    return {
                        "ok": False,
                        "verified": False,
                        "code": "account_field_mismatch",
                        "reason": f"Account codeHash mismatch: expected {want_ch}, got {acct['codeHash']}.",
                        "address": norm_addr,
                        "stateRoot": mpt["rootHash"],
                        "exists": True,
                        "account": acct,
                    }
        except Exception as exc:
            return {
                "ok": False,
                "verified": False,
                "code": "invalid_expected_account",
                "reason": str(exc),
                "address": norm_addr,
                "stateRoot": mpt["rootHash"],
                "exists": True,
                "account": acct,
            }

    return {
        "ok": True,
        "verified": True,
        "code": "verified",
        "reason": f"Account {norm_addr} verified against stateRoot {mpt['rootHash']}.",
        "address": norm_addr,
        "stateRoot": mpt["rootHash"],
        "exists": True,
        "account": acct,
    }


def verify_storage_proof(
    *,
    storage_root: Any,
    key: Any = None,
    slot: Any = None,
    proof: Any = None,
    expected_value: Any = _SENTINEL,
) -> dict[str, Any]:
    slot_in = slot if slot is not None else key
    try:
        slot_word = _to_word32_bytes(slot_in, "slot")
    except Exception as exc:
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_slot",
            "reason": str(exc),
            "slotHex": None,
            "storageRoot": None,
            "value": None,
            "valueHex": None,
            "valueHex32": None,
        }
    slot_hex = "0x" + slot_word.hex()
    mpt = verify_mpt_proof(root_hash=storage_root, key=keccak256_bytes(slot_word), proof=proof)
    if not mpt["ok"]:
        return {
            "ok": False,
            "verified": False,
            "code": mpt["code"],
            "reason": mpt["reason"],
            "slotHex": slot_hex,
            "storageRoot": mpt["rootHash"],
            "value": None,
            "valueHex": None,
            "valueHex32": None,
        }

    recovered = 0
    if mpt["value"] is not None:
        try:
            inner = rlp_decode(mpt["value"])
        except Exception as exc:
            return {
                "ok": False,
                "verified": False,
                "code": "invalid_storage_rlp",
                "reason": f"Malformed storage leaf RLP: {exc}",
                "slotHex": slot_hex,
                "storageRoot": mpt["rootHash"],
                "value": None,
                "valueHex": None,
                "valueHex32": None,
            }
        if not isinstance(inner, bytes) or len(inner) == 0 or len(inner) > 32 or inner[0] == 0:
            return {
                "ok": False,
                "verified": False,
                "code": "invalid_storage_rlp",
                "reason": "Canonical Ethereum storage leaf RLP must decode to 1..32 minimal non-zero scalar bytes.",
                "slotHex": slot_hex,
                "storageRoot": mpt["rootHash"],
                "value": None,
                "valueHex": None,
                "valueHex32": None,
            }
        recovered = bytes_to_int(inner, strict_minimal=True)

    val_hex = hex(recovered)
    val_hex32 = f"0x{recovered:064x}"

    if expected_value is not _SENTINEL:
        try:
            want_v = _parse_uint256(expected_value, "expected_value")
        except Exception as exc:
            return {
                "ok": False,
                "verified": False,
                "code": "invalid_expected_value",
                "reason": str(exc),
                "slotHex": slot_hex,
                "storageRoot": mpt["rootHash"],
                "value": recovered,
                "valueHex": val_hex,
                "valueHex32": val_hex32,
            }
        if recovered != want_v:
            return {
                "ok": False,
                "verified": False,
                "code": "storage_value_mismatch",
                "reason": f"Storage slot {slot_hex} value mismatch: expected {hex(want_v)}, got {val_hex}.",
                "slotHex": slot_hex,
                "storageRoot": mpt["rootHash"],
                "value": recovered,
                "valueHex": val_hex,
                "valueHex32": val_hex32,
            }

    return {
        "ok": True,
        "verified": True,
        "code": "verified_zero" if mpt["value"] is None else "verified",
        "reason": f"Storage slot {slot_hex} verified ({val_hex}) against storageRoot {mpt['rootHash']}.",
        "slotHex": slot_hex,
        "storageRoot": mpt["rootHash"],
        "value": recovered,
        "valueHex": val_hex,
        "valueHex32": val_hex32,
    }


def verify_eip1186_proof(
    *,
    state_root: Any,
    proof: Any,
    expected_storage: Any = None,
) -> dict[str, Any]:
    if not isinstance(proof, dict):
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_eip1186_proof",
            "reason": "EIP-1186 proof must be an eth_getProof response dict.",
        }

    raw_sr = proof.get("storageHash") or proof.get("storageRoot") or proof.get("storage_root")
    raw_ch = proof.get("codeHash") or proof.get("code_hash")
    raw_ap = proof.get("accountProof") if "accountProof" in proof else proof.get("account_proof")
    raw_sps = proof.get("storageProof") if "storageProof" in proof else proof.get("storage_proof", [])

    acct_res = verify_account_proof(state_root=state_root, address=proof.get("address"), account_proof=raw_ap)
    if not acct_res["ok"]:
        return {
            "ok": False,
            "verified": False,
            "code": acct_res["code"],
            "reason": acct_res["reason"],
            "address": acct_res["address"],
            "stateRoot": acct_res["stateRoot"],
        }

    if not acct_res["exists"]:
        if expected_storage:
            return {
                "ok": False,
                "verified": False,
                "code": "account_not_found",
                "reason": f"Account {acct_res['address']} does not exist at stateRoot {acct_res['stateRoot']}.",
            }
        return {
            "ok": True,
            "verified": True,
            "code": "verified_absent",
            "reason": acct_res["reason"],
            "address": acct_res["address"],
            "stateRoot": acct_res["stateRoot"],
            "exists": False,
            "account": None,
            "storage": [],
        }

    exp_acct: dict[str, Any] = {}
    if "nonce" in proof:
        exp_acct["nonce"] = proof["nonce"]
    if "balance" in proof:
        exp_acct["balance"] = proof["balance"]
    if raw_sr is not None:
        exp_acct["storageRoot"] = raw_sr
    if raw_ch is not None:
        exp_acct["codeHash"] = raw_ch

    top_check = verify_account_proof(
        state_root=state_root,
        address=proof.get("address"),
        account_proof=raw_ap,
        expected_account=exp_acct,
    )
    if not top_check["ok"]:
        return {
            "ok": False,
            "verified": False,
            "code": top_check["code"],
            "reason": top_check["reason"],
            "address": acct_res["address"],
            "stateRoot": acct_res["stateRoot"],
        }

    if not isinstance(raw_sps, list):
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_eip1186_proof",
            "reason": "EIP-1186 storageProof must be a list.",
        }

    verified_slots: list[dict[str, Any]] = []
    by_slot: dict[str, dict[str, Any]] = {}
    for i, sp in enumerate(raw_sps):
        if not isinstance(sp, dict):
            return {"ok": False, "verified": False, "code": "invalid_eip1186_proof", "reason": f"storageProof[{i}] must be a dict."}
        sr = verify_storage_proof(
            storage_root=acct_res["account"]["storageRoot"],
            key=sp.get("key") if "key" in sp else sp.get("slot"),
            proof=sp.get("proof") if "proof" in sp else sp.get("storage_proof"),
            expected_value=sp.get("value"),
        )
        if not sr["ok"]:
            return {
                "ok": False,
                "verified": False,
                "code": sr["code"],
                "reason": f"storageProof[{i}]: {sr['reason']}",
                "address": acct_res["address"],
                "stateRoot": acct_res["stateRoot"],
            }
        verified_slots.append(sr)
        by_slot[sr["slotHex"]] = sr

    if expected_storage is not None:
        req_list = (
            [{"slot": k, "value": v} for k, v in expected_storage.items()]
            if isinstance(expected_storage, dict)
            else list(expected_storage)
        )
        for i, req in enumerate(req_list):
            try:
                norm_s = "0x" + _to_word32_bytes(req.get("slot") if "slot" in req else req.get("key"), f"expected_storage[{i}].slot").hex()
                want_v = _parse_uint256(req["value"], f"expected_storage[{i}].value")
            except Exception as exc:
                return {"ok": False, "verified": False, "code": "invalid_expected_storage", "reason": str(exc)}
            got = by_slot.get(norm_s)
            if got is None:
                return {"ok": False, "verified": False, "code": "missing_expected_slot", "reason": f"Required storage slot {norm_s} omitted from storageProof."}
            if got["value"] != want_v:
                return {"ok": False, "verified": False, "code": "storage_value_mismatch", "reason": f"Slot {norm_s} has value {got['valueHex']}, expected {hex(want_v)}."}

    return {
        "ok": True,
        "verified": True,
        "code": "verified",
        "reason": f"Verified EIP-1186 account {acct_res['address']} and {len(verified_slots)} storage slot(s) against stateRoot {acct_res['stateRoot']}.",
        "address": acct_res["address"],
        "stateRoot": acct_res["stateRoot"],
        "exists": True,
        "account": acct_res["account"],
        "storage": verified_slots,
    }


# ─── 6. Offline EVM Receipt-Trie & Canonical USDC Settlement Verifiers ──


def _parse_receipt_type(raw_type: Any) -> int:
    if raw_type in (None, "", "0x0", "0x00", 0):
        return 0
    n = _parse_uint256(raw_type, "receipt.type")
    if n < 0 or n > 0x7F:
        raise ValueError(f"Invalid EIP-2718 receipt type: {raw_type}")
    return n


def encode_evm_receipt(rpc_receipt: dict[str, Any]) -> bytes:
    tx_type = _parse_receipt_type(rpc_receipt.get("type"))
    if rpc_receipt.get("root") and "status" not in rpc_receipt:
        status_or_root = _as_fixed_bytes(rpc_receipt["root"], 32, "rpcReceipt.root")
    else:
        st = _parse_uint256(rpc_receipt.get("status", 0), "rpcReceipt.status")
        if st not in (0, 1):
            raise ValueError(f"Invalid receipt status: {rpc_receipt.get('status')}")
        status_or_root = b"\x01" if st == 1 else b""

    cum_gas = uint_to_minimal_bytes(_parse_uint256(rpc_receipt["cumulativeGasUsed"], "cumulativeGasUsed"))
    bloom = _as_fixed_bytes(rpc_receipt["logsBloom"], 256, "logsBloom")
    enc_logs: list[list[Any]] = []
    for i, log in enumerate(rpc_receipt.get("logs") or []):
        addr = _as_fixed_bytes(log["address"], 20, f"logs[{i}].address")
        topics = [_as_fixed_bytes(t, 32, f"logs[{i}].topics") for t in (log.get("topics") or [])]
        raw_d = log.get("data")
        data = b"" if not raw_d or raw_d in ("0x", "0X") else _as_bytes_flex(raw_d, f"logs[{i}].data")
        enc_logs.append([addr, topics, data])

    tup: list[Any] = [status_or_root, cum_gas, bloom, enc_logs]
    if tx_type == 0x7E and rpc_receipt.get("depositNonce") is not None:
        tup.append(uint_to_minimal_bytes(_parse_uint256(rpc_receipt["depositNonce"], "depositNonce")))
        if rpc_receipt.get("depositReceiptVersion") is not None:
            tup.append(uint_to_minimal_bytes(_parse_uint256(rpc_receipt["depositReceiptVersion"], "depositReceiptVersion")))

    rlp_payload = rlp_encode(tup)
    return rlp_payload if tx_type == 0 else bytes([tx_type]) + rlp_payload


def decode_evm_receipt(raw_receipt_bytes: Any) -> dict[str, Any]:
    raw = _as_bytes_flex(raw_receipt_bytes, "raw_receipt_bytes")
    if len(raw) == 0:
        raise ValueError("Empty receipt bytes")
    tx_type = 0
    rlp_slice = raw
    if raw[0] < 0x80:
        if raw[0] == 0 or len(raw) < 2 or raw[1] < 0xC0:
            raise ValueError(f"Invalid EIP-2718 receipt envelope (type=0x{raw[0]:x})")
        tx_type = raw[0]
        rlp_slice = raw[1:]
    elif raw[0] < 0xC0:
        raise ValueError("Legacy receipt payload must be an RLP list (prefix >= 0xc0)")

    lst = rlp_decode(rlp_slice)
    max_items = 6 if tx_type == 0x7E else 4
    if not isinstance(lst, list) or len(lst) < 4 or len(lst) > max_items:
        raise ValueError(f"Invalid receipt RLP tuple length for txType=0x{tx_type:x}")

    status_b, gas_b, bloom_b, raw_logs = lst[:4]
    if not isinstance(status_b, bytes) or not isinstance(gas_b, bytes) or not isinstance(bloom_b, bytes) or not isinstance(raw_logs, list):
        raise ValueError("Invalid receipt RLP field types")
    if len(bloom_b) != 256:
        raise ValueError(f"Invalid logsBloom length {len(bloom_b)} (expected 256)")

    status: int | None = None
    post_root: str | None = None
    if len(status_b) == 0:
        status = 0
    elif status_b == b"\x01":
        status = 1
    elif len(status_b) == 32:
        post_root = "0x" + status_b.hex()
    else:
        raise ValueError(f"Invalid receipt status bytes (len={len(status_b)})")

    logs: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw_logs):
        if not isinstance(entry, list) or len(entry) != 3:
            raise ValueError(f"Malformed log[{idx}] RLP tuple")
        a_b, top_arr, d_b = entry
        if not isinstance(a_b, bytes) or len(a_b) != 20 or not isinstance(top_arr, list) or not isinstance(d_b, bytes):
            raise ValueError(f"Malformed log[{idx}] fields")
        topics: list[str] = []
        for t in top_arr:
            if not isinstance(t, bytes) or len(t) != 32:
                raise ValueError(f"Malformed log[{idx}] topic")
            topics.append("0x" + t.hex())
        logs.append({
            "logIndex": idx,
            "address": "0x" + a_b.hex(),
            "topics": topics,
            "data": "0x" + d_b.hex(),
        })

    out: dict[str, Any] = {
        "txType": tx_type,
        "status": status,
        "cumulativeGasUsed": bytes_to_int(gas_b, strict_minimal=True),
        "logsBloom": "0x" + bloom_b.hex(),
        "logs": logs,
    }
    if post_root:
        out["postStateRoot"] = post_root
    if tx_type == 0x7E and len(lst) >= 5:
        out["depositNonce"] = bytes_to_int(lst[4], strict_minimal=True)
        if len(lst) == 6:
            out["depositReceiptVersion"] = bytes_to_int(lst[5], strict_minimal=True)
    return out


def build_receipt_trie_proof(
    block_receipts: list[dict[str, Any]],
    target_tx_hash_or_index: str | int,
    *,
    network: str | None = None,
    block_number: str | int | None = None,
    block_hash: str | None = None,
) -> dict[str, Any]:
    if not isinstance(block_receipts, list) or len(block_receipts) == 0:
        raise TypeError("block_receipts must be a non-empty list")

    want_hash = (
        target_tx_hash_or_index.strip().lower()
        if isinstance(target_tx_hash_or_index, str) and _HEX32_RE.match(target_tx_hash_or_index.strip())
        else None
    )
    want_idx = None if want_hash is not None else _parse_uint256(target_tx_hash_or_index, "target_tx_index")

    entries: list[dict[str, Any]] = []
    target_rcpt: dict[str, Any] | None = None
    target_idx: int | None = None

    for i, r in enumerate(block_receipts):
        tx_idx = _parse_uint256(r.get("transactionIndex", i), f"block_receipts[{i}].transactionIndex")
        entries.append({"key": rlp_encode(tx_idx), "value": encode_evm_receipt(r)})
        if want_hash is not None:
            if str(r.get("transactionHash", "")).lower() == want_hash:
                target_rcpt = r
                target_idx = tx_idx
        elif tx_idx == want_idx:
            target_rcpt = r
            target_idx = tx_idx

    if target_idx is None or target_rcpt is None:
        raise ValueError(f"Target transaction ({target_tx_hash_or_index}) not found in block_receipts")

    built = build_mpt_proof(entries, rlp_encode(target_idx))
    raw_bn = block_number if block_number is not None else target_rcpt.get("blockNumber")
    bn_str = str(_parse_uint256(raw_bn, "blockNumber")) if raw_bn is not None else None
    bh = block_hash or target_rcpt.get("blockHash")
    norm_net = normalize_evm_network_id(network) if network else None

    res: dict[str, Any] = {
        "type": "evm_receipt_trie_v0",
        "receiptsRoot": built["rootHash"],
        "transactionIndex": target_idx,
        "receiptProof": built["proof"],
    }
    if norm_net:
        res["network"] = norm_net
    if bn_str is not None:
        res["blockNumber"] = bn_str
    if bh:
        res["blockHash"] = str(bh).lower()
    if target_rcpt.get("transactionHash"):
        res["transactionHash"] = str(target_rcpt["transactionHash"]).lower()
    return res


def verify_evm_receipt_proof(
    *,
    receipts_root: Any,
    transaction_index: Any,
    receipt_proof: Any,
) -> dict[str, Any]:
    try:
        tx_idx = _parse_uint256(transaction_index, "transaction_index")
    except Exception as exc:
        return {"ok": False, "verified": False, "code": "invalid_transaction_index", "reason": str(exc)}

    mpt = verify_mpt_proof(root_hash=receipts_root, key=rlp_encode(tx_idx), proof=receipt_proof)
    if not mpt["ok"]:
        return {
            "ok": False,
            "verified": False,
            "code": mpt["code"],
            "reason": mpt["reason"],
            "receiptsRoot": mpt["rootHash"],
            "transactionIndex": tx_idx,
        }
    if mpt["value"] is None:
        return {
            "ok": False,
            "verified": False,
            "code": "receipt_not_found",
            "reason": f"No transaction receipt exists at transactionIndex={tx_idx} under {mpt['rootHash']}.",
            "receiptsRoot": mpt["rootHash"],
            "transactionIndex": tx_idx,
        }
    try:
        dec = decode_evm_receipt(mpt["value"])
    except Exception as exc:
        return {
            "ok": False,
            "verified": False,
            "code": "invalid_receipt_rlp",
            "reason": f"Failed to decode EVM receipt RLP: {exc}",
            "receiptsRoot": mpt["rootHash"],
            "transactionIndex": tx_idx,
        }
    return {
        "ok": True,
        "verified": True,
        "code": "verified",
        "reason": f"Verified EVM receipt (type=0x{dec['txType']:x}, status={dec['status']}) at index {tx_idx} against {mpt['rootHash']}.",
        "receiptsRoot": mpt["rootHash"],
        "transactionIndex": tx_idx,
        "receipt": dec,
    }


def _normalize_topic_address(topic_hex: Any) -> str | None:
    if not isinstance(topic_hex, str) or not _HEX32_RE.match(topic_hex):
        return None
    if topic_hex[2:26] != "0" * 24:
        return None
    return "0x" + topic_hex[26:].lower()


def _match_trusted_root(
    trusted_roots: Any,
    *,
    root_field: str,
    alt_field: str,
    network: str | None,
    block_number: str | None,
    block_hash: str | None,
    target_root: str,
) -> bool:
    if not trusted_roots or not target_root:
        return False
    want_r = target_root.lower()

    def check_entry(entry: Any) -> bool:
        if not entry:
            return False
        if isinstance(entry, str):
            return entry.strip().lower() == want_r
        if isinstance(entry, dict):
            cand = str(entry.get(root_field) or entry.get(alt_field) or "").strip().lower()
            if not cand or cand != want_r:
                return False
            if entry.get("network") and network and normalize_evm_network_id(entry["network"]) != network:
                return False
            if entry.get("blockNumber") is not None and block_number is not None:
                try:
                    if str(_parse_uint256(entry["blockNumber"], "blockNumber")) != block_number:
                        return False
                except Exception:
                    return False
            if entry.get("blockHash") and block_hash and str(entry["blockHash"]).lower() != block_hash.lower():
                return False
            return True
        return False

    if isinstance(trusted_roots, (list, tuple, set)):
        return any(check_entry(it) for it in trusted_roots)
    if isinstance(trusted_roots, dict):
        keys: list[str] = []
        if network and block_number is not None:
            keys.append(f"{network}:{block_number}")
        if block_number is not None:
            keys.append(block_number)
        if network and block_hash:
            keys.append(f"{network}:{block_hash.lower()}")
        if block_hash:
            keys.append(block_hash.lower())
        if network:
            keys.append(network)
        for k in keys:
            if k in trusted_roots and check_entry(trusted_roots[k]):
                return True
        return check_entry(trusted_roots)
    return False


# ─── 7. Signed Block Root Attestations (paxiom.root.v0) ─────────────────


def _parse_iso_epoch_sec(val: Any) -> float | None:
    if not isinstance(val, str) or not _ISO_DATETIME_RE.match(val):
        return None
    norm = val[:-1] + "+00:00" if val.endswith("Z") else val
    if "." in norm:
        head, tail = norm.split(".", 1)
        tz_idx = max(tail.find("+"), tail.find("-"))
        frac, tz_part = (tail[:tz_idx], tail[tz_idx:]) if tz_idx != -1 else (tail, "")
        norm = f"{head}.{(frac + '000000')[:6]}{tz_part}"
    try:
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def root_attestation_signing_bytes(payload: dict[str, Any]) -> bytes:
    return canonicalize({
        "attestationVersion": ROOT_ATTESTATION_VERSION,
        "payload": payload,
    }).encode("utf-8")


def validate_root_attestation_structure(attestation: Any, depth: int = 0) -> list[str]:
    if depth > MAX_DEPTH:
        return ["Attestation exceeds max depth"]
    if not isinstance(attestation, dict):
        return ["Root attestation must be a dict"]
    errs: list[str] = []
    if attestation.get("attestationVersion") != ROOT_ATTESTATION_VERSION:
        errs.append(f"Unsupported attestationVersion '{attestation.get('attestationVersion')}'")
    p = attestation.get("payload")
    if not isinstance(p, dict):
        return [*errs, "payload must be a dict"]
    if not isinstance(p.get("network"), str) or not p["network"].strip():
        errs.append("payload.network must be a non-empty string")
    if not isinstance(p.get("blockNumber"), str) or not _DEC_UINT_RE.match(p["blockNumber"]):
        errs.append("payload.blockNumber must be a canonical decimal integer string")
    if not isinstance(p.get("blockHash"), str) or not _HEX32_RE.match(p["blockHash"]):
        errs.append("payload.blockHash must be a 0x-prefixed 32-byte hex string")
    if p.get("stateRoot") is not None and (not isinstance(p.get("stateRoot"), str) or not _HEX32_RE.match(p["stateRoot"])):
        errs.append("payload.stateRoot must be a 0x-prefixed 32-byte hex string")
    if p.get("receiptsRoot") is not None and (not isinstance(p.get("receiptsRoot"), str) or not _HEX32_RE.match(p["receiptsRoot"])):
        errs.append("payload.receiptsRoot must be a 0x-prefixed 32-byte hex string")
    if not p.get("stateRoot") and not p.get("receiptsRoot"):
        errs.append("payload must include stateRoot or receiptsRoot")
    if p.get("finalityTier") not in ALLOWED_FINALITY_TIERS:
        errs.append(f"payload.finalityTier must be one of {ALLOWED_FINALITY_TIERS}")
    if _parse_iso_epoch_sec(p.get("issuedAt")) is None:
        errs.append("payload.issuedAt must be an ISO-8601 timestamp")
    if "expiresAt" in p and _parse_iso_epoch_sec(p.get("expiresAt")) is None:
        errs.append("payload.expiresAt must be an ISO-8601 timestamp")
    attester = p.get("attester")
    if not isinstance(attester, dict) or not attester.get("name") or not attester.get("keyId"):
        errs.append("payload.attester.{name,keyId} are required")
    sig = attestation.get("signature")
    if not isinstance(sig, dict):
        return [*errs, "signature object is required"]
    if sig.get("algorithm") != "ed25519":
        errs.append("signature.algorithm must be 'ed25519'")
    if sig.get("keyId") != (attester or {}).get("keyId"):
        errs.append("signature.keyId must match payload.attester.keyId")
    if not isinstance(sig.get("publicKey"), str) or not isinstance(sig.get("value"), str):
        errs.append("signature.publicKey and signature.value must be base64 strings")
    return errs


def issue_root_attestation(
    *,
    private_key: Any,
    network: str,
    block_number: str | int,
    block_hash: str | bytes,
    attester: dict[str, Any],
    state_root: str | bytes | None = None,
    receipts_root: str | bytes | None = None,
    timestamp: int | None = None,
    finality_tier: str = "l2-sequencer-attested",
    issued_at: str | datetime | None = None,
    expires_at: str | datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(attester, dict) or not attester.get("name") or not attester.get("keyId"):
        raise TypeError("attester.name and attester.keyId are required")
    norm_net = normalize_evm_network_id(network)
    if not norm_net:
        raise TypeError("network is required")
    norm_bn = str(_parse_uint256(block_number, "block_number"))
    norm_bh = "0x" + _as_fixed_bytes(block_hash, 32, "block_hash").hex()
    norm_sr = "0x" + _as_fixed_bytes(state_root, 32, "state_root").hex() if state_root is not None else None
    norm_rr = "0x" + _as_fixed_bytes(receipts_root, 32, "receipts_root").hex() if receipts_root is not None else None
    if not norm_sr and not norm_rr:
        raise TypeError("At least one of state_root or receipts_root is required")
    if finality_tier not in ALLOWED_FINALITY_TIERS:
        raise ValueError(f"Invalid finality_tier '{finality_tier}'")

    seed = extract_ed25519_seed(private_key)
    pub_b64 = base64.b64encode(ed25519_public_key_from_seed(seed)).decode("ascii")

    now_iso = (
        issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(issued_at, datetime)
        else (str(issued_at) if issued_at is not None else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    )

    payload: dict[str, Any] = {
        "network": norm_net,
        "blockNumber": norm_bn,
        "blockHash": norm_bh,
        "finalityTier": finality_tier,
        "issuedAt": now_iso,
        "attester": {
            "name": str(attester["name"]),
            "keyId": str(attester["keyId"]),
            **({"uri": str(attester["uri"])} if attester.get("uri") else {}),
        },
    }
    if norm_sr:
        payload["stateRoot"] = norm_sr
    if norm_rr:
        payload["receiptsRoot"] = norm_rr
    if timestamp is not None:
        payload["timestamp"] = int(timestamp)
    if expires_at is not None:
        payload["expiresAt"] = (
            expires_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if isinstance(expires_at, datetime)
            else str(expires_at)
        )

    sig_bytes = ed25519_sign(seed, root_attestation_signing_bytes(payload))
    return {
        "attestationVersion": ROOT_ATTESTATION_VERSION,
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": payload["attester"]["keyId"],
            "publicKey": pub_b64,
            "value": base64.b64encode(sig_bytes).decode("ascii"),
        },
    }


def _strict_b64(val: Any, expected_len: int, label: str) -> bytes:
    if not isinstance(val, str) or len(val) == 0 or len(val) % 4 != 0 or not _STRICT_BASE64_RE.match(val):
        raise ValueError(f"{label} must be canonical base64")
    raw = base64.b64decode(val, validate=True)
    if len(raw) != expected_len or base64.b64encode(raw).decode("ascii") != val:
        raise ValueError(f"{label} must decode to {expected_len} canonical bytes")
    return raw


def verify_root_attestation(
    attestation: Any,
    *,
    trusted_root_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    allowed_finality_tiers: list[str] | tuple[str, ...] | set[str] | None = None,
    now: float | datetime | str | None = None,
) -> dict[str, Any]:
    def fail(code: str, reason: str) -> dict[str, Any]:
        return {"ok": False, "verified": False, "code": code, "reason": reason, "payload": None}

    errs = validate_root_attestation_structure(attestation)
    if errs:
        return fail("invalid_root_attestation", errs[0])

    sig = attestation["signature"]
    try:
        pub_b = _strict_b64(sig["publicKey"], 32, "signature.publicKey")
        sig_b = _strict_b64(sig["value"], 64, "signature.value")
        msg_b = root_attestation_signing_bytes(attestation["payload"])
    except Exception as exc:
        return fail("invalid_signature", str(exc))

    if not ed25519_verify(pub_b, msg_b, sig_b):
        return fail("invalid_signature", "Ed25519 signature verification failed on rootAttestation.")

    if trusted_root_public_keys is not None:
        if sig["publicKey"] not in set(trusted_root_public_keys):
            return fail("untrusted_root_signer", f"Root attestation signer ({sig['publicKey']}) is not in trusted_root_public_keys.")

    if allowed_finality_tiers is not None and len(allowed_finality_tiers) > 0:
        if attestation["payload"]["finalityTier"] not in set(allowed_finality_tiers):
            return fail(
                "disallowed_finality_tier",
                f"Root attestation finalityTier '{attestation['payload']['finalityTier']}' is not in allowed_finality_tiers.",
            )

    if now is None:
        now_sec = time.time()
    elif isinstance(now, datetime):
        now_sec = now.timestamp()
    elif isinstance(now, (int, float)):
        # Support either epoch ms (>1e11) or epoch seconds
        now_sec = float(now) / 1000.0 if now > 100_000_000_000 else float(now)
    else:
        parsed_n = _parse_iso_epoch_sec(str(now))
        now_sec = parsed_n if parsed_n is not None else time.time()

    exp_str = attestation["payload"].get("expiresAt")
    if exp_str:
        exp_sec = _parse_iso_epoch_sec(exp_str)
        if exp_sec is not None and exp_sec < now_sec:
            return fail("expired_root_attestation", f"Root attestation expired at {exp_str}.")

    return {
        "ok": True,
        "verified": True,
        "code": "verified",
        "reason": f"Verified paxiom.root.v0 attestation for {attestation['payload']['network']} block {attestation['payload']['blockNumber']}.",
        "payload": attestation["payload"],
        "signerPublicKey": sig["publicKey"],
    }


def verify_usdc_settlement_proof(
    *,
    settlement_proof: Any,
    network: str | None = None,
    expected_pay_to: str | None = None,
    expected_payer: str | None = None,
    min_amount_atomic: int | str = 0,
    expected_asset: str = "USDC",
    expected_transaction_hash: str | None = None,
    trusted_roots: Any = None,
    root_attestation: Any = None,
    trusted_root_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    trusted_verifier_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    allowed_finality_tiers: list[str] | tuple[str, ...] | set[str] | None = None,
    verified_root_attestation: dict[str, Any] | None = None,
    allow_unanchored_root: bool = False,
    now: float | datetime | str | None = None,
) -> dict[str, Any]:
    def fail(code: str, reason: str, **extra: Any) -> dict[str, Any]:
        return {"ok": False, "verified": False, "code": code, "reason": reason, "rootAnchored": bool(extra.pop("rootAnchored", False)), **extra}

    if not isinstance(settlement_proof, dict):
        return fail("invalid_settlement_proof", "settlement_proof must be a dict.")

    raw_att = root_attestation or settlement_proof.get("rootAttestation")
    raw_keys = trusted_root_public_keys if trusted_root_public_keys is not None else trusted_verifier_public_keys
    eff_verified_att = verified_root_attestation

    if eff_verified_att is None and raw_att is not None:
        if raw_keys is None and not allow_unanchored_root:
            return fail("untrusted_root_signer", "rootAttestation provided without trusted_root_public_keys.")
        att_res = verify_root_attestation(
            raw_att,
            trusted_root_public_keys=raw_keys,
            allowed_finality_tiers=allowed_finality_tiers,
            now=now,
        )
        if not att_res["ok"]:
            return fail(att_res["code"], att_res["reason"])
        eff_verified_att = att_res

    eff_net = normalize_evm_network_id(network or settlement_proof.get("network"))
    if not eff_net:
        return fail("missing_network", "network is required to verify USDC settlement proof.")

    asset_str = str(expected_asset or "USDC").strip()
    if asset_str.upper() == "USDC":
        token_addr = CANONICAL_USDC_BY_NETWORK.get(eff_net)
        if not token_addr:
            return fail("unsupported_network", f"No canonical USDC contract registered for network '{eff_net}'.")
    elif _EVM_ADDR_RE.match(asset_str):
        token_addr = asset_str
    else:
        return fail("unsupported_asset", f"Unsupported asset '{asset_str}'.")
    want_token_lower = token_addr.lower()

    try:
        req_amt = _parse_uint256(min_amount_atomic, "min_amount_atomic")
    except Exception as exc:
        return fail("invalid_amount", str(exc))

    want_to: str | None = None
    if expected_pay_to is not None and str(expected_pay_to).strip():
        if not _EVM_ADDR_RE.match(str(expected_pay_to).strip()):
            return fail("invalid_pay_to", f"expected_pay_to '{expected_pay_to}' is not a valid EVM address.")
        want_to = str(expected_pay_to).strip().lower()

    want_payer: str | None = None
    if expected_payer is not None and str(expected_payer).strip():
        if not _EVM_ADDR_RE.match(str(expected_payer).strip()):
            return fail("invalid_payer", f"expected_payer '{expected_payer}' is not a valid EVM address.")
        want_payer = str(expected_payer).strip().lower()

    if expected_transaction_hash and settlement_proof.get("transactionHash"):
        if str(expected_transaction_hash).lower() != str(settlement_proof["transactionHash"]).lower():
            return fail("transaction_hash_mismatch", "settlementProof.transactionHash != receipt transactionHash.")

    evm_res = verify_evm_receipt_proof(
        receipts_root=settlement_proof.get("receiptsRoot"),
        transaction_index=settlement_proof.get("transactionIndex", settlement_proof.get("txIndex")),
        receipt_proof=settlement_proof.get("receiptProof", settlement_proof.get("proof")),
    )
    if not evm_res["ok"]:
        return fail(evm_res["code"], evm_res["reason"], receiptsRoot=evm_res.get("receiptsRoot"))

    if evm_res["receipt"]["status"] != 1:
        return fail(
            "tx_reverted",
            f"Transaction at index {evm_res['transactionIndex']} reverted (status={evm_res['receipt']['status']}).",
            receiptsRoot=evm_res["receiptsRoot"],
            transactionIndex=evm_res["transactionIndex"],
        )

    bn_str: str | None = None
    if settlement_proof.get("blockNumber") is not None:
        try:
            bn_str = str(_parse_uint256(settlement_proof["blockNumber"], "blockNumber"))
        except Exception as exc:
            return fail("invalid_block_number", str(exc))
    bh_str = str(settlement_proof["blockHash"]).lower() if settlement_proof.get("blockHash") else None

    root_anchored = False
    anchor_source: str | None = None
    if eff_verified_att and eff_verified_att.get("ok"):
        att_p = eff_verified_att["payload"]
        if normalize_evm_network_id(att_p["network"]) != eff_net:
            return fail("root_attestation_mismatch", "Root attestation network mismatch.")
        if str(att_p.get("receiptsRoot", "")).lower() != evm_res["receiptsRoot"].lower():
            return fail("root_attestation_mismatch", "Root attestation receiptsRoot mismatch.")
        if bn_str is not None and str(att_p["blockNumber"]) != bn_str:
            return fail("root_attestation_mismatch", "Root attestation blockNumber mismatch.")
        if bh_str and att_p.get("blockHash") and str(att_p["blockHash"]).lower() != bh_str:
            return fail("root_attestation_mismatch", "Root attestation blockHash mismatch.")
        root_anchored = True
        anchor_source = "rootAttestation"
    elif _match_trusted_root(
        trusted_roots,
        root_field="receiptsRoot",
        alt_field="receipts_root",
        network=eff_net,
        block_number=bn_str,
        block_hash=bh_str,
        target_root=evm_res["receiptsRoot"],
    ):
        root_anchored = True
        anchor_source = "trustedRoots"

    if not root_anchored and not allow_unanchored_root:
        return fail(
            "untrusted_receipts_root",
            f"MPT receipt proof verified structurally under {evm_res['receiptsRoot']}, but receiptsRoot is not anchored.",
            receiptsRoot=evm_res["receiptsRoot"],
            transactionIndex=evm_res["transactionIndex"],
        )

    matched: list[dict[str, Any]] = []
    for log in evm_res["receipt"]["logs"]:
        if log["address"] != want_token_lower:
            continue
        topics = log["topics"]
        if len(topics) != 3 or topics[0] != ERC20_TRANSFER_TOPIC0:
            continue
        frm = _normalize_topic_address(topics[1])
        to_a = _normalize_topic_address(topics[2])
        if not frm or not to_a:
            continue
        if len(log["data"]) != 66:
            continue
        amt = int(log["data"], 16)
        if want_to and to_a != want_to:
            continue
        if want_payer and frm != want_payer:
            continue
        if amt < req_amt:
            continue
        matched.append({
            "logIndex": log["logIndex"],
            "token": token_addr,
            "from": frm,
            "to": to_a,
            "amountAtomic": str(amt),
        })

    if not matched:
        return fail(
            "matching_transfer_not_found",
            f"Receipt at index {evm_res['transactionIndex']} succeeded, but emitted no Transfer >= {req_amt} on {token_addr}.",
            rootAnchored=root_anchored,
            receiptsRoot=evm_res["receiptsRoot"],
            transactionIndex=evm_res["transactionIndex"],
        )

    return {
        "ok": True,
        "verified": True,
        "code": "verified_settled",
        "reason": f"Verified on-chain {asset_str} Transfer ({matched[0]['amountAtomic']} atomic units to {matched[0]['to']}) via MPT receipt proof at txIndex={evm_res['transactionIndex']}.",
        "network": eff_net,
        "blockNumber": bn_str,
        "blockHash": bh_str,
        "receiptsRoot": evm_res["receiptsRoot"],
        "transactionIndex": evm_res["transactionIndex"],
        "rootAnchored": root_anchored,
        "anchorSource": anchor_source,
        "matchedTransfer": matched[0],
        "allMatchedTransfers": matched,
    }


def evaluate_receipt_offline_proofs(
    *,
    receipt: dict[str, Any],
    settlement_proof: Any = None,
    claim_proof: Any = None,
    trusted_roots: Any = None,
    root_attestation: Any = None,
    trusted_root_public_keys: list[str] | tuple[str, ...] | set[str] | None = None,
    allowed_finality_tiers: list[str] | tuple[str, ...] | set[str] | None = None,
    expected_pay_to: str | None = None,
    expected_payer: str | None = None,
    now: float | datetime | str | None = None,
) -> dict[str, Any]:
    p = receipt["payload"]
    raw_att = (
        root_attestation
        or (settlement_proof.get("rootAttestation") if isinstance(settlement_proof, dict) else None)
        or (claim_proof.get("rootAttestation") if isinstance(claim_proof, dict) else None)
    )

    verified_att: dict[str, Any] | None = None
    att_err: dict[str, Any] | None = None
    if raw_att is not None:
        if trusted_root_public_keys is None:
            att_err = {
                "code": "untrusted_root_signer",
                "reason": "rootAttestation supplied without trusted_root_public_keys.",
            }
        else:
            att_check = verify_root_attestation(
                raw_att,
                trusted_root_public_keys=trusted_root_public_keys,
                allowed_finality_tiers=allowed_finality_tiers,
                now=now,
            )
            if att_check["ok"]:
                verified_att = att_check
            else:
                att_err = att_check

    eff_net = normalize_evm_network_id(
        (settlement_proof.get("network") if isinstance(settlement_proof, dict) else None)
        or (claim_proof.get("network") if isinstance(claim_proof, dict) else None)
        or p["payment"]["network"]
    )

    claim_verified = False
    if claim_proof is not None:
        if not isinstance(claim_proof, dict):
            return {"outcome": "fail", "trustState": "proof_invalid", "checkProof": "invalid", "summary": "claim_proof must be a dict."}
        raw_p_obj = claim_proof["proof"] if isinstance(claim_proof.get("proof"), dict) else claim_proof
        sr = claim_proof.get("stateRoot") or ((verified_att or {}).get("payload") or {}).get("stateRoot")
        if not sr:
            return {
                "outcome": "fail",
                "trustState": "proof_invalid",
                "checkProof": "invalid",
                "summary": f"Offline claimProof failed: {att_err['reason']}" if att_err else "Offline EIP-1186 claimProof requires stateRoot.",
            }
        eip_res = verify_eip1186_proof(state_root=sr, proof=raw_p_obj, expected_storage=claim_proof.get("expectedStorage"))
        if not eip_res["ok"]:
            return {"outcome": "fail", "trustState": "proof_invalid", "checkProof": "invalid", "summary": f"Offline EIP-1186 claimProof failed: {eip_res['reason']}"}

        cp_bn = str(_parse_uint256(claim_proof["blockNumber"], "blockNumber")) if claim_proof.get("blockNumber") is not None else None
        cp_bh = str(claim_proof["blockHash"]).lower() if claim_proof.get("blockHash") else None
        sr_anchored = bool(claim_proof.get("allowUnanchoredRoot"))
        if verified_att and verified_att.get("ok") and str(verified_att["payload"].get("stateRoot", "")).lower() == eip_res["stateRoot"].lower():
            sr_anchored = True
        elif _match_trusted_root(
            trusted_roots,
            root_field="stateRoot",
            alt_field="state_root",
            network=eff_net,
            block_number=cp_bn,
            block_hash=cp_bh,
            target_root=eip_res["stateRoot"],
        ):
            sr_anchored = True
        if not sr_anchored:
            return {
                "outcome": "fail",
                "trustState": "proof_invalid",
                "checkProof": "invalid",
                "summary": f"Offline EIP-1186 claimProof rootAttestation failed: {att_err['reason']}" if att_err else f"Offline EIP-1186 claimProof verified structurally under {eip_res['stateRoot']}, but stateRoot is not anchored.",
            }
        claim_verified = True

    if settlement_proof is not None:
        rcpt_pay_to = expected_pay_to or p["payment"].get("payTo") or p["issuer"].get("payTo")
        rcpt_payer = expected_payer or p["payment"].get("payer")
        rcpt_tx = p["payment"]["settlement"].get("transactionHash")

        structural = verify_usdc_settlement_proof(
            settlement_proof=settlement_proof,
            network=p["payment"]["network"],
            expected_pay_to=rcpt_pay_to,
            expected_payer=rcpt_payer,
            min_amount_atomic=p["payment"]["amountAtomic"],
            expected_asset=p["payment"]["asset"],
            expected_transaction_hash=rcpt_tx,
            trusted_roots=trusted_roots,
            verified_root_attestation=verified_att if (verified_att and verified_att.get("ok")) else None,
            allow_unanchored_root=True,
            now=now,
        )
        if not structural["ok"]:
            if structural["code"] == "tx_reverted":
                return {
                    "outcome": "fail",
                    "trustState": "settlement_failed",
                    "checkSettlement": "failed",
                    "checkProof": "invalid",
                    "summary": f"Offline settlement proof shows transaction reverted: {structural['reason']}",
                }
            return {
                "outcome": "fail",
                "trustState": "proof_invalid",
                "checkProof": "invalid",
                "summary": f"Offline settlement proof failed verification: {structural['reason']}",
            }

        if att_err and att_err["code"] in ("invalid_signature", "invalid_root_attestation"):
            return {
                "outcome": "fail",
                "trustState": "proof_invalid",
                "checkProof": "invalid",
                "summary": f"Offline rootAttestation failed verification: {att_err['reason']}",
            }

        if structural["rootAnchored"]:
            return {
                "outcome": "verified_settled",
                "checkSettlement": "verified_settled",
                "checkProof": "verified",
                "summary": structural["reason"],
            }

        return {
            "outcome": "unanchored_settlement_proof",
            "checkProof": "verified" if claim_verified else "provided",
            "summary": (
                f"MPT settlement proof verified structurally, but rootAttestation did not anchor receiptsRoot: {att_err['reason']}"
                if att_err
                else f"MPT settlement proof verified structurally against {structural['receiptsRoot']}, but receiptsRoot was not anchored."
            ),
        }

    if claim_verified:
        return {"outcome": "claim_verified", "checkProof": "verified"}

    return {"outcome": "none"}
