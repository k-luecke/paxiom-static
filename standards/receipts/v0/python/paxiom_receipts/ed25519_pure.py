"""RFC 8032 Ed25519 & RFC 8410 PKCS#8 PEM helpers with optional OpenSSL acceleration."""
from __future__ import annotations

import base64
import hashlib
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _CryptoPriv,
        Ed25519PublicKey as _CryptoPub,
    )
    from cryptography.hazmat.primitives import serialization as _crypto_ser

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - exercised when cryptography is absent
    _HAS_CRYPTOGRAPHY = False

# RFC 8410 Section 7 unencrypted Ed25519 PrivateKeyInfo DER prefix (16 bytes + 32-byte seed)
PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
# OID 1.3.101.112 (id-Ed25519)
_OID_ED25519 = bytes.fromhex("06032b6570")

# RFC 8032 curve parameters (Ed25519)
_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    y2 = (y * y) % _P
    x2 = ((y2 - 1) * pow(_D * y2 + 1, _P - 2, _P)) % _P
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
# Extended twisted Edwards coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z
_BASE_PT = (_BX, _BY, 1, (_BX * _BY) % _P)
_IDENTITY_PT = (0, 1, 1, 0)


def _point_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_double(p1: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p1
    a = (x1 * x1) % _P
    b = (y1 * y1) % _P
    c = (2 * z1 * z1) % _P
    h = (a + b) % _P
    xy = (x1 + y1) % _P
    e = (h - (xy * xy) % _P) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(k: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    res = _IDENTITY_PT
    addend = pt
    n = k
    while n > 0:
        if n & 1:
            res = _point_add(res, addend)
        addend = _point_double(addend)
        n >>= 1
    return res


def _point_encode(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _P - 2, _P)
    xp = (x * zi) % _P
    yp = (y * zi) % _P
    return (yp | ((xp & 1) << 255)).to_bytes(32, "little")


def _point_decode_canonical(enc: bytes) -> tuple[int, int, int, int] | None:
    if len(enc) != 32:
        return None
    unpacked = int.from_bytes(enc, "little")
    sign = (unpacked >> 255) & 1
    y = unpacked & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    pt = (x, y, 1, (x * y) % _P)
    # Enforce canonical point encoding (reject -0 sign bit)
    if _point_encode(pt) != enc:
        return None
    return pt


def _b64url_decode_nopad(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def extract_ed25519_seed(private_key: Any) -> bytes:
    """Normalize a PKCS#8 PEM string, JWK dict, 32-byte raw seed, or cryptography key into a 32-byte seed."""
    if private_key is None:
        raise TypeError("private_key is required to sign a Paxiom receipt")

    if isinstance(private_key, (bytes, bytearray, memoryview)):
        raw = bytes(private_key)
        if len(raw) == 32:
            return raw
        raise TypeError(f"Raw Ed25519 private key seed must be 32 bytes, got {len(raw)}")

    if _HAS_CRYPTOGRAPHY and isinstance(private_key, _CryptoPriv):
        return private_key.private_bytes(
            encoding=_crypto_ser.Encoding.Raw,
            format=_crypto_ser.PrivateFormat.Raw,
            encryption_algorithm=_crypto_ser.NoEncryption(),
        )

    if isinstance(private_key, dict):
        if private_key.get("kty") == "OKP" and private_key.get("crv") == "Ed25519" and isinstance(private_key.get("d"), str):
            seed = _b64url_decode_nopad(private_key["d"])
            if len(seed) != 32:
                raise TypeError("Ed25519 JWK 'd' field must decode to 32 bytes")
            return seed
        raise TypeError("Unsupported JWK private_key: expected {kty: 'OKP', crv: 'Ed25519', d: '...'}")

    if isinstance(private_key, str):
        text = private_key.strip()
        if "-----BEGIN PRIVATE KEY-----" in text:
            lines = [
                ln.strip()
                for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith("-----")
            ]
            der = base64.b64decode("".join(lines), validate=True)
            if len(der) == 48 and der.startswith(PKCS8_ED25519_PREFIX):
                return der[16:48]
            # Handle OneAsymmetricKey / PKCS#8 with optional attributes/publicKey
            idx = der.find(_OID_ED25519)
            if idx != -1:
                rest = der[idx + len(_OID_ED25519) :]
                if len(rest) >= 36 and rest[0] == 0x04 and rest[1] == 0x22 and rest[2] == 0x04 and rest[3] == 0x20:
                    return rest[4:36]
            raise TypeError("PEM private key is not an unencrypted Ed25519 PKCS#8 key")
        raise TypeError("String private_key must be a PKCS#8 PEM ('-----BEGIN PRIVATE KEY-----')")

    raise TypeError("Unsupported private_key format: supply PKCS#8 PEM, Ed25519 JWK dict, or 32-byte seed")


def seed_to_pkcs8_pem(seed: bytes) -> str:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    der = PKCS8_ED25519_PREFIX + seed
    b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----\n"


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    if _HAS_CRYPTOGRAPHY:
        priv = _CryptoPriv.from_private_bytes(seed)
        return priv.public_key().public_bytes(
            encoding=_crypto_ser.Encoding.Raw,
            format=_crypto_ser.PublicFormat.Raw,
        )
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _point_encode(_scalar_mult(a, _BASE_PT))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    if _HAS_CRYPTOGRAPHY:
        return _CryptoPriv.from_private_bytes(seed).sign(message)
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:64]
    pub_bytes = _point_encode(_scalar_mult(a, _BASE_PT))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_bytes = _point_encode(_scalar_mult(r, _BASE_PT))
    k = int.from_bytes(hashlib.sha512(r_bytes + pub_bytes + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_bytes + s.to_bytes(32, "little")


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        return False
    # Enforce strict RFC 8032 §5.1.7 canonical S < L & canonical point encodings before backend call
    s = int.from_bytes(signature_bytes[32:64], "little")
    if s >= _L:
        return False
    if _HAS_CRYPTOGRAPHY:
        # Also verify canonical encodings for R and A so malleable encodings never slip through
        if _point_decode_canonical(public_key_bytes) is None or _point_decode_canonical(signature_bytes[:32]) is None:
            return False
        try:
            _CryptoPub.from_public_bytes(public_key_bytes).verify(signature_bytes, message)
            return True
        except Exception:
            return False

    a_pt = _point_decode_canonical(public_key_bytes)
    r_pt = _point_decode_canonical(signature_bytes[:32])
    if a_pt is None or r_pt is None:
        return False
    k = int.from_bytes(hashlib.sha512(signature_bytes[:32] + public_key_bytes + message).digest(), "little") % _L
    lhs = _scalar_mult(s, _BASE_PT)
    neg_a = ((-a_pt[0]) % _P, a_pt[1], a_pt[2], (-a_pt[3]) % _P)
    rhs_check = _point_add(lhs, _scalar_mult(k, neg_a))
    return _point_encode(rhs_check) == signature_bytes[:32]
