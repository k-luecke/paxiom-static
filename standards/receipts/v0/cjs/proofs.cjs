'use strict';
// Auto-generated from src/proofs.mjs by scripts/build-cjs.mjs — do not edit directly.
// Zero-dependency Offline Cryptographic Proof Verifier & Builder (@paxiom/receipts/proofs).
// Implements:
//   1. Pure Keccak-256 (24-round Keccak-f[1600], 0x01 pad — Ethereum Yellow Paper, NOT NIST SHA3-256)
//   2. Strict Canonical RLP encoder & decoder (Yellow Paper Appendix B)
//   3. Ethereum Modified Merkle-Patricia Trie (MPT) verifier & builder (Yellow Paper Appendix D)
//   4. Offline EIP-1186 Account & Storage Proof verifier + Solidity / EIP-3009 slot helpers
//   5. Offline EVM Receipt-Trie & Canonical USDC Settlement Proof builder & verifier
//      (Legacy + EIP-2718 0x01/0x02/0x03/0x04 + OP-Stack 0x7e Deposit receipts;
//       Ethereum, Base, Base Sepolia, Arbitrum, Optimism, Polygon, and Circle Arc)
//   6. Ed25519 Signed Block Root Attestations (paxiom.root.v0) via pure WebCrypto
//
// Pure Web-Standard module: ZERO `node:*` imports and ZERO Node buffer references.
// Runs identically in Browsers, Cloudflare Workers, Deno, Bun, and Node.js >= 18.

const { isByteArray, asUint8Array, utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, concatBytes, bytesToBase64, base64ToBytes, strictDecodeBase64Bytes } = require('./bytes.cjs');
const { canonicalize, MAX_DEPTH } = require('./canonicalize.cjs');
const { normalizePayToId } = require('./schema.cjs');

const ROOT_ATTESTATION_VERSION = 'paxiom.root.v0';
const ERC8021_MARKER_HEX = '0x80218021802180218021802180218021';
const EMPTY_TRIE_ROOT_HEX =
  '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421';
const EMPTY_CODE_HASH_HEX =
  '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const ERC20_TRANSFER_TOPIC0 =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

const ALLOWED_FINALITY_TIERS = Object.freeze([
  'l1-sync-finalized',
  'l2-sequencer-attested',
  'bft-finalized',
  'rpc-head'
]);

const CANONICAL_USDC_BY_NETWORK = Object.freeze(
  Object.assign(Object.create(null), {
    'eip155:1': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    'eip155:11155111': '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
    'eip155:8453': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    'eip155:84532': '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    'eip155:42161': '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
    'eip155:421614': '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d',
    'eip155:10': '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',
    'eip155:137': '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359',
    'eip155:5042': '0x3600000000000000000000000000000000000000',
    'eip155:5042002': '0x3600000000000000000000000000000000000000'
  })
);

const MAX_RLP_DEPTH = 64;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_ANY_RE = /^0x[0-9a-fA-F]+$/;
const DEC_UINT_RE = /^[0-9]+$/;
const HEX_SEED_32_RE = /^(?:0x)?[0-9a-fA-F]{64}$/;

// RFC 8410 Ed25519 PKCS#8 v1 ASN.1 DER prefix (16 bytes preceding 32-byte seed)
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

// ─── 1. Pure Keccak-256 (Keccak-f[1600], 24 rounds) ─────────────────────

const KECCAK_ROTC = new Uint8Array([
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
]);

const KECCAK_PILN = new Uint8Array([
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
]);

const KECCAK_RC_LO = new Uint32Array([
  0x00000001, 0x00008082, 0x0000808a, 0x80008000,
  0x0000808b, 0x80000001, 0x80008081, 0x00008009,
  0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
  0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
  0x00008002, 0x00000080, 0x0000800a, 0x8000000a,
  0x80008081, 0x00008080, 0x80000001, 0x80008008
]);

const KECCAK_RC_HI = new Uint32Array([
  0x00000000, 0x00000000, 0x80000000, 0x80000000,
  0x00000000, 0x00000000, 0x80000000, 0x80000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x80000000, 0x80000000, 0x80000000,
  0x80000000, 0x80000000, 0x00000000, 0x80000000,
  0x80000000, 0x80000000, 0x00000000, 0x80000000
]);

function keccakF1600(s) {
  const cLo = new Uint32Array(5);
  const cHi = new Uint32Array(5);
  const tLo = new Uint32Array(5);
  const tHi = new Uint32Array(5);

  for (let round = 0; round < 24; round++) {
    // Theta
    for (let x = 0; x < 5; x++) {
      const i = x * 2;
      cLo[x] = s[i] ^ s[i + 10] ^ s[i + 20] ^ s[i + 30] ^ s[i + 40];
      cHi[x] = s[i + 1] ^ s[i + 11] ^ s[i + 21] ^ s[i + 31] ^ s[i + 41];
    }
    for (let x = 0; x < 5; x++) {
      const x4 = (x + 4) % 5;
      const x1 = (x + 1) % 5;
      const c1Lo = cLo[x1];
      const c1Hi = cHi[x1];
      const dLo = (cLo[x4] ^ ((c1Lo << 1) | (c1Hi >>> 31))) >>> 0;
      const dHi = (cHi[x4] ^ ((c1Hi << 1) | (c1Lo >>> 31))) >>> 0;
      for (let y = 0; y < 50; y += 10) {
        const idx = y + x * 2;
        s[idx] = (s[idx] ^ dLo) >>> 0;
        s[idx + 1] = (s[idx + 1] ^ dHi) >>> 0;
      }
    }

    // Rho & Pi
    let curLo = s[2];
    let curHi = s[3];
    for (let t = 0; t < 24; t++) {
      const r = KECCAK_ROTC[t];
      const pi = KECCAK_PILN[t] * 2;
      const nextLo = s[pi];
      const nextHi = s[pi + 1];
      if (r < 32) {
        s[pi] = ((curLo << r) | (curHi >>> (32 - r))) >>> 0;
        s[pi + 1] = ((curHi << r) | (curLo >>> (32 - r))) >>> 0;
      } else if (r === 32) {
        s[pi] = curHi;
        s[pi + 1] = curLo;
      } else {
        const s32 = r - 32;
        s[pi] = ((curHi << s32) | (curLo >>> (32 - s32))) >>> 0;
        s[pi + 1] = ((curLo << s32) | (curHi >>> (32 - s32))) >>> 0;
      }
      curLo = nextLo;
      curHi = nextHi;
    }

    // Chi
    for (let row = 0; row < 50; row += 10) {
      for (let x = 0; x < 5; x++) {
        tLo[x] = s[row + x * 2];
        tHi[x] = s[row + x * 2 + 1];
      }
      for (let x = 0; x < 5; x++) {
        const x1 = (x + 1) % 5;
        const x2 = (x + 2) % 5;
        s[row + x * 2] = (tLo[x] ^ ((~tLo[x1]) & tLo[x2])) >>> 0;
        s[row + x * 2 + 1] = (tHi[x] ^ ((~tHi[x1]) & tHi[x2])) >>> 0;
      }
    }

    // Iota
    s[0] = (s[0] ^ KECCAK_RC_LO[round]) >>> 0;
    s[1] = (s[1] ^ KECCAK_RC_HI[round]) >>> 0;
  }
}

function xorRateBlock(state, block, offset) {
  for (let i = 0; i < 34; i++) {
    const b = offset + i * 4;
    const word = (
      block[b] |
      (block[b + 1] << 8) |
      (block[b + 2] << 16) |
      (block[b + 3] << 24)
    ) >>> 0;
    state[i] = (state[i] ^ word) >>> 0;
  }
}

/**
 * Compute Ethereum Keccak-256 (0x01 pad) over raw bytes (`Uint8Array`, `ArrayBufferView`, or `ArrayBuffer`).
 */
function keccak256Bytes(input) {
  const data = asUint8Array(input);
  const state = new Uint32Array(50);
  const rate = 136;
  let offset = 0;
  while (offset + rate <= data.length) {
    xorRateBlock(state, data, offset);
    keccakF1600(state);
    offset += rate;
  }

  const last = new Uint8Array(rate);
  const rem = data.length - offset;
  if (rem > 0) {
    last.set(data.subarray(offset), 0);
  }
  last[rem] ^= 0x01;
  last[rate - 1] ^= 0x80;
  xorRateBlock(state, last, 0);
  keccakF1600(state);

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const w = state[i];
    const o = i * 4;
    out[o] = w & 0xff;
    out[o + 1] = (w >>> 8) & 0xff;
    out[o + 2] = (w >>> 16) & 0xff;
    out[o + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

/**
 * Compute `0x`-prefixed lowercase 64-hex Keccak-256 over raw bytes.
 */
function keccak256Hex(input) {
  return `0x${bytesToHex(keccak256Bytes(input))}`;
}

// ─── 2. Strict Canonical RLP (Ethereum Yellow Paper Appendix B) ─────────

/**
 * Convert a non-negative `bigint` or safe integer `number` to minimal big-endian bytes (`0n -> Uint8Array(0)`).
 */
function uintToMinimalBytes(value) {
  let n;
  if (typeof value === 'bigint') {
    if (value < 0n) throw new RangeError('RLP integer must be non-negative');
    n = value;
  } else if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError('RLP number must be a non-negative safe integer');
    }
    n = BigInt(value);
  } else {
    throw new TypeError('Expected non-negative bigint or safe integer');
  }
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  return hexToBytes(hex);
}

/**
 * Convert big-endian bytes to `bigint`. When `strictMinimal: true`, rejects leading `0x00` bytes.
 */
function bytesToBigInt(bytes, { strictMinimal = false } = {}) {
  const u8 = asUint8Array(bytes);
  if (u8.length === 0) return 0n;
  if (strictMinimal && u8[0] === 0) {
    throw new Error('Non-canonical RLP scalar: leading zero byte');
  }
  return BigInt(`0x${bytesToHex(u8)}`);
}

function encodeLengthPrefix(length, shortOffset, longOffset) {
  if (length <= 55) {
    return new Uint8Array([shortOffset + length]);
  }
  const lenBytes = uintToMinimalBytes(length);
  const out = new Uint8Array(1 + lenBytes.length);
  out[0] = longOffset + lenBytes.length;
  out.set(lenBytes, 1);
  return out;
}

/**
 * Canonical Ethereum RLP encoder.
 * Accepts `Uint8Array` / `ArrayBufferView`, non-negative `bigint` / safe `number`, or nested `Array`.
 */
function rlpEncode(item) {
  if (Array.isArray(item)) {
    const encodedChildren = item.map((child) => rlpEncode(child));
    const payload = concatBytes(encodedChildren);
    const prefix = encodeLengthPrefix(payload.length, 0xc0, 0xf7);
    return concatBytes([prefix, payload]);
  }
  let bytes;
  if (isByteArray(item) || item instanceof ArrayBuffer) {
    bytes = asUint8Array(item);
  } else if (typeof item === 'bigint' || typeof item === 'number') {
    bytes = uintToMinimalBytes(item);
  } else {
    throw new TypeError('RLP item must be Uint8Array, non-negative bigint/number, or Array');
  }

  if (bytes.length === 1 && bytes[0] < 0x80) {
    return new Uint8Array([bytes[0]]);
  }
  const prefix = encodeLengthPrefix(bytes.length, 0x80, 0xb7);
  return concatBytes([prefix, bytes]);
}

function decodeCanonicalLength(data, offset, lenOfLen) {
  if (offset + lenOfLen > data.length) {
    throw new Error('Truncated RLP length prefix');
  }
  if (data[offset] === 0) {
    throw new Error('Non-canonical RLP: leading zero byte in length prefix');
  }
  let len = 0;
  for (let i = 0; i < lenOfLen; i++) {
    len = len * 256 + data[offset + i];
    if (!Number.isSafeInteger(len)) {
      throw new Error('RLP length exceeds safe integer bounds');
    }
  }
  if (len <= 55) {
    throw new Error('Non-canonical RLP: length <= 55 must use short prefix');
  }
  return len;
}

function rlpDecodeItem(data, offset, depth) {
  if (depth > MAX_RLP_DEPTH) {
    throw new Error(`RLP nesting exceeds maximum depth (${MAX_RLP_DEPTH})`);
  }
  if (offset >= data.length) {
    throw new Error('Unexpected end of RLP input');
  }
  const prefix = data[offset];

  if (prefix < 0x80) {
    return { value: data.slice(offset, offset + 1), nextOffset: offset + 1 };
  }

  if (prefix <= 0xb7) {
    const len = prefix - 0x80;
    const start = offset + 1;
    const end = start + len;
    if (end > data.length) {
      throw new Error('Truncated RLP short byte string');
    }
    if (len === 1 && data[start] < 0x80) {
      throw new Error('Non-canonical RLP: single byte < 0x80 must not use 0x81 prefix');
    }
    return { value: data.slice(start, end), nextOffset: end };
  }

  if (prefix <= 0xbf) {
    const lenOfLen = prefix - 0xb7;
    const len = decodeCanonicalLength(data, offset + 1, lenOfLen);
    const start = offset + 1 + lenOfLen;
    const end = start + len;
    if (end > data.length) {
      throw new Error('Truncated RLP long byte string');
    }
    return { value: data.slice(start, end), nextOffset: end };
  }

  if (prefix <= 0xf7) {
    const len = prefix - 0xc0;
    const start = offset + 1;
    const end = start + len;
    if (end > data.length) {
      throw new Error('Truncated RLP short list');
    }
    const items = [];
    let cur = start;
    while (cur < end) {
      const child = rlpDecodeItem(data, cur, depth + 1);
      items.push(child.value);
      cur = child.nextOffset;
    }
    if (cur !== end) {
      throw new Error('Malformed RLP list boundary');
    }
    return { value: items, nextOffset: end };
  }

  const lenOfLen = prefix - 0xf7;
  const len = decodeCanonicalLength(data, offset + 1, lenOfLen);
  const start = offset + 1 + lenOfLen;
  const end = start + len;
  if (end > data.length) {
    throw new Error('Truncated RLP long list');
  }
  const items = [];
  let cur = start;
  while (cur < end) {
    const child = rlpDecodeItem(data, cur, depth + 1);
    items.push(child.value);
    cur = child.nextOffset;
  }
  if (cur !== end) {
    throw new Error('Malformed RLP long list boundary');
  }
  return { value: items, nextOffset: end };
}

/**
 * Strict canonical Ethereum RLP decoder (Yellow Paper Appendix B).
 * Rejects trailing bytes, non-canonical prefixes, leading zero lengths, and deep nesting.
 */
function rlpDecode(input) {
  const data = typeof input === 'string' ? hexToBytes(input) : asUint8Array(input);
  if (data.length === 0) {
    throw new Error('Cannot RLP-decode empty byte sequence');
  }
  const { value, nextOffset } = rlpDecodeItem(data, 0, 0);
  if (nextOffset !== data.length) {
    throw new Error(`Trailing ${data.length - nextOffset} byte(s) after RLP payload`);
  }
  return value;
}

// ─── 3. Network, Address & Solidity Slot Helpers ────────────────────────

function normalizeEvmNetworkId(rawNet) {
  if (typeof rawNet !== 'string' || !rawNet.trim()) return null;
  const trimmed = rawNet.trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'ethereum' || lower === 'mainnet' || lower === 'eth') return 'eip155:1';
  if (lower === 'sepolia' || lower === 'ethereum-sepolia') return 'eip155:11155111';
  if (lower === 'base' || lower === 'base-mainnet') return 'eip155:8453';
  if (lower === 'base-sepolia') return 'eip155:84532';
  if (lower === 'arbitrum' || lower === 'arbitrum-one') return 'eip155:42161';
  if (lower === 'arbitrum-sepolia') return 'eip155:421614';
  if (lower === 'optimism' || lower === 'op-mainnet') return 'eip155:10';
  if (lower === 'polygon' || lower === 'polygon-pos') return 'eip155:137';
  if (lower === 'arc' || lower === 'arc-mainnet') return 'eip155:5042';
  if (lower === 'arc-testnet') return 'eip155:5042002';
  return lower.startsWith('eip155:') ? lower : trimmed;
}

function asBytesFlexible(input, label) {
  if (isByteArray(input) || input instanceof ArrayBuffer) {
    return asUint8Array(input);
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed.startsWith('0x') && !trimmed.startsWith('0X') && !/^[0-9a-fA-F]*$/.test(trimmed)) {
      throw new TypeError(`${label}: expected hex string or Uint8Array`);
    }
    return hexToBytes(trimmed);
  }
  throw new TypeError(`${label}: expected hex string or Uint8Array`);
}

function asFixedBytes(input, expectedLen, label) {
  const b = asBytesFlexible(input, label);
  if (b.length !== expectedLen) {
    throw new TypeError(`${label}: expected ${expectedLen} bytes, got ${b.length}`);
  }
  return b;
}

function toWord32Bytes(value, label) {
  if (typeof value === 'bigint' || typeof value === 'number') {
    const min = uintToMinimalBytes(value);
    if (min.length > 32) {
      throw new RangeError(`${label}: integer exceeds 256 bits`);
    }
    const out = new Uint8Array(32);
    out.set(min, 32 - min.length);
    return out;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (DEC_UINT_RE.test(trimmed)) {
      return toWord32Bytes(BigInt(trimmed), label);
    }
    const clean = trimmed.replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length > 64) {
      throw new TypeError(`${label}: expected <=32-byte hex or uint256`);
    }
    return hexToBytes(clean.padStart(64, '0'));
  }
  if (isByteArray(value) || value instanceof ArrayBuffer) {
    const b = asUint8Array(value);
    if (b.length > 32) {
      throw new RangeError(`${label}: byte array exceeds 32 bytes`);
    }
    const out = new Uint8Array(32);
    out.set(b, 32 - b.length);
    return out;
  }
  throw new TypeError(`${label}: unsupported 32-byte word input`);
}

function parseFlexibleUint256(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n || value >= (1n << 256n)) {
      throw new RangeError(`${label}: uint256 out of range`);
    }
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`${label}: expected non-negative safe integer`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '0x' || trimmed === '0X') return 0n;
    if (HEX_ANY_RE.test(trimmed)) {
      const v = BigInt(trimmed);
      if (v >= (1n << 256n)) throw new RangeError(`${label}: uint256 out of range`);
      return v;
    }
    if (DEC_UINT_RE.test(trimmed)) {
      const v = BigInt(trimmed);
      if (v >= (1n << 256n)) throw new RangeError(`${label}: uint256 out of range`);
      return v;
    }
  }
  if (isByteArray(value) || value instanceof ArrayBuffer) {
    const u8 = asUint8Array(value);
    if (u8.length > 32) throw new RangeError(`${label}: exceeds 32 bytes`);
    return bytesToBigInt(u8);
  }
  throw new TypeError(`${label}: invalid uint256 value`);
}

/**
 * Derive world-state trie key `keccak256(address20)` for a 20-byte EVM address.
 */
function deriveAccountTrieKey(address) {
  return keccak256Bytes(asFixedBytes(address, 20, 'address'));
}

/**
 * Derive contract storage trie key `keccak256(leftPad32(slot))`.
 */
function deriveStorageTrieKey(slot) {
  return keccak256Bytes(toWord32Bytes(slot, 'slot'));
}

/**
 * Compute Solidity single-level mapping storage slot `keccak256(abi.encode(key, baseSlot))`.
 */
function computeMappingSlot(key, baseSlot) {
  const keyWord = toWord32Bytes(key, 'key');
  const slotWord = toWord32Bytes(baseSlot, 'baseSlot');
  return keccak256Hex(concatBytes([keyWord, slotWord]));
}

/**
 * Compute Solidity nested mapping storage slot `mapping(K1 => mapping(K2 => V))` at `baseSlot`:
 * `keccak256(abi.encode(innerKey, keccak256(abi.encode(outerKey, baseSlot))))`.
 */
function computeNestedMappingSlot(outerKey, innerKey, baseSlot) {
  const outerSlot = computeMappingSlot(outerKey, baseSlot);
  return computeMappingSlot(innerKey, outerSlot);
}

/**
 * Compute EIP-3009 `authorizationState(address authorizer, bytes32 nonce)` storage slot
 * given the token contract's `_authorizationStates` mapping `baseSlot`.
 */
function computeEip3009AuthStateSlot(authorizer, nonceBytes32, baseSlot) {
  const addrBytes = asFixedBytes(authorizer, 20, 'authorizer');
  const nonceBytes = asFixedBytes(nonceBytes32, 32, 'nonceBytes32');
  return computeNestedMappingSlot(addrBytes, nonceBytes, baseSlot);
}

// ─── 4. Modified Merkle-Patricia Trie (MPT) Verifier & Builder ──────────

function bytesToNibbles(bytes) {
  const u8 = asUint8Array(bytes);
  const out = new Uint8Array(u8.length * 2);
  for (let i = 0; i < u8.length; i++) {
    out[i * 2] = u8[i] >>> 4;
    out[i * 2 + 1] = u8[i] & 0x0f;
  }
  return out;
}

function encodeCompactNibbles(nibbles, isLeaf) {
  const odd = (nibbles.length & 1) === 1;
  const prefixFlag = (isLeaf ? 2 : 0) + (odd ? 1 : 0);
  if (odd) {
    const out = new Uint8Array(1 + ((nibbles.length - 1) >>> 1));
    out[0] = (prefixFlag << 4) | (nibbles[0] & 0x0f);
    for (let i = 1; i < nibbles.length; i += 2) {
      out[1 + ((i - 1) >>> 1)] = ((nibbles[i] & 0x0f) << 4) | (nibbles[i + 1] & 0x0f);
    }
    return out;
  }
  const out = new Uint8Array(1 + (nibbles.length >>> 1));
  out[0] = prefixFlag << 4;
  for (let i = 0; i < nibbles.length; i += 2) {
    out[1 + (i >>> 1)] = ((nibbles[i] & 0x0f) << 4) | (nibbles[i + 1] & 0x0f);
  }
  return out;
}

function decodeCompactNibbles(hpBytes) {
  if (!(hpBytes instanceof Uint8Array) || hpBytes.length === 0) {
    throw new Error('Compact hex-prefix path must be non-empty bytes');
  }
  const first = hpBytes[0];
  const flag = first >>> 4;
  if (flag > 3) {
    throw new Error(`Invalid compact hex-prefix flag: ${flag}`);
  }
  const odd = (flag & 1) === 1;
  const isLeaf = (flag & 2) !== 0;
  if (!odd && (first & 0x0f) !== 0) {
    throw new Error('Non-canonical compact hex-prefix: non-zero low nibble on even path');
  }
  const nibLen = (hpBytes.length - 1) * 2 + (odd ? 1 : 0);
  const nibbles = new Uint8Array(nibLen);
  let pos = 0;
  if (odd) {
    nibbles[pos++] = first & 0x0f;
  }
  for (let i = 1; i < hpBytes.length; i++) {
    nibbles[pos++] = hpBytes[i] >>> 4;
    nibbles[pos++] = hpBytes[i] & 0x0f;
  }
  return { isLeaf, nibbles };
}

function nibblesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function nibblesStartsWith(full, prefix) {
  if (full.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (full[i] !== prefix[i]) return false;
  }
  return true;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Deterministically verify an Ethereum Modified Merkle-Patricia Trie (MPT) proof.
 * Supports inclusion proofs, authenticated absence/exclusion proofs (`value: null`),
 * empty tries (`EMPTY_TRIE_ROOT_HEX`), and inline `< 32`-byte embedded child nodes.
 * Never throws on untrusted proof input.
 */
function verifyMptProof({ rootHash, key, proof, expectedValue } = {}) {
  const fail = (code, reason, extra = {}) => ({
    ok: false,
    verified: false,
    code,
    reason,
    rootHash: extra.rootHash ?? null,
    keyHex: extra.keyHex ?? null,
    value: null
  });

  let rootBytes;
  let keyBytes;
  try {
    rootBytes = asFixedBytes(rootHash, 32, 'rootHash');
    keyBytes = asBytesFlexible(key, 'key');
  } catch (err) {
    return fail('invalid_input', String((err && err.message) || err));
  }

  const rootHex = `0x${bytesToHex(rootBytes)}`;
  const keyHex = `0x${bytesToHex(keyBytes)}`;

  if (!Array.isArray(proof)) {
    return fail('invalid_proof', 'proof must be an array of RLP-encoded trie nodes.', { rootHex, keyHex, rootHash: rootHex });
  }

  let proofNodes;
  try {
    proofNodes = proof.map((n, idx) => asBytesFlexible(n, `proof[${idx}]`));
  } catch (err) {
    return fail('invalid_proof', String((err && err.message) || err), { rootHash: rootHex, keyHex });
  }

  const checkExpected = (recovered) => {
    if (expectedValue === undefined) {
      return {
        ok: true,
        verified: true,
        code: recovered === null ? 'verified_absent' : 'verified',
        reason: recovered === null
          ? 'Authenticated MPT exclusion proof verified (key absent under root).'
          : 'Authenticated MPT inclusion proof verified.',
        rootHash: rootHex,
        keyHex,
        value: recovered
      };
    }
    if (expectedValue === null) {
      if (recovered !== null) {
        return fail(
          'unexpected_inclusion',
          `Expected key ${keyHex} to be absent, but MPT proof resolved to 0x${bytesToHex(recovered)}.`,
          { rootHash: rootHex, keyHex }
        );
      }
      return {
        ok: true,
        verified: true,
        code: 'verified_absent',
        reason: 'Authenticated MPT exclusion proof verified (key absent under root).',
        rootHash: rootHex,
        keyHex,
        value: null
      };
    }
    let wantBytes;
    try {
      wantBytes = asBytesFlexible(expectedValue, 'expectedValue');
    } catch (err) {
      return fail('invalid_input', String((err && err.message) || err), { rootHash: rootHex, keyHex });
    }
    if (recovered === null) {
      return fail(
        'key_absent',
        `Key ${keyHex} is absent under ${rootHex}, expected value 0x${bytesToHex(wantBytes)}.`,
        { rootHash: rootHex, keyHex }
      );
    }
    if (!bytesEqual(recovered, wantBytes)) {
      return fail(
        'value_mismatch',
        `MPT leaf value mismatch for ${keyHex}: expected 0x${bytesToHex(wantBytes)}, got 0x${bytesToHex(recovered)}.`,
        { rootHash: rootHex, keyHex }
      );
    }
    return {
      ok: true,
      verified: true,
      code: 'verified',
      reason: 'Authenticated MPT inclusion proof and expected value verified.',
      rootHash: rootHex,
      keyHex,
      value: recovered
    };
  };

  // Special case: Empty trie root (keccak256(0x80))
  if (rootHex === EMPTY_TRIE_ROOT_HEX) {
    const validEmptyProof =
      proofNodes.length === 0 ||
      (proofNodes.length === 1 && proofNodes[0].length === 1 && proofNodes[0][0] === 0x80);
    if (!validEmptyProof) {
      return fail(
        'proof_root_mismatch',
        'Non-empty proof nodes supplied for empty trie root.',
        { rootHash: rootHex, keyHex }
      );
    }
    return checkExpected(null);
  }

  if (proofNodes.length === 0) {
    return fail('empty_proof', 'MPT proof array is empty for non-empty rootHash.', {
      rootHash: rootHex,
      keyHex
    });
  }

  const nodeByHash = new Map();
  for (let i = 0; i < proofNodes.length; i++) {
    const raw = proofNodes[i];
    if (raw.length === 0) {
      return fail('invalid_trie_node', `proof[${i}] is empty.`, { rootHash: rootHex, keyHex });
    }
    nodeByHash.set(keccak256Hex(raw), raw);
  }

  const rootNodeRaw = nodeByHash.get(rootHex);
  if (!rootNodeRaw) {
    return fail(
      'proof_root_mismatch',
      `No proof node hashes to claimed rootHash ${rootHex}.`,
      { rootHash: rootHex, keyHex }
    );
  }

  let currentDecoded;
  try {
    currentDecoded = rlpDecode(rootNodeRaw);
  } catch (err) {
    return fail('invalid_rlp', `Failed to RLP-decode root trie node: ${(err && err.message) || err}`, {
      rootHash: rootHex,
      keyHex
    });
  }

  const keyNibbles = bytesToNibbles(keyBytes);
  let nibbleIdx = 0;
  const maxSteps = keyNibbles.length + 2;

  const resolveChildNode = (childEntry) => {
    if (Array.isArray(childEntry)) {
      const reencoded = rlpEncode(childEntry);
      if (reencoded.length >= 32) {
        return {
          ok: false,
          code: 'invalid_inline_node',
          reason: `Inline embedded trie node must be < 32 bytes in RLP (got ${reencoded.length} bytes).`
        };
      }
      return { ok: true, decoded: childEntry };
    }
    if (childEntry instanceof Uint8Array) {
      if (childEntry.length === 0) {
        return { ok: true, absent: true };
      }
      if (childEntry.length !== 32) {
        return {
          ok: false,
          code: 'invalid_child_ref',
          reason: `Hashed trie child reference must be 32 bytes (got ${childEntry.length} bytes).`
        };
      }
      const wantHash = `0x${bytesToHex(childEntry)}`;
      const nextRaw = nodeByHash.get(wantHash);
      if (!nextRaw) {
        return {
          ok: false,
          code: 'incomplete_proof',
          reason: `Missing trie node in proof for child hash ${wantHash}.`
        };
      }
      try {
        return { ok: true, decoded: rlpDecode(nextRaw) };
      } catch (err) {
        return {
          ok: false,
          code: 'invalid_rlp',
          reason: `Failed to RLP-decode child node ${wantHash}: ${(err && err.message) || err}`
        };
      }
    }
    return { ok: false, code: 'invalid_trie_node', reason: 'Malformed trie child entry.' };
  };

  for (let step = 0; step < maxSteps; step++) {
    if (!Array.isArray(currentDecoded)) {
      return fail('invalid_trie_node', 'Decoded trie node must be an RLP list.', {
        rootHash: rootHex,
        keyHex
      });
    }

    if (currentDecoded.length === 17) {
      const branchVal = currentDecoded[16];
      if (!(branchVal instanceof Uint8Array)) {
        return fail('invalid_trie_node', 'Branch node item[16] value must be RLP bytes.', {
          rootHash: rootHex,
          keyHex
        });
      }
      if (nibbleIdx === keyNibbles.length) {
        return checkExpected(branchVal.length === 0 ? null : branchVal);
      }
      const nib = keyNibbles[nibbleIdx++];
      const next = resolveChildNode(currentDecoded[nib]);
      if (!next.ok) {
        return fail(next.code, next.reason, { rootHash: rootHex, keyHex });
      }
      if (next.absent) {
        return checkExpected(null);
      }
      currentDecoded = next.decoded;
      continue;
    }

    if (currentDecoded.length === 2) {
      let hp;
      try {
        hp = decodeCompactNibbles(currentDecoded[0]);
      } catch (err) {
        return fail('invalid_trie_node', String((err && err.message) || err), {
          rootHash: rootHex,
          keyHex
        });
      }

      const remaining = keyNibbles.subarray(nibbleIdx);
      if (hp.isLeaf) {
        const leafVal = currentDecoded[1];
        if (!(leafVal instanceof Uint8Array) || leafVal.length === 0) {
          return fail('invalid_trie_node', 'Leaf node value must be non-empty RLP bytes.', {
            rootHash: rootHex,
            keyHex
          });
        }
        if (nibblesEqual(remaining, hp.nibbles)) {
          return checkExpected(leafVal);
        }
        // Key diverges at leaf -> authenticated absence
        return checkExpected(null);
      }

      // Extension node
      if (hp.nibbles.length === 0) {
        return fail('invalid_trie_node', 'Extension node must have at least 1 shared nibble.', {
          rootHash: rootHex,
          keyHex
        });
      }
      if (!nibblesStartsWith(remaining, hp.nibbles)) {
        // Key diverges inside extension shared prefix -> authenticated absence
        return checkExpected(null);
      }
      nibbleIdx += hp.nibbles.length;
      const next = resolveChildNode(currentDecoded[1]);
      if (!next.ok) {
        return fail(next.code, next.reason, { rootHash: rootHex, keyHex });
      }
      if (next.absent) {
        return fail('invalid_trie_node', 'Extension node child reference cannot be empty.', {
          rootHash: rootHex,
          keyHex
        });
      }
      currentDecoded = next.decoded;
      continue;
    }

    return fail(
      'invalid_trie_node',
      `Invalid trie node list length ${currentDecoded.length} (expected 2 or 17).`,
      { rootHash: rootHex, keyHex }
    );
  }

  return fail('proof_depth_exceeded', 'MPT walk exceeded key nibble length.', {
    rootHash: rootHex,
    keyHex
  });
}

function buildTrieAst(items, depth) {
  if (items.length === 1) {
    return {
      kind: 'leaf',
      nibbles: items[0].nibbles.subarray(depth),
      value: items[0].value
    };
  }

  let lcp = items[0].nibbles.length - depth;
  for (let i = 1; i < items.length; i++) {
    const rem = items[i].nibbles.length - depth;
    if (rem < lcp) lcp = rem;
    for (let j = 0; j < lcp; j++) {
      if (items[i].nibbles[depth + j] !== items[0].nibbles[depth + j]) {
        lcp = j;
        break;
      }
    }
    if (lcp === 0) break;
  }

  if (lcp > 0) {
    return {
      kind: 'ext',
      nibbles: items[0].nibbles.subarray(depth, depth + lcp),
      child: buildTrieAst(items, depth + lcp)
    };
  }

  const buckets = Array.from({ length: 16 }, () => []);
  let branchVal = null;
  for (const it of items) {
    if (it.nibbles.length === depth) {
      branchVal = it.value;
    } else {
      buckets[it.nibbles[depth]].push(it);
    }
  }
  const branches = buckets.map((b) => (b.length > 0 ? buildTrieAst(b, depth + 1) : null));
  return { kind: 'branch', branches, value: branchVal };
}

function annotateTrieSerialization(ast) {
  if (!ast) return null;
  if (ast.kind === 'leaf') {
    ast.rawList = [encodeCompactNibbles(ast.nibbles, true), ast.value];
    ast.rlpBytes = rlpEncode(ast.rawList);
    return ast;
  }
  if (ast.kind === 'ext') {
    annotateTrieSerialization(ast.child);
    const childRef = ast.child.rlpBytes.length < 32
      ? ast.child.rawList
      : keccak256Bytes(ast.child.rlpBytes);
    ast.rawList = [encodeCompactNibbles(ast.nibbles, false), childRef];
    ast.rlpBytes = rlpEncode(ast.rawList);
    return ast;
  }
  const childRefs = ast.branches.map((b) => {
    if (!b) return new Uint8Array(0);
    annotateTrieSerialization(b);
    return b.rlpBytes.length < 32 ? b.rawList : keccak256Bytes(b.rlpBytes);
  });
  ast.rawList = [...childRefs, ast.value || new Uint8Array(0)];
  ast.rlpBytes = rlpEncode(ast.rawList);
  return ast;
}

/**
 * Build a canonical Ethereum Modified Merkle-Patricia Trie from `{ key, value }[]` entries
 * and extract an EIP-1186-compatible `proof` array (`0x...` hex RLP nodes) for `targetKey`.
 * Supports both inclusion proofs and exclusion proofs when `targetKey` is absent.
 */
function buildMptProof(entries, targetKey) {
  if (!Array.isArray(entries)) {
    throw new TypeError('entries must be an Array of { key, value }');
  }
  const targetBytes = asBytesFlexible(targetKey, 'targetKey');
  const keyHex = `0x${bytesToHex(targetBytes)}`;
  const targetNibbles = bytesToNibbles(targetBytes);

  const dedup = new Map();
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (!e || typeof e !== 'object') {
      throw new TypeError(`entries[${i}] must be an object with { key, value }`);
    }
    const kBytes = asBytesFlexible(e.key, `entries[${i}].key`);
    const vBytes = asBytesFlexible(e.value, `entries[${i}].value`);
    const kHex = `0x${bytesToHex(kBytes)}`;
    if (vBytes.length === 0) {
      dedup.delete(kHex);
    } else {
      dedup.set(kHex, { keyBytes: kBytes, nibbles: bytesToNibbles(kBytes), value: vBytes });
    }
  }

  if (dedup.size === 0) {
    return {
      rootHash: EMPTY_TRIE_ROOT_HEX,
      keyHex,
      value: null,
      proof: []
    };
  }

  const rootAst = annotateTrieSerialization(buildTrieAst([...dedup.values()], 0));
  const rootHash = keccak256Hex(rootAst.rlpBytes);
  const proof = [`0x${bytesToHex(rootAst.rlpBytes)}`];

  let cur = rootAst;
  let idx = 0;
  let foundValue = null;

  while (cur) {
    if (cur.kind === 'leaf') {
      if (nibblesEqual(targetNibbles.subarray(idx), cur.nibbles)) {
        foundValue = cur.value;
      }
      break;
    }
    if (cur.kind === 'ext') {
      if (!nibblesStartsWith(targetNibbles.subarray(idx), cur.nibbles)) {
        break;
      }
      idx += cur.nibbles.length;
      const next = cur.child;
      if (next.rlpBytes.length >= 32) {
        proof.push(`0x${bytesToHex(next.rlpBytes)}`);
      }
      cur = next;
      continue;
    }
    if (idx === targetNibbles.length) {
      foundValue = cur.value;
      break;
    }
    const nib = targetNibbles[idx++];
    const next = cur.branches[nib];
    if (!next) break;
    if (next.rlpBytes.length >= 32) {
      proof.push(`0x${bytesToHex(next.rlpBytes)}`);
    }
    cur = next;
  }

  return {
    rootHash,
    keyHex,
    value: foundValue,
    proof
  };
}

// ─── 5. Offline EIP-1186 Account & Storage Verifiers ────────────────────

/**
 * Encode an Ethereum world-state account tuple `RLP([nonce, balance, storageRoot, codeHash])`.
 */
function encodeEvmAccount({
  nonce = 0n,
  balance = 0n,
  storageRoot = EMPTY_TRIE_ROOT_HEX,
  storageHash,
  codeHash = EMPTY_CODE_HASH_HEX
} = {}) {
  const n = parseFlexibleUint256(nonce, 'account.nonce');
  const b = parseFlexibleUint256(balance, 'account.balance');
  const sRoot = asFixedBytes(storageRoot ?? storageHash, 32, 'account.storageRoot');
  const cHash = asFixedBytes(codeHash, 32, 'account.codeHash');
  return rlpEncode([uintToMinimalBytes(n), uintToMinimalBytes(b), sRoot, cHash]);
}

/**
 * Decode an RLP-encoded Ethereum world-state account tuple.
 */
function decodeEvmAccount(rawAccountRlp) {
  const decoded = rlpDecode(rawAccountRlp);
  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('Account RLP must be a 4-item list [nonce, balance, storageRoot, codeHash]');
  }
  const [nonceBytes, balanceBytes, storageRootBytes, codeHashBytes] = decoded;
  if (
    !(nonceBytes instanceof Uint8Array) ||
    !(balanceBytes instanceof Uint8Array) ||
    !(storageRootBytes instanceof Uint8Array) ||
    !(codeHashBytes instanceof Uint8Array)
  ) {
    throw new Error('Account RLP fields must all be byte strings');
  }
  if (storageRootBytes.length !== 32 || codeHashBytes.length !== 32) {
    throw new Error('Account storageRoot and codeHash must each be 32 bytes');
  }
  const nonce = bytesToBigInt(nonceBytes, { strictMinimal: true });
  const balance = bytesToBigInt(balanceBytes, { strictMinimal: true });
  return {
    nonce,
    balance,
    storageRoot: `0x${bytesToHex(storageRootBytes)}`,
    codeHash: `0x${bytesToHex(codeHashBytes)}`
  };
}

/**
 * Verify an EIP-1186 `accountProof` against a block `stateRoot` offline. Never throws.
 */
function verifyAccountProof({
  stateRoot,
  address,
  accountProof,
  expectedAccount
} = {}) {
  let addrBytes;
  try {
    addrBytes = asFixedBytes(address, 20, 'address');
  } catch (err) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_address',
      reason: String((err && err.message) || err),
      address: null,
      stateRoot: null,
      exists: false,
      account: null
    };
  }
  const normalizedAddr = `0x${bytesToHex(addrBytes)}`;
  const trieKey = keccak256Bytes(addrBytes);
  const mpt = verifyMptProof({ rootHash: stateRoot, key: trieKey, proof: accountProof });
  if (!mpt.ok) {
    return {
      ok: false,
      verified: false,
      code: mpt.code,
      reason: mpt.reason,
      address: normalizedAddr,
      stateRoot: mpt.rootHash,
      exists: false,
      account: null
    };
  }

  if (mpt.value === null) {
    if (expectedAccount && typeof expectedAccount === 'object') {
      return {
        ok: false,
        verified: false,
        code: 'account_not_found',
        reason: `Account ${normalizedAddr} does not exist under stateRoot ${mpt.rootHash}.`,
        address: normalizedAddr,
        stateRoot: mpt.rootHash,
        exists: false,
        account: null
      };
    }
    return {
      ok: true,
      verified: true,
      code: 'verified_absent',
      reason: `Authenticated non-existence of account ${normalizedAddr} under ${mpt.rootHash}.`,
      address: normalizedAddr,
      stateRoot: mpt.rootHash,
      exists: false,
      account: null
    };
  }

  if (expectedAccount === null) {
    return {
      ok: false,
      verified: false,
      code: 'unexpected_account_exists',
      reason: `Expected account ${normalizedAddr} to be absent, but account exists in state trie.`,
      address: normalizedAddr,
      stateRoot: mpt.rootHash,
      exists: true,
      account: null
    };
  }

  let account;
  try {
    account = decodeEvmAccount(mpt.value);
  } catch (err) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_account_rlp',
      reason: `Malformed account RLP: ${(err && err.message) || err}`,
      address: normalizedAddr,
      stateRoot: mpt.rootHash,
      exists: false,
      account: null
    };
  }

  if (expectedAccount && typeof expectedAccount === 'object') {
    try {
      if (expectedAccount.nonce !== undefined) {
        const wantNonce = parseFlexibleUint256(expectedAccount.nonce, 'expectedAccount.nonce');
        if (account.nonce !== wantNonce) {
          return {
            ok: false,
            verified: false,
            code: 'account_field_mismatch',
            reason: `Account nonce mismatch: expected ${wantNonce}, got ${account.nonce}.`,
            address: normalizedAddr,
            stateRoot: mpt.rootHash,
            exists: true,
            account
          };
        }
      }
      if (expectedAccount.balance !== undefined) {
        const wantBal = parseFlexibleUint256(expectedAccount.balance, 'expectedAccount.balance');
        if (account.balance !== wantBal) {
          return {
            ok: false,
            verified: false,
            code: 'account_field_mismatch',
            reason: `Account balance mismatch: expected ${wantBal}, got ${account.balance}.`,
            address: normalizedAddr,
            stateRoot: mpt.rootHash,
            exists: true,
            account
          };
        }
      }
      const rawExpectedStorage = expectedAccount.storageRoot ?? expectedAccount.storageHash;
      if (rawExpectedStorage !== undefined) {
        const wantSr = `0x${bytesToHex(asFixedBytes(rawExpectedStorage, 32, 'expectedAccount.storageRoot'))}`;
        if (account.storageRoot !== wantSr) {
          return {
            ok: false,
            verified: false,
            code: 'account_field_mismatch',
            reason: `Account storageRoot mismatch: expected ${wantSr}, got ${account.storageRoot}.`,
            address: normalizedAddr,
            stateRoot: mpt.rootHash,
            exists: true,
            account
          };
        }
      }
      if (expectedAccount.codeHash !== undefined) {
        const wantCh = `0x${bytesToHex(asFixedBytes(expectedAccount.codeHash, 32, 'expectedAccount.codeHash'))}`;
        if (account.codeHash !== wantCh) {
          return {
            ok: false,
            verified: false,
            code: 'account_field_mismatch',
            reason: `Account codeHash mismatch: expected ${wantCh}, got ${account.codeHash}.`,
            address: normalizedAddr,
            stateRoot: mpt.rootHash,
            exists: true,
            account
          };
        }
      }
    } catch (err) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_expected_account',
        reason: String((err && err.message) || err),
        address: normalizedAddr,
        stateRoot: mpt.rootHash,
        exists: true,
        account
      };
    }
  }

  return {
    ok: true,
    verified: true,
    code: 'verified',
    reason: `Account ${normalizedAddr} verified against stateRoot ${mpt.rootHash}.`,
    address: normalizedAddr,
    stateRoot: mpt.rootHash,
    exists: true,
    account
  };
}

/**
 * Verify a contract storage slot proof against `storageRoot` offline.
 * Handles both non-zero slot inclusion proofs and `0x0` slot exclusion proofs. Never throws.
 */
function verifyStorageProof({
  storageRoot,
  key,
  slot,
  proof,
  storageProof,
  expectedValue
} = {}) {
  const slotInput = slot !== undefined ? slot : key;
  const proofInput = proof !== undefined ? proof : storageProof;

  let slotWord;
  try {
    slotWord = toWord32Bytes(slotInput, 'slot');
  } catch (err) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_slot',
      reason: String((err && err.message) || err),
      slotHex: null,
      storageRoot: null,
      value: null,
      valueHex: null,
      valueHex32: null
    };
  }
  const slotHex = `0x${bytesToHex(slotWord)}`;
  const trieKey = keccak256Bytes(slotWord);
  const mpt = verifyMptProof({ rootHash: storageRoot, key: trieKey, proof: proofInput });
  if (!mpt.ok) {
    return {
      ok: false,
      verified: false,
      code: mpt.code,
      reason: mpt.reason,
      slotHex,
      storageRoot: mpt.rootHash,
      value: null,
      valueHex: null,
      valueHex32: null
    };
  }

  let recoveredBigInt = 0n;
  if (mpt.value !== null) {
    let inner;
    try {
      inner = rlpDecode(mpt.value);
    } catch (err) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_storage_rlp',
        reason: `Malformed storage leaf RLP: ${(err && err.message) || err}`,
        slotHex,
        storageRoot: mpt.rootHash,
        value: null,
        valueHex: null,
        valueHex32: null
      };
    }
    if (!(inner instanceof Uint8Array) || inner.length === 0 || inner.length > 32 || inner[0] === 0) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_storage_rlp',
        reason: 'Canonical Ethereum storage leaf RLP must decode to 1..32 minimal non-zero scalar bytes.',
        slotHex,
        storageRoot: mpt.rootHash,
        value: null,
        valueHex: null,
        valueHex32: null
      };
    }
    recoveredBigInt = bytesToBigInt(inner, { strictMinimal: true });
  }

  const valueHex = `0x${recoveredBigInt.toString(16)}`;
  const valueHex32 = `0x${recoveredBigInt.toString(16).padStart(64, '0')}`;

  if (expectedValue !== undefined) {
    let wantBigInt;
    try {
      wantBigInt = parseFlexibleUint256(expectedValue, 'expectedValue');
    } catch (err) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_expected_value',
        reason: String((err && err.message) || err),
        slotHex,
        storageRoot: mpt.rootHash,
        value: recoveredBigInt,
        valueHex,
        valueHex32
      };
    }
    if (recoveredBigInt !== wantBigInt) {
      return {
        ok: false,
        verified: false,
        code: 'storage_value_mismatch',
        reason: `Storage slot ${slotHex} value mismatch: expected 0x${wantBigInt.toString(16)}, got ${valueHex}.`,
        slotHex,
        storageRoot: mpt.rootHash,
        value: recoveredBigInt,
        valueHex,
        valueHex32
      };
    }
  }

  return {
    ok: true,
    verified: true,
    code: mpt.value === null ? 'verified_zero' : 'verified',
    reason: `Storage slot ${slotHex} verified (${valueHex}) against storageRoot ${mpt.rootHash}.`,
    slotHex,
    storageRoot: mpt.rootHash,
    value: recoveredBigInt,
    valueHex,
    valueHex32
  };
}

/**
 * Verify a full EIP-1186 `eth_getProof` JSON response (`proof`) against `stateRoot`,
 * including account fields and every entry in `proof.storageProof` (plus optional `expectedStorage` assertions).
 * Never throws.
 */
function verifyEip1186Proof({ stateRoot, proof, expectedStorage } = {}) {
  if (!proof || typeof proof !== 'object') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_eip1186_proof',
      reason: 'EIP-1186 proof must be an eth_getProof response object.'
    };
  }

  const rawStorageHash = proof.storageHash ?? proof.storageRoot ?? proof.storage_root;
  const rawCodeHash = proof.codeHash ?? proof.code_hash;
  const rawAccountProof = proof.accountProof ?? proof.account_proof;
  const rawStorageProofs = proof.storageProof ?? proof.storage_proof ?? [];

  // EIP-1186 non-existent account: balance=0, nonce=0, codeHash=0x00..00 or EMPTY_CODE_HASH, storageHash=0x00..00 or EMPTY_TRIE_ROOT
  const acctRes = verifyAccountProof({
    stateRoot,
    address: proof.address,
    accountProof: rawAccountProof
  });
  if (!acctRes.ok) {
    return {
      ok: false,
      verified: false,
      code: acctRes.code,
      reason: acctRes.reason,
      address: acctRes.address,
      stateRoot: acctRes.stateRoot
    };
  }

  if (!acctRes.exists) {
    if (Array.isArray(rawStorageProofs) && rawStorageProofs.length > 0) {
      for (let i = 0; i < rawStorageProofs.length; i++) {
        const sp = rawStorageProofs[i];
        let v = 0n;
        try {
          v = parseFlexibleUint256(sp.value ?? 0n, `storageProof[${i}].value`);
        } catch (err) {
          return { ok: false, verified: false, code: 'invalid_storage_value', reason: String(err.message || err) };
        }
        if (v !== 0n) {
          return {
            ok: false,
            verified: false,
            code: 'storage_value_mismatch',
            reason: `Non-existent account ${acctRes.address} cannot hold non-zero storage value in storageProof[${i}].`
          };
        }
      }
    }
    if (expectedStorage && (Array.isArray(expectedStorage) ? expectedStorage.length > 0 : Object.keys(expectedStorage).length > 0)) {
      return {
        ok: false,
        verified: false,
        code: 'account_not_found',
        reason: `Account ${acctRes.address} does not exist at stateRoot ${acctRes.stateRoot}.`
      };
    }
    return {
      ok: true,
      verified: true,
      code: 'verified_absent',
      reason: acctRes.reason,
      address: acctRes.address,
      stateRoot: acctRes.stateRoot,
      exists: false,
      account: null,
      storage: []
    };
  }

  // Account exists -> verify claimed EIP-1186 top-level fields match the MPT-authenticated account tuple
  const checkTopLevel = verifyAccountProof({
    stateRoot,
    address: proof.address,
    accountProof: rawAccountProof,
    expectedAccount: {
      ...(proof.nonce !== undefined ? { nonce: proof.nonce } : {}),
      ...(proof.balance !== undefined ? { balance: proof.balance } : {}),
      ...(rawStorageHash !== undefined ? { storageRoot: rawStorageHash } : {}),
      ...(rawCodeHash !== undefined ? { codeHash: rawCodeHash } : {})
    }
  });
  if (!checkTopLevel.ok) {
    return {
      ok: false,
      verified: false,
      code: checkTopLevel.code,
      reason: checkTopLevel.reason,
      address: acctRes.address,
      stateRoot: acctRes.stateRoot
    };
  }

  if (!Array.isArray(rawStorageProofs)) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_eip1186_proof',
      reason: 'EIP-1186 storageProof must be an array.'
    };
  }

  const verifiedSlots = [];
  const verifiedBySlotHex = new Map();

  for (let i = 0; i < rawStorageProofs.length; i++) {
    const sp = rawStorageProofs[i];
    if (!sp || typeof sp !== 'object') {
      return {
        ok: false,
        verified: false,
        code: 'invalid_eip1186_proof',
        reason: `storageProof[${i}] must be an object.`
      };
    }
    const slotRes = verifyStorageProof({
      storageRoot: acctRes.account.storageRoot,
      key: sp.key !== undefined ? sp.key : sp.slot,
      proof: sp.proof !== undefined ? sp.proof : sp.storage_proof,
      expectedValue: sp.value
    });
    if (!slotRes.ok) {
      return {
        ok: false,
        verified: false,
        code: slotRes.code,
        reason: `storageProof[${i}]: ${slotRes.reason}`,
        address: acctRes.address,
        stateRoot: acctRes.stateRoot
      };
    }
    verifiedSlots.push(slotRes);
    verifiedBySlotHex.set(slotRes.slotHex, slotRes);
  }

  if (expectedStorage !== undefined && expectedStorage !== null) {
    const reqList = Array.isArray(expectedStorage)
      ? expectedStorage
      : Object.entries(expectedStorage).map(([slotKey, value]) => ({ slot: slotKey, value }));

    for (let i = 0; i < reqList.length; i++) {
      const req = reqList[i];
      let normSlotHex;
      let wantVal;
      try {
        normSlotHex = `0x${bytesToHex(toWord32Bytes(req.slot ?? req.key, `expectedStorage[${i}].slot`))}`;
        wantVal = parseFlexibleUint256(req.value, `expectedStorage[${i}].value`);
      } catch (err) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_expected_storage',
          reason: String((err && err.message) || err)
        };
      }
      const got = verifiedBySlotHex.get(normSlotHex);
      if (!got) {
        return {
          ok: false,
          verified: false,
          code: 'missing_expected_slot',
          reason: `Required storage slot ${normSlotHex} was omitted from EIP-1186 storageProof.`
        };
      }
      if (got.value !== wantVal) {
        return {
          ok: false,
          verified: false,
          code: 'storage_value_mismatch',
          reason: `Required storage slot ${normSlotHex} has verified value ${got.valueHex}, expected 0x${wantVal.toString(16)}.`
        };
      }
    }
  }

  return {
    ok: true,
    verified: true,
    code: 'verified',
    reason: `Verified EIP-1186 account ${acctRes.address} and ${verifiedSlots.length} storage slot(s) against stateRoot ${acctRes.stateRoot}.`,
    address: acctRes.address,
    stateRoot: acctRes.stateRoot,
    exists: true,
    account: acctRes.account,
    storage: verifiedSlots
  };
}

// ─── 6. Offline EVM Receipt-Trie & Canonical USDC Settlement Verifiers ──

function parseReceiptType(rawType) {
  if (rawType === undefined || rawType === null || rawType === '' || rawType === '0x0' || rawType === '0x00' || rawType === 0) {
    return 0;
  }
  const n = Number(parseFlexibleUint256(rawType, 'receipt.type'));
  if (!Number.isInteger(n) || n < 0 || n > 0x7f) {
    throw new RangeError(`Invalid EIP-2718 receipt type: ${rawType}`);
  }
  return n;
}

/**
 * Encode a JSON-RPC `eth_getTransactionReceipt` object into its exact consensus receipt-trie leaf bytes.
 * Supports Legacy (`0x0`), EIP-2930 (`0x1`), EIP-1559 (`0x2`), EIP-4844 (`0x3`), EIP-7702 (`0x4`),
 * Arbitrum typed receipts, and OP-Stack (`0x7e`) Deposit receipts (`depositNonce`, `depositReceiptVersion`).
 */
function encodeEvmReceipt(rpcReceipt) {
  if (!rpcReceipt || typeof rpcReceipt !== 'object') {
    throw new TypeError('rpcReceipt must be an eth_getTransactionReceipt object');
  }
  const txType = parseReceiptType(rpcReceipt.type);

  let statusOrRoot;
  if (rpcReceipt.root && rpcReceipt.status === undefined) {
    statusOrRoot = asFixedBytes(rpcReceipt.root, 32, 'rpcReceipt.root');
  } else {
    const st = parseFlexibleUint256(rpcReceipt.status ?? 0, 'rpcReceipt.status');
    if (st !== 0n && st !== 1n) {
      throw new RangeError(`Invalid receipt status: ${rpcReceipt.status}`);
    }
    statusOrRoot = st === 1n ? new Uint8Array([1]) : new Uint8Array(0);
  }

  const cumulativeGasUsed = uintToMinimalBytes(
    parseFlexibleUint256(rpcReceipt.cumulativeGasUsed, 'rpcReceipt.cumulativeGasUsed')
  );
  const logsBloom = asFixedBytes(rpcReceipt.logsBloom, 256, 'rpcReceipt.logsBloom');
  if (!Array.isArray(rpcReceipt.logs)) {
    throw new TypeError('rpcReceipt.logs must be an array');
  }
  const encodedLogs = rpcReceipt.logs.map((log, idx) => {
    const addr = asFixedBytes(log.address, 20, `logs[${idx}].address`);
    if (!Array.isArray(log.topics)) {
      throw new TypeError(`logs[${idx}].topics must be an array`);
    }
    const topics = log.topics.map((t, tIdx) => asFixedBytes(t, 32, `logs[${idx}].topics[${tIdx}]`));
    const data = !log.data || log.data === '0x' || log.data === '0X'
      ? new Uint8Array(0)
      : asBytesFlexible(log.data, `logs[${idx}].data`);
    return [addr, topics, data];
  });

  const tuple = [statusOrRoot, cumulativeGasUsed, logsBloom, encodedLogs];

  // OP-Stack (Base / Optimism) 0x7e Deposit Receipt Canyon/Regolith extension
  if (txType === 0x7e && rpcReceipt.depositNonce !== undefined && rpcReceipt.depositNonce !== null) {
    tuple.push(uintToMinimalBytes(parseFlexibleUint256(rpcReceipt.depositNonce, 'depositNonce')));
    if (rpcReceipt.depositReceiptVersion !== undefined && rpcReceipt.depositReceiptVersion !== null) {
      tuple.push(
        uintToMinimalBytes(parseFlexibleUint256(rpcReceipt.depositReceiptVersion, 'depositReceiptVersion'))
      );
    }
  }

  const rlpPayload = rlpEncode(tuple);
  if (txType === 0) return rlpPayload;
  return concatBytes([new Uint8Array([txType]), rlpPayload]);
}

/**
 * Decode consensus receipt-trie leaf bytes into `{ txType, status, cumulativeGasUsed, logsBloom, logs, ... }`.
 */
function decodeEvmReceipt(rawReceiptBytes) {
  const raw = asBytesFlexible(rawReceiptBytes, 'rawReceiptBytes');
  if (raw.length === 0) {
    throw new Error('Empty receipt bytes');
  }
  let txType = 0;
  let rlpSlice = raw;
  if (raw[0] < 0x80) {
    if (raw[0] === 0 || raw.length < 2 || raw[1] < 0xc0) {
      throw new Error(`Invalid EIP-2718 receipt envelope (type=0x${raw[0].toString(16)})`);
    }
    txType = raw[0];
    rlpSlice = raw.subarray(1);
  } else if (raw[0] < 0xc0) {
    throw new Error('Legacy receipt payload must be an RLP list (prefix >= 0xc0)');
  }

  const list = rlpDecode(rlpSlice);
  const maxItems = txType === 0x7e ? 6 : 4;
  if (!Array.isArray(list) || list.length < 4 || list.length > maxItems) {
    throw new Error(`Invalid receipt RLP tuple length ${Array.isArray(list) ? list.length : 'non-list'} for txType=0x${txType.toString(16)}`);
  }

  const [statusBytes, gasBytes, bloomBytes, rawLogs] = list;
  if (
    !(statusBytes instanceof Uint8Array) ||
    !(gasBytes instanceof Uint8Array) ||
    !(bloomBytes instanceof Uint8Array) ||
    !Array.isArray(rawLogs)
  ) {
    throw new Error('Invalid receipt RLP field types');
  }
  if (bloomBytes.length !== 256) {
    throw new Error(`Invalid logsBloom length ${bloomBytes.length} (expected 256)`);
  }

  let status = null;
  let postStateRoot = null;
  if (statusBytes.length === 0) {
    status = 0;
  } else if (statusBytes.length === 1 && statusBytes[0] === 1) {
    status = 1;
  } else if (statusBytes.length === 32) {
    postStateRoot = `0x${bytesToHex(statusBytes)}`;
  } else {
    throw new Error(`Invalid receipt status bytes (length=${statusBytes.length})`);
  }

  const cumulativeGasUsed = bytesToBigInt(gasBytes, { strictMinimal: true });
  const logs = rawLogs.map((entry, idx) => {
    if (!Array.isArray(entry) || entry.length !== 3) {
      throw new Error(`Malformed log[${idx}] RLP tuple`);
    }
    const [addrBytes, topicsArr, dataBytes] = entry;
    if (!(addrBytes instanceof Uint8Array) || addrBytes.length !== 20) {
      throw new Error(`Malformed log[${idx}] address`);
    }
    if (!Array.isArray(topicsArr)) {
      throw new Error(`Malformed log[${idx}] topics`);
    }
    const topics = topicsArr.map((t, tIdx) => {
      if (!(t instanceof Uint8Array) || t.length !== 32) {
        throw new Error(`Malformed log[${idx}].topics[${tIdx}]`);
      }
      return `0x${bytesToHex(t)}`;
    });
    if (!(dataBytes instanceof Uint8Array)) {
      throw new Error(`Malformed log[${idx}] data`);
    }
    return {
      logIndex: idx,
      address: `0x${bytesToHex(addrBytes)}`,
      topics,
      data: `0x${bytesToHex(dataBytes)}`
    };
  });

  const out = {
    txType,
    status,
    ...(postStateRoot ? { postStateRoot } : {}),
    cumulativeGasUsed,
    logsBloom: `0x${bytesToHex(bloomBytes)}`,
    logs
  };

  if (txType === 0x7e && list.length >= 5) {
    if (!(list[4] instanceof Uint8Array)) throw new Error('Malformed OP-Stack depositNonce');
    out.depositNonce = bytesToBigInt(list[4], { strictMinimal: true });
    if (list.length === 6) {
      if (!(list[5] instanceof Uint8Array)) throw new Error('Malformed OP-Stack depositReceiptVersion');
      out.depositReceiptVersion = bytesToBigInt(list[5], { strictMinimal: true });
    }
  }

  return out;
}

/**
 * Build a compact `evm_receipt_trie_v0` settlement proof for a target transaction (`transactionHash` or `transactionIndex`)
 * from a full `eth_getBlockReceipts` array.
 */
function buildReceiptTrieProof(blockReceipts, targetTxHashOrIndex, extra = {}) {
  if (!Array.isArray(blockReceipts) || blockReceipts.length === 0) {
    throw new TypeError('blockReceipts must be a non-empty array from eth_getBlockReceipts');
  }

  let targetReceipt = null;
  let targetIndex = null;
  const entries = [];

  const wantHash =
    typeof targetTxHashOrIndex === 'string' && HEX32_RE.test(targetTxHashOrIndex.trim())
      ? targetTxHashOrIndex.trim().toLowerCase()
      : null;
  const wantIdx =
    wantHash === null ? Number(parseFlexibleUint256(targetTxHashOrIndex, 'targetTxIndex')) : null;

  for (let i = 0; i < blockReceipts.length; i++) {
    const r = blockReceipts[i];
    const txIdx = Number(
      parseFlexibleUint256(
        r.transactionIndex !== undefined ? r.transactionIndex : i,
        `blockReceipts[${i}].transactionIndex`
      )
    );
    const keyBytes = rlpEncode(BigInt(txIdx));
    const valBytes = encodeEvmReceipt(r);
    entries.push({ key: keyBytes, value: valBytes });

    if (wantHash !== null) {
      if (String(r.transactionHash || '').toLowerCase() === wantHash) {
        targetReceipt = r;
        targetIndex = txIdx;
      }
    } else if (txIdx === wantIdx) {
      targetReceipt = r;
      targetIndex = txIdx;
    }
  }

  if (targetIndex === null || !targetReceipt) {
    throw new Error(`Target transaction (${targetTxHashOrIndex}) not found in blockReceipts`);
  }

  const targetKey = rlpEncode(BigInt(targetIndex));
  const built = buildMptProof(entries, targetKey);

  const rawBlockNum = extra.blockNumber ?? targetReceipt.blockNumber;
  const blockNumber =
    rawBlockNum !== undefined && rawBlockNum !== null
      ? parseFlexibleUint256(rawBlockNum, 'blockNumber').toString()
      : null;
  const blockHash = extra.blockHash || targetReceipt.blockHash || null;
  const network = extra.network ? normalizeEvmNetworkId(extra.network) : undefined;

  return {
    type: 'evm_receipt_trie_v0',
    ...(network ? { network } : {}),
    ...(blockNumber !== null ? { blockNumber } : {}),
    ...(blockHash ? { blockHash: String(blockHash).toLowerCase() } : {}),
    receiptsRoot: built.rootHash,
    transactionIndex: targetIndex,
    ...(targetReceipt.transactionHash
      ? { transactionHash: String(targetReceipt.transactionHash).toLowerCase() }
      : {}),
    receiptProof: built.proof
  };
}

/**
 * Verify an EVM transaction receipt inclusion proof at `transactionIndex` against `receiptsRoot`.
 * Never throws.
 */
function verifyEvmReceiptProof({
  receiptsRoot,
  transactionIndex,
  receiptProof
} = {}) {
  let txIdxBig;
  try {
    txIdxBig = parseFlexibleUint256(transactionIndex, 'transactionIndex');
  } catch (err) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_transaction_index',
      reason: String((err && err.message) || err)
    };
  }
  const keyBytes = rlpEncode(txIdxBig);
  const mpt = verifyMptProof({ rootHash: receiptsRoot, key: keyBytes, proof: receiptProof });
  if (!mpt.ok) {
    return {
      ok: false,
      verified: false,
      code: mpt.code,
      reason: mpt.reason,
      receiptsRoot: mpt.rootHash,
      transactionIndex: Number(txIdxBig)
    };
  }
  if (mpt.value === null) {
    return {
      ok: false,
      verified: false,
      code: 'receipt_not_found',
      reason: `No transaction receipt exists at transactionIndex=${txIdxBig} under receiptsRoot ${mpt.rootHash}.`,
      receiptsRoot: mpt.rootHash,
      transactionIndex: Number(txIdxBig)
    };
  }

  let decoded;
  try {
    decoded = decodeEvmReceipt(mpt.value);
  } catch (err) {
    return {
      ok: false,
      verified: false,
      code: 'invalid_receipt_rlp',
      reason: `Failed to decode EVM receipt RLP: ${(err && err.message) || err}`,
      receiptsRoot: mpt.rootHash,
      transactionIndex: Number(txIdxBig)
    };
  }

  return {
    ok: true,
    verified: true,
    code: 'verified',
    reason: `Verified EVM receipt (type=0x${decoded.txType.toString(16)}, status=${decoded.status}) at index ${txIdxBig} against ${mpt.rootHash}.`,
    receiptsRoot: mpt.rootHash,
    transactionIndex: Number(txIdxBig),
    receipt: decoded
  };
}

function normalizeTopicAddress(topicHex) {
  if (typeof topicHex !== 'string' || !HEX32_RE.test(topicHex)) return null;
  // Canonical ABI-encoded address topic has 12 zero-padding bytes (24 hex '0' chars)
  if (topicHex.slice(2, 26) !== '000000000000000000000000') return null;
  return `0x${topicHex.slice(26).toLowerCase()}`;
}

function matchTrustedReceiptsRoot(trustedRoots, { network, blockNumber, blockHash, receiptsRoot }) {
  if (!trustedRoots) return { matched: false };

  const wantRoot = receiptsRoot.toLowerCase();
  const checkEntry = (entry) => {
    if (!entry) return false;
    if (typeof entry === 'string') {
      return entry.trim().toLowerCase() === wantRoot;
    }
    if (typeof entry === 'object') {
      const candRoot = String(entry.receiptsRoot || entry.receipts_root || '').trim().toLowerCase();
      if (!candRoot || candRoot !== wantRoot) return false;
      if (entry.network && normalizeEvmNetworkId(entry.network) !== network) return false;
      if (entry.blockNumber !== undefined && entry.blockNumber !== null && blockNumber !== null) {
        try {
          if (parseFlexibleUint256(entry.blockNumber, 'blockNumber').toString() !== blockNumber) return false;
        } catch {
          return false;
        }
      }
      if (entry.blockHash && blockHash && String(entry.blockHash).toLowerCase() !== blockHash.toLowerCase()) {
        return false;
      }
      return true;
    }
    return false;
  };

  if (Array.isArray(trustedRoots) || trustedRoots instanceof Set) {
    for (const item of trustedRoots) {
      if (checkEntry(item)) return { matched: true, source: 'trustedRoots' };
    }
    return { matched: false };
  }

  if (typeof trustedRoots === 'object') {
    const keysToTry = [];
    if (blockNumber !== null) {
      keysToTry.push(`${network}:${blockNumber}`, blockNumber);
    }
    if (blockHash) {
      keysToTry.push(`${network}:${blockHash.toLowerCase()}`, blockHash.toLowerCase());
    }
    keysToTry.push(network);
    for (const k of keysToTry) {
      if (Object.prototype.hasOwnProperty.call(trustedRoots, k) && checkEntry(trustedRoots[k])) {
        return { matched: true, source: 'trustedRoots' };
      }
    }
    if (checkEntry(trustedRoots)) return { matched: true, source: 'trustedRoots' };
  }

  return { matched: false };
}

/**
 * Synchronous core of offline x402 / ERC-20 USDC settlement proof verification.
 * Verifies:
 *   1. MPT inclusion of the receipt at `transactionIndex` under `receiptsRoot`
 *   2. `receipt.status === 1` (not reverted!)
 *   3. Canonical USDC (or explicit ERC-20 contract) `Transfer(from, to, value)` log
 *      matching `expectedPayTo`, `expectedPayer` (if supplied), and `value >= minAmountAtomic`
 *   4. Trusted `receiptsRoot` anchor (from `trustedRoots` or pre-verified `verifiedRootAttestation`),
 *      unless `allowUnanchoredRoot === true`.
 */
function verifyUsdcSettlementProofSync({
  settlementProof,
  network,
  expectedPayTo,
  minAmountAtomic = 0n,
  expectedPayer,
  expectedAsset = 'USDC',
  expectedTransactionHash,
  trustedRoots = null,
  verifiedRootAttestation = null,
  allowUnanchoredRoot = false
} = {}) {
  const fail = (code, reason, extra = {}) => ({
    ok: false,
    verified: false,
    code,
    reason,
    rootAnchored: Boolean(extra.rootAnchored),
    ...extra
  });

  if (!settlementProof || typeof settlementProof !== 'object') {
    return fail('invalid_settlement_proof', 'settlementProof must be an object.');
  }

  const effNet = normalizeEvmNetworkId(network || settlementProof.network);
  if (!effNet) {
    return fail('missing_network', 'network (e.g. "eip155:8453") is required to verify USDC settlement proof.');
  }

  let tokenAddress;
  const assetStr = String(expectedAsset || 'USDC').trim();
  if (assetStr.toUpperCase() === 'USDC') {
    tokenAddress = CANONICAL_USDC_BY_NETWORK[effNet];
    if (!tokenAddress) {
      return fail(
        'unsupported_network',
        `No canonical USDC contract registered for network "${effNet}".`
      );
    }
  } else if (EVM_ADDRESS_RE.test(assetStr)) {
    const canonicalUsdc = CANONICAL_USDC_BY_NETWORK[effNet];
    tokenAddress = assetStr;
    // Allow explicit canonical USDC address or explicit custom ERC-20 token contract
    if (canonicalUsdc && canonicalUsdc.toLowerCase() === assetStr.toLowerCase()) {
      tokenAddress = canonicalUsdc;
    }
  } else {
    return fail('unsupported_asset', `Unsupported asset "${assetStr}" for EVM receipt-trie verification.`);
  }
  const wantTokenLower = tokenAddress.toLowerCase();

  let requiredAmount;
  try {
    requiredAmount = parseFlexibleUint256(minAmountAtomic, 'minAmountAtomic');
  } catch (err) {
    return fail('invalid_amount', String((err && err.message) || err));
  }

  let wantToLower = null;
  if (expectedPayTo !== undefined && expectedPayTo !== null && String(expectedPayTo).trim() !== '') {
    const normTo = normalizePayToId(String(expectedPayTo));
    if (!EVM_ADDRESS_RE.test(normTo)) {
      return fail('invalid_pay_to', `expectedPayTo "${expectedPayTo}" is not a valid 20-byte EVM address.`);
    }
    wantToLower = normTo.toLowerCase();
  }

  let wantPayerLower = null;
  if (expectedPayer !== undefined && expectedPayer !== null && String(expectedPayer).trim() !== '') {
    const normPayer = normalizePayToId(String(expectedPayer));
    if (!EVM_ADDRESS_RE.test(normPayer)) {
      return fail('invalid_payer', `expectedPayer "${expectedPayer}" is not a valid 20-byte EVM address.`);
    }
    wantPayerLower = normPayer.toLowerCase();
  }

  if (expectedTransactionHash && settlementProof.transactionHash) {
    if (String(expectedTransactionHash).toLowerCase() !== String(settlementProof.transactionHash).toLowerCase()) {
      return fail(
        'transaction_hash_mismatch',
        `settlementProof.transactionHash (${settlementProof.transactionHash}) != receipt transactionHash (${expectedTransactionHash}).`
      );
    }
  }

  const rawProofNodes = settlementProof.receiptProof ?? settlementProof.proof;
  const txIndexInput = settlementProof.transactionIndex ?? settlementProof.txIndex;
  const evmRes = verifyEvmReceiptProof({
    receiptsRoot: settlementProof.receiptsRoot,
    transactionIndex: txIndexInput,
    receiptProof: rawProofNodes
  });
  if (!evmRes.ok) {
    return fail(evmRes.code, evmRes.reason, { receiptsRoot: evmRes.receiptsRoot });
  }

  if (evmRes.receipt.status !== 1) {
    return fail(
      'tx_reverted',
      `Transaction at index ${evmRes.transactionIndex} did not succeed (status=${evmRes.receipt.status}).`,
      { receiptsRoot: evmRes.receiptsRoot, transactionIndex: evmRes.transactionIndex }
    );
  }

  let blockNumber = null;
  if (settlementProof.blockNumber !== undefined && settlementProof.blockNumber !== null) {
    try {
      blockNumber = parseFlexibleUint256(settlementProof.blockNumber, 'settlementProof.blockNumber').toString();
    } catch (err) {
      return fail('invalid_block_number', String((err && err.message) || err));
    }
  }
  const blockHash = settlementProof.blockHash ? String(settlementProof.blockHash).toLowerCase() : null;

  // Check root trust anchor
  let rootAnchored = false;
  let anchorSource = null;

  if (verifiedRootAttestation && verifiedRootAttestation.ok) {
    const att = verifiedRootAttestation.payload;
    if (normalizeEvmNetworkId(att.network) !== effNet) {
      return fail(
        'root_attestation_mismatch',
        `Root attestation network (${att.network}) does not match settlement network (${effNet}).`
      );
    }
    if (String(att.receiptsRoot).toLowerCase() !== evmRes.receiptsRoot.toLowerCase()) {
      return fail(
        'root_attestation_mismatch',
        `Root attestation receiptsRoot (${att.receiptsRoot}) != proof receiptsRoot (${evmRes.receiptsRoot}).`
      );
    }
    if (blockNumber !== null && String(att.blockNumber) !== blockNumber) {
      return fail(
        'root_attestation_mismatch',
        `Root attestation blockNumber (${att.blockNumber}) != proof blockNumber (${blockNumber}).`
      );
    }
    if (blockHash && att.blockHash && String(att.blockHash).toLowerCase() !== blockHash) {
      return fail(
        'root_attestation_mismatch',
        `Root attestation blockHash (${att.blockHash}) != proof blockHash (${blockHash}).`
      );
    }
    rootAnchored = true;
    anchorSource = 'rootAttestation';
  } else {
    const trustedMatch = matchTrustedReceiptsRoot(trustedRoots, {
      network: effNet,
      blockNumber,
      blockHash,
      receiptsRoot: evmRes.receiptsRoot
    });
    if (trustedMatch.matched) {
      rootAnchored = true;
      anchorSource = trustedMatch.source;
    }
  }

  if (!rootAnchored && !allowUnanchoredRoot) {
    return fail(
      'untrusted_receipts_root',
      `MPT receipt proof is structurally valid under ${evmRes.receiptsRoot}, but receiptsRoot is not anchored by trustedRoots or a trusted rootAttestation.`,
      { receiptsRoot: evmRes.receiptsRoot, transactionIndex: evmRes.transactionIndex }
    );
  }

  // Scan decoded receipt logs for canonical ERC-20 Transfer(from, to, value)
  const matchedTransfers = [];
  for (const log of evmRes.receipt.logs) {
    if (log.address !== wantTokenLower) continue;
    if (!log.topics || log.topics.length !== 3) continue;
    if (log.topics[0] !== ERC20_TRANSFER_TOPIC0) continue;
    const from = normalizeTopicAddress(log.topics[1]);
    const to = normalizeTopicAddress(log.topics[2]);
    if (!from || !to) continue;
    if (!log.data || log.data.length !== 66) continue; // 0x + 32-byte uint256
    let amount;
    try {
      amount = BigInt(log.data);
    } catch {
      continue;
    }
    if (wantToLower && to !== wantToLower) continue;
    if (wantPayerLower && from !== wantPayerLower) continue;
    if (amount < requiredAmount) continue;
    matchedTransfers.push({
      logIndex: log.logIndex,
      token: tokenAddress,
      from,
      to,
      amountAtomic: amount.toString()
    });
  }

  if (matchedTransfers.length === 0) {
    return fail(
      'matching_transfer_not_found',
      `Receipt at index ${evmRes.transactionIndex} succeeded, but emitted no Transfer >= ${requiredAmount} on ${tokenAddress}${wantToLower ? ` to ${wantToLower}` : ''}${wantPayerLower ? ` from ${wantPayerLower}` : ''}.`,
      {
        rootAnchored,
        receiptsRoot: evmRes.receiptsRoot,
        transactionIndex: evmRes.transactionIndex
      }
    );
  }

  return {
    ok: true,
    verified: true,
    code: 'verified_settled',
    reason: `Verified on-chain ${assetStr} Transfer (${matchedTransfers[0].amountAtomic} atomic units to ${matchedTransfers[0].to}) via MPT receipt proof at txIndex=${evmRes.transactionIndex}.`,
    network: effNet,
    blockNumber,
    blockHash,
    receiptsRoot: evmRes.receiptsRoot,
    transactionIndex: evmRes.transactionIndex,
    rootAnchored,
    anchorSource,
    matchedTransfer: matchedTransfers[0],
    allMatchedTransfers: matchedTransfers
  };
}

// ─── 7. Signed Block Root Attestations (paxiom.root.v0) ─────────────────

function getSubtleCrypto(explicitCrypto) {
  const c = explicitCrypto || globalThis.crypto || require('node:crypto').webcrypto;
  if (!c || !c.subtle) {
    throw new Error('WebCrypto API (crypto.subtle) is required for Ed25519 root attestations');
  }
  return c;
}

function concatPkcs8Seed(seed32) {
  const out = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  out.set(ED25519_PKCS8_PREFIX, 0);
  out.set(seed32, ED25519_PKCS8_PREFIX.length);
  return out;
}

async function importAttesterPrivateKey(privateKey, webCrypto) {
  if (typeof CryptoKey !== 'undefined' && privateKey instanceof CryptoKey) {
    throw new TypeError('Pass privateKey as PKCS#8 PEM, 32-byte hex/Uint8Array seed, or JWK so publicKey can be derived');
  }
  let pkcs8Bytes = null;
  if (privateKey instanceof Uint8Array && privateKey.length === 32) {
    pkcs8Bytes = concatPkcs8Seed(privateKey);
  } else if (typeof privateKey === 'string') {
    const trimmed = privateKey.trim().replace(/\\n/g, '\n');
    if (trimmed.includes('-----BEGIN')) {
      const b64 = trimmed
        .replace(/-----BEGIN [^-]+-----/g, '')
        .replace(/-----END [^-]+-----/g, '')
        .replace(/\s+/g, '');
      pkcs8Bytes = base64ToBytes(b64);
    } else if (HEX_SEED_32_RE.test(trimmed)) {
      pkcs8Bytes = concatPkcs8Seed(hexToBytes(trimmed));
    }
  } else if (privateKey && typeof privateKey === 'object' && privateKey.kty === 'OKP' && privateKey.crv === 'Ed25519' && privateKey.d && privateKey.x) {
    const ck = await webCrypto.subtle.importKey('jwk', privateKey, { name: 'Ed25519' }, false, ['sign']);
    const pubRaw = strictDecodeBase64Bytes(
      privateKey.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (privateKey.x.length % 4)) % 4),
      32,
      'JWK.x'
    );
    return { cryptoKey: ck, publicKey: bytesToBase64(pubRaw) };
  }

  if (!pkcs8Bytes) {
    throw new TypeError('Unsupported Ed25519 privateKey format for issueRootAttestation');
  }

  const ck = await webCrypto.subtle.importKey('pkcs8', pkcs8Bytes, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await webCrypto.subtle.exportKey('jwk', ck);
  const stdX = jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (jwk.x.length % 4)) % 4);
  const pubRaw = strictDecodeBase64Bytes(stdX, 32, 'derived public key');
  return { cryptoKey: ck, publicKey: bytesToBase64(pubRaw) };
}

/**
 * Compute domain-separated RFC 8785 JCS signing input bytes for `paxiom.root.v0`.
 */
function rootAttestationSigningBytes(payload) {
  return utf8ToBytes(
    canonicalize({
      attestationVersion: ROOT_ATTESTATION_VERSION,
      payload
    })
  );
}

/**
 * Validate structural schema of a `paxiom.root.v0` signed block root attestation.
 * Returns array of human-readable error strings (`[]` when valid).
 */
function validateRootAttestationStructure(attestation, depth = 0) {
  const errs = [];
  if (depth > MAX_DEPTH) return ['Attestation exceeds max depth'];
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    return ['Root attestation must be a JSON object'];
  }
  if (attestation.attestationVersion !== ROOT_ATTESTATION_VERSION) {
    errs.push(`Unsupported attestationVersion "${attestation.attestationVersion}" (expected "${ROOT_ATTESTATION_VERSION}")`);
  }
  const p = attestation.payload;
  if (!p || typeof p !== 'object' || Array.isArray(p)) {
    errs.push('payload must be an object');
    return errs;
  }
  if (typeof p.network !== 'string' || !p.network.trim()) {
    errs.push('payload.network must be a non-empty string');
  }
  if (typeof p.blockNumber !== 'string' || !DEC_UINT_RE.test(p.blockNumber)) {
    errs.push('payload.blockNumber must be a canonical decimal integer string');
  }
  if (typeof p.blockHash !== 'string' || !HEX32_RE.test(p.blockHash)) {
    errs.push('payload.blockHash must be a 0x-prefixed 32-byte hex string');
  }
  if (p.stateRoot !== undefined && p.stateRoot !== null && (typeof p.stateRoot !== 'string' || !HEX32_RE.test(p.stateRoot))) {
    errs.push('payload.stateRoot must be a 0x-prefixed 32-byte hex string');
  }
  if (p.receiptsRoot !== undefined && p.receiptsRoot !== null && (typeof p.receiptsRoot !== 'string' || !HEX32_RE.test(p.receiptsRoot))) {
    errs.push('payload.receiptsRoot must be a 0x-prefixed 32-byte hex string');
  }
  if (!p.stateRoot && !p.receiptsRoot) {
    errs.push('payload must include at least one of stateRoot or receiptsRoot');
  }
  if (!ALLOWED_FINALITY_TIERS.includes(p.finalityTier)) {
    errs.push(`payload.finalityTier must be one of: ${ALLOWED_FINALITY_TIERS.join(', ')}`);
  }
  if (typeof p.issuedAt !== 'string' || Number.isNaN(Date.parse(p.issuedAt))) {
    errs.push('payload.issuedAt must be an ISO-8601 timestamp');
  }
  if (p.expiresAt !== undefined && (typeof p.expiresAt !== 'string' || Number.isNaN(Date.parse(p.expiresAt)))) {
    errs.push('payload.expiresAt must be an ISO-8601 timestamp');
  }
  if (!p.attester || typeof p.attester !== 'object' || !p.attester.name || !p.attester.keyId) {
    errs.push('payload.attester.{name,keyId} are required');
  }

  const sig = attestation.signature;
  if (!sig || typeof sig !== 'object') {
    errs.push('signature object is required');
    return errs;
  }
  if (sig.algorithm !== 'ed25519') {
    errs.push('signature.algorithm must be "ed25519"');
  }
  if (typeof sig.keyId !== 'string' || sig.keyId !== (p.attester && p.attester.keyId)) {
    errs.push('signature.keyId must match payload.attester.keyId');
  }
  if (typeof sig.publicKey !== 'string' || typeof sig.value !== 'string') {
    errs.push('signature.publicKey and signature.value must be base64 strings');
  }
  return errs;
}

/**
 * Issue an Ed25519-signed `paxiom.root.v0` block root attestation using pure WebCrypto.
 */
async function issueRootAttestation({
  privateKey,
  network,
  blockNumber,
  blockHash,
  stateRoot,
  receiptsRoot,
  timestamp,
  finalityTier = 'l2-sequencer-attested',
  issuedAt = new Date().toISOString(),
  expiresAt,
  attester,
  crypto: explicitCrypto
} = {}) {
  if (!attester || !attester.name || !attester.keyId) {
    throw new TypeError('attester.name and attester.keyId are required');
  }
  const normNet = normalizeEvmNetworkId(network);
  if (!normNet) throw new TypeError('network is required');
  const normBlockNum = parseFlexibleUint256(blockNumber, 'blockNumber').toString();
  const normBlockHash = `0x${bytesToHex(asFixedBytes(blockHash, 32, 'blockHash'))}`;
  const normStateRoot = stateRoot !== undefined && stateRoot !== null
    ? `0x${bytesToHex(asFixedBytes(stateRoot, 32, 'stateRoot'))}`
    : undefined;
  const normReceiptsRoot = receiptsRoot !== undefined && receiptsRoot !== null
    ? `0x${bytesToHex(asFixedBytes(receiptsRoot, 32, 'receiptsRoot'))}`
    : undefined;
  if (!normStateRoot && !normReceiptsRoot) {
    throw new TypeError('At least one of stateRoot or receiptsRoot is required');
  }
  if (!ALLOWED_FINALITY_TIERS.includes(finalityTier)) {
    throw new TypeError(`Invalid finalityTier "${finalityTier}"`);
  }

  const webCrypto = getSubtleCrypto(explicitCrypto);
  const { cryptoKey, publicKey } = await importAttesterPrivateKey(privateKey, webCrypto);

  const payload = {
    network: normNet,
    blockNumber: normBlockNum,
    blockHash: normBlockHash,
    ...(normStateRoot ? { stateRoot: normStateRoot } : {}),
    ...(normReceiptsRoot ? { receiptsRoot: normReceiptsRoot } : {}),
    ...(timestamp !== undefined && timestamp !== null ? { timestamp: Number(timestamp) } : {}),
    finalityTier,
    issuedAt: issuedAt instanceof Date ? issuedAt.toISOString() : String(issuedAt),
    ...(expiresAt ? { expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : String(expiresAt) } : {}),
    attester: {
      name: String(attester.name),
      keyId: String(attester.keyId),
      ...(attester.uri ? { uri: String(attester.uri) } : {})
    }
  };

  const msgBytes = rootAttestationSigningBytes(payload);
  const sigBytes = new Uint8Array(await webCrypto.subtle.sign({ name: 'Ed25519' }, cryptoKey, msgBytes));

  return {
    attestationVersion: ROOT_ATTESTATION_VERSION,
    payload,
    signature: {
      algorithm: 'ed25519',
      keyId: payload.attester.keyId,
      publicKey,
      value: bytesToBase64(sigBytes)
    }
  };
}

/**
 * Verify a `paxiom.root.v0` signed block root attestation via pure WebCrypto. Never throws.
 */
async function verifyRootAttestation(
  attestation,
  {
    trustedRootPublicKeys,
    allowedFinalityTiers,
    now,
    crypto: explicitCrypto
  } = {}
) {
  const fail = (code, reason) => ({ ok: false, verified: false, code, reason, payload: null });
  const schemaErrs = validateRootAttestationStructure(attestation);
  if (schemaErrs.length > 0) {
    return fail('invalid_root_attestation', schemaErrs[0]);
  }

  let webCrypto;
  try {
    webCrypto = getSubtleCrypto(explicitCrypto);
  } catch (err) {
    return fail('crypto_unavailable', String((err && err.message) || err));
  }

  let pubBytes;
  let sigBytes;
  let msgBytes;
  try {
    pubBytes = strictDecodeBase64Bytes(attestation.signature.publicKey, 32, 'signature.publicKey');
    sigBytes = strictDecodeBase64Bytes(attestation.signature.value, 64, 'signature.value');
    msgBytes = rootAttestationSigningBytes(attestation.payload);
  } catch (err) {
    return fail('invalid_signature', String((err && err.message) || err));
  }

  let sigOk = false;
  try {
    const pubKey = await webCrypto.subtle.importKey('raw', pubBytes, { name: 'Ed25519' }, false, ['verify']);
    sigOk = await webCrypto.subtle.verify({ name: 'Ed25519' }, pubKey, sigBytes, msgBytes);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return fail('invalid_signature', 'Ed25519 signature verification failed on rootAttestation.');
  }

  if (trustedRootPublicKeys !== undefined && trustedRootPublicKeys !== null) {
    const allowedSet = trustedRootPublicKeys instanceof Set
      ? trustedRootPublicKeys
      : new Set(Array.isArray(trustedRootPublicKeys) ? trustedRootPublicKeys : []);
    if (!allowedSet.has(attestation.signature.publicKey)) {
      return fail(
        'untrusted_root_signer',
        `Root attestation signer (${attestation.signature.publicKey}) is not in trustedRootPublicKeys.`
      );
    }
  }

  if (Array.isArray(allowedFinalityTiers) && allowedFinalityTiers.length > 0) {
    if (!allowedFinalityTiers.includes(attestation.payload.finalityTier)) {
      return fail(
        'disallowed_finality_tier',
        `Root attestation finalityTier "${attestation.payload.finalityTier}" is not in allowedFinalityTiers.`
      );
    }
  }

  const nowMs = typeof now === 'number' && Number.isFinite(now)
    ? now
    : now instanceof Date
      ? now.getTime()
      : Date.now();
  if (attestation.payload.expiresAt && Date.parse(attestation.payload.expiresAt) < nowMs) {
    return fail('expired_root_attestation', `Root attestation expired at ${attestation.payload.expiresAt}.`);
  }

  return {
    ok: true,
    verified: true,
    code: 'verified',
    reason: `Verified paxiom.root.v0 attestation for ${attestation.payload.network} block ${attestation.payload.blockNumber} (${attestation.payload.finalityTier}).`,
    payload: attestation.payload,
    signerPublicKey: attestation.signature.publicKey
  };
}

function matchTrustedStateRoot(trustedRoots, { network, blockNumber, blockHash, stateRoot }) {
  if (!trustedRoots || !stateRoot) return { matched: false };
  const wantRoot = stateRoot.toLowerCase();
  const checkEntry = (entry) => {
    if (!entry) return false;
    if (typeof entry === 'string') {
      return entry.trim().toLowerCase() === wantRoot;
    }
    if (typeof entry === 'object') {
      const candRoot = String(entry.stateRoot || entry.state_root || '').trim().toLowerCase();
      if (!candRoot || candRoot !== wantRoot) return false;
      if (entry.network && network && normalizeEvmNetworkId(entry.network) !== network) return false;
      if (entry.blockNumber !== undefined && entry.blockNumber !== null && blockNumber !== null) {
        try {
          if (parseFlexibleUint256(entry.blockNumber, 'blockNumber').toString() !== blockNumber) return false;
        } catch {
          return false;
        }
      }
      if (entry.blockHash && blockHash && String(entry.blockHash).toLowerCase() !== blockHash.toLowerCase()) {
        return false;
      }
      return true;
    }
    return false;
  };

  if (Array.isArray(trustedRoots) || trustedRoots instanceof Set) {
    for (const item of trustedRoots) {
      if (checkEntry(item)) return { matched: true, source: 'trustedRoots' };
    }
    return { matched: false };
  }
  if (typeof trustedRoots === 'object') {
    const keysToTry = [];
    if (network && blockNumber !== null) keysToTry.push(`${network}:${blockNumber}`);
    if (blockNumber !== null) keysToTry.push(blockNumber);
    if (network && blockHash) keysToTry.push(`${network}:${blockHash.toLowerCase()}`);
    if (blockHash) keysToTry.push(blockHash.toLowerCase());
    if (network) keysToTry.push(network);
    for (const k of keysToTry) {
      if (Object.prototype.hasOwnProperty.call(trustedRoots, k) && checkEntry(trustedRoots[k])) {
        return { matched: true, source: 'trustedRoots' };
      }
    }
    if (checkEntry(trustedRoots)) return { matched: true, source: 'trustedRoots' };
  }
  return { matched: false };
}

/**
 * Shared deterministic evaluator used by both `src/verify.mjs` (Node sync) and `src/web.mjs` (WebCrypto async)
 * to evaluate optional `claimProof` (EIP-1186) and `settlementProof` (EVM receipt-trie) inputs on a receipt.
 */
function evaluateReceiptOfflineProofsSync({
  receipt,
  opts = {},
  verifiedRootAttestation = null,
  rootAttestationError = null
} = {}) {
  const p = receipt.payload;
  const effNet = normalizeEvmNetworkId(
    (opts.settlementProof && opts.settlementProof.network) ||
    (opts.claimProof && opts.claimProof.network) ||
    p.payment.network
  );

  let claimProofVerified = false;

  // (A) Evaluate optional EIP-1186 state/storage claimProof
  if (opts.claimProof !== undefined && opts.claimProof !== null) {
    if (typeof opts.claimProof !== 'object') {
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: 'claimProof must be an EIP-1186 proof envelope object.'
      };
    }
    const cp = opts.claimProof;
    const rawProofObj = cp.proof && typeof cp.proof === 'object' && !Array.isArray(cp.proof) ? cp.proof : cp;
    const stateRoot =
      cp.stateRoot ||
      (verifiedRootAttestation && verifiedRootAttestation.payload && verifiedRootAttestation.payload.stateRoot) ||
      null;

    if (!stateRoot) {
      if (rootAttestationError) {
        return {
          outcome: 'fail',
          trustState: 'proof_invalid',
          checkProof: 'invalid',
          summary: `Offline claimProof rootAttestation failed: ${rootAttestationError.reason}`
        };
      }
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: 'Offline EIP-1186 claimProof requires stateRoot (explicit or via verified rootAttestation).'
      };
    }

    const eipRes = verifyEip1186Proof({
      stateRoot,
      proof: rawProofObj,
      expectedStorage: cp.expectedStorage
    });
    if (!eipRes.ok) {
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: `Offline EIP-1186 claimProof failed: ${eipRes.reason}`
      };
    }

    let cpBlockNumber = null;
    if (cp.blockNumber !== undefined && cp.blockNumber !== null) {
      try {
        cpBlockNumber = parseFlexibleUint256(cp.blockNumber, 'claimProof.blockNumber').toString();
      } catch {
        cpBlockNumber = null;
      }
    }
    const cpBlockHash = cp.blockHash ? String(cp.blockHash).toLowerCase() : null;

    let stateAnchored = Boolean(cp.allowUnanchoredRoot);
    if (
      verifiedRootAttestation &&
      verifiedRootAttestation.ok &&
      verifiedRootAttestation.payload.stateRoot &&
      verifiedRootAttestation.payload.stateRoot.toLowerCase() === eipRes.stateRoot.toLowerCase()
    ) {
      stateAnchored = true;
    } else if (
      matchTrustedStateRoot(opts.trustedRoots, {
        network: effNet,
        blockNumber: cpBlockNumber,
        blockHash: cpBlockHash,
        stateRoot: eipRes.stateRoot
      }).matched
    ) {
      stateAnchored = true;
    }

    if (!stateAnchored) {
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: rootAttestationError
          ? `Offline EIP-1186 claimProof rootAttestation failed: ${rootAttestationError.reason}`
          : `Offline EIP-1186 claimProof verified structurally under ${eipRes.stateRoot}, but stateRoot is not anchored by trustedRoots or trustedRootPublicKeys.`
      };
    }
    claimProofVerified = true;
  }

  // (B) Evaluate optional EVM receipt-trie settlementProof
  if (opts.settlementProof !== undefined && opts.settlementProof !== null) {
    const sp = opts.settlementProof;
    const receiptPayTo = opts.expectedPayTo || p.payment.payTo || p.issuer.payTo || undefined;
    const receiptPayer = opts.expectedPayer || p.payment.payer || undefined;
    const receiptTxHash = p.payment.settlement && p.payment.settlement.transactionHash
      ? p.payment.settlement.transactionHash
      : undefined;

    // First verify structural MPT + Transfer log (and check root anchor if available)
    const structural = verifyUsdcSettlementProofSync({
      settlementProof: sp,
      network: p.payment.network,
      expectedPayTo: receiptPayTo,
      expectedPayer: receiptPayer,
      minAmountAtomic: p.payment.amountAtomic,
      expectedAsset: p.payment.asset,
      expectedTransactionHash: receiptTxHash,
      trustedRoots: opts.trustedRoots || null,
      verifiedRootAttestation: verifiedRootAttestation && verifiedRootAttestation.ok ? verifiedRootAttestation : null,
      allowUnanchoredRoot: true
    });

    if (!structural.ok) {
      if (structural.code === 'tx_reverted') {
        return {
          outcome: 'fail',
          trustState: 'settlement_failed',
          checkSettlement: 'failed',
          checkProof: 'invalid',
          summary: `Offline settlement proof shows transaction reverted: ${structural.reason}`
        };
      }
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: `Offline settlement proof failed verification: ${structural.reason}`
      };
    }

    if (
      rootAttestationError &&
      (rootAttestationError.code === 'invalid_signature' ||
        rootAttestationError.code === 'invalid_root_attestation')
    ) {
      return {
        outcome: 'fail',
        trustState: 'proof_invalid',
        checkProof: 'invalid',
        summary: `Offline rootAttestation failed verification: ${rootAttestationError.reason}`
      };
    }

    if (structural.rootAnchored) {
      return {
        outcome: 'verified_settled',
        checkSettlement: 'verified_settled',
        checkProof: 'verified',
        summary: structural.reason,
        settlementDetail: structural
      };
    }

    return {
      outcome: 'unanchored_settlement_proof',
      checkProof: claimProofVerified ? 'verified' : 'provided',
      summary: rootAttestationError
        ? `MPT settlement proof verified structurally, but rootAttestation did not anchor receiptsRoot: ${rootAttestationError.reason}`
        : `MPT settlement proof verified structurally against ${structural.receiptsRoot}, but receiptsRoot was not anchored by trustedRoots or trustedRootPublicKeys.`
    };
  }

  if (claimProofVerified) {
    return {
      outcome: 'claim_verified',
      checkProof: 'verified'
    };
  }

  return { outcome: 'none' };
}

/**
 * Async WebCrypto wrapper for offline USDC settlement proof verification,
 * automatically verifying an attached or supplied `rootAttestation` when present. Never throws.
 */
async function verifyUsdcSettlementProof(opts = {}) {
  const safeOpts = opts && typeof opts === 'object' ? opts : {};
  const sp = safeOpts.settlementProof;
  const rawAtt = safeOpts.rootAttestation || (sp && sp.rootAttestation) || null;
  const rawKeys = safeOpts.trustedRootPublicKeys ?? safeOpts.trustedVerifierPublicKeys ?? null;

  let verifiedAtt = null;
  if (rawAtt) {
    if (!rawKeys && !safeOpts.allowUnanchoredRoot) {
      return {
        ok: false,
        verified: false,
        code: 'untrusted_root_signer',
        reason: 'rootAttestation provided without trustedRootPublicKeys.',
        rootAnchored: false
      };
    }
    verifiedAtt = await verifyRootAttestation(rawAtt, {
      trustedRootPublicKeys: rawKeys || undefined,
      allowedFinalityTiers: safeOpts.allowedFinalityTiers,
      now: safeOpts.now,
      crypto: safeOpts.crypto
    });
    if (!verifiedAtt.ok) {
      return {
        ok: false,
        verified: false,
        code: verifiedAtt.code,
        reason: verifiedAtt.reason,
        rootAnchored: false
      };
    }
  }

  return verifyUsdcSettlementProofSync({
    ...safeOpts,
    verifiedRootAttestation: verifiedAtt
  });
}

// ─── 8. ERC-8021 Base Builder Code & x402 Calldata Attribution ──────────

const ERC8021_MARKER_BYTES = new Uint8Array([
  0x80, 0x21, 0x80, 0x21, 0x80, 0x21, 0x80, 0x21,
  0x80, 0x21, 0x80, 0x21, 0x80, 0x21, 0x80, 0x21
]);
const ERC8021_CODE_RE = /^[\x21-\x2b\x2d-\x7e]+$/; // printable non-whitespace, non-comma ASCII
const MAX_CBOR_DEPTH = 16;

function validateAttributionCode(code, label) {
  if (typeof code !== 'string' || !code || !ERC8021_CODE_RE.test(code)) {
    throw new TypeError(`${label} must be a non-empty printable ASCII identifier without commas or whitespace`);
  }
  return code;
}

function cborEncodeHeader(majorType, length) {
  const mt = majorType << 5;
  if (length < 24) return new Uint8Array([mt | length]);
  if (length <= 0xff) return new Uint8Array([mt | 24, length]);
  if (length <= 0xffff) return new Uint8Array([mt | 25, (length >>> 8) & 0xff, length & 0xff]);
  if (length <= 0xffffffff) {
    return new Uint8Array([
      mt | 26,
      (length >>> 24) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff
    ]);
  }
  throw new RangeError('CBOR value exceeds 32-bit length bounds');
}

function cborEncodeValue(val, depth = 0) {
  if (depth > MAX_CBOR_DEPTH) throw new RangeError('CBOR nesting exceeds max depth');
  if (val === null) return new Uint8Array([0xf6]);
  if (val === false) return new Uint8Array([0xf4]);
  if (val === true) return new Uint8Array([0xf5]);
  if (typeof val === 'number' || typeof val === 'bigint') {
    const n = typeof val === 'bigint' ? Number(val) : val;
    if (!Number.isSafeInteger(n)) throw new TypeError('CBOR integer must be a safe integer');
    if (n >= 0) return cborEncodeHeader(0, n);
    return cborEncodeHeader(1, -1 - n);
  }
  if (typeof val === 'string') {
    const b = utf8ToBytes(val);
    return concatBytes([cborEncodeHeader(3, b.length), b]);
  }
  if (val instanceof Uint8Array) {
    return concatBytes([cborEncodeHeader(2, val.length), val]);
  }
  if (Array.isArray(val)) {
    const parts = [cborEncodeHeader(4, val.length)];
    for (const item of val) parts.push(cborEncodeValue(item, depth + 1));
    return concatBytes(parts);
  }
  if (val && typeof val === 'object') {
    const entries = Object.entries(val).filter(([, v]) => v !== undefined);
    const parts = [cborEncodeHeader(5, entries.length)];
    for (const [k, v] of entries) {
      parts.push(cborEncodeValue(k, depth + 1));
      parts.push(cborEncodeValue(v, depth + 1));
    }
    return concatBytes(parts);
  }
  throw new TypeError(`Unsupported CBOR value type: ${typeof val}`);
}

function cborDecodeHead(data, offset) {
  if (offset >= data.length) throw new Error('Unexpected end of CBOR input');
  const initial = data[offset];
  const major = initial >>> 5;
  const info = initial & 0x1f;
  if (info < 24) return { major, arg: info, next: offset + 1 };
  if (info === 24) {
    if (offset + 2 > data.length) throw new Error('Truncated CBOR uint8');
    return { major, arg: data[offset + 1], next: offset + 2 };
  }
  if (info === 25) {
    if (offset + 3 > data.length) throw new Error('Truncated CBOR uint16');
    return { major, arg: (data[offset + 1] << 8) | data[offset + 2], next: offset + 3 };
  }
  if (info === 26) {
    if (offset + 5 > data.length) throw new Error('Truncated CBOR uint32');
    const u32 = (
      (data[offset + 1] * 0x1000000) +
      ((data[offset + 2] << 16) | (data[offset + 3] << 8) | data[offset + 4])
    );
    return { major, arg: u32, next: offset + 5 };
  }
  throw new Error(`Unsupported CBOR additional info: ${info}`);
}

function cborDecodeItem(data, offset, depth = 0) {
  if (depth > MAX_CBOR_DEPTH) throw new Error('CBOR nesting exceeds max depth');
  const { major, arg, next } = cborDecodeHead(data, offset);
  if (major === 0) return { value: arg, next };
  if (major === 1) return { value: -1 - arg, next };
  if (major === 2) {
    if (next + arg > data.length) throw new Error('Truncated CBOR byte string');
    return { value: data.slice(next, next + arg), next: next + arg };
  }
  if (major === 3) {
    if (next + arg > data.length) throw new Error('Truncated CBOR text string');
    return { value: bytesToUtf8(data.subarray(next, next + arg)), next: next + arg };
  }
  if (major === 4) {
    const arr = [];
    let cur = next;
    for (let i = 0; i < arg; i++) {
      const child = cborDecodeItem(data, cur, depth + 1);
      arr.push(child.value);
      cur = child.next;
    }
    return { value: arr, next: cur };
  }
  if (major === 5) {
    const obj = Object.create(null);
    let cur = next;
    for (let i = 0; i < arg; i++) {
      const k = cborDecodeItem(data, cur, depth + 1);
      const v = cborDecodeItem(data, k.next, depth + 1);
      obj[String(k.value)] = v.value;
      cur = v.next;
    }
    return { value: obj, next: cur };
  }
  if (major === 7) {
    if (arg === 20) return { value: false, next };
    if (arg === 21) return { value: true, next };
    if (arg === 22) return { value: null, next };
  }
  throw new Error(`Unsupported CBOR major type ${major}`);
}

/**
 * Encode an ERC-8021 transaction attribution suffix (`0x...` hex) compatible with Base Builder Codes
 * and `wevm/ox` (`Schema 0` canonical codes, `Schema 1` custom registry, and `Schema 2` CBOR `x402` attribution).
 * Accepts a single Builder Code string (e.g. `'bc_...'`), an array of code strings, or an attribution object.
 */
function encodeErc8021Suffix(attribution) {
  let spec;
  if (typeof attribution === 'string') {
    spec = { codes: [attribution] };
  } else if (Array.isArray(attribution)) {
    spec = { codes: attribution };
  } else if (attribution && typeof attribution === 'object') {
    spec = attribution;
  } else {
    throw new TypeError('attribution must be a Builder Code string, string[], or ERC-8021 attribution object');
  }

  const isSchema2 =
    spec.id === 2 ||
    spec.appCode !== undefined ||
    spec.walletCode !== undefined ||
    spec.serviceCodes !== undefined ||
    spec.registries !== undefined ||
    spec.metadata !== undefined;

  if (isSchema2) {
    const map = {};
    if (spec.appCode !== undefined) map.a = validateAttributionCode(spec.appCode, 'appCode');
    if (spec.walletCode !== undefined) map.w = validateAttributionCode(spec.walletCode, 'walletCode');
    if (Array.isArray(spec.serviceCodes) && spec.serviceCodes.length > 0) {
      map.s = spec.serviceCodes.map((c, idx) => validateAttributionCode(c, `serviceCodes[${idx}]`));
    }
    if (spec.registries && typeof spec.registries === 'object') {
      const r = {};
      if (spec.registries.app) {
        const addr = `0x${bytesToHex(asFixedBytes(spec.registries.app.address, 20, 'registries.app.address'))}`;
        const cid = `0x${parseFlexibleUint256(spec.registries.app.chainId, 'registries.app.chainId').toString(16)}`;
        r.a = { c: cid, a: addr };
      }
      if (spec.registries.wallet) {
        const addr = `0x${bytesToHex(asFixedBytes(spec.registries.wallet.address, 20, 'registries.wallet.address'))}`;
        const cid = `0x${parseFlexibleUint256(spec.registries.wallet.chainId, 'registries.wallet.chainId').toString(16)}`;
        r.w = { c: cid, a: addr };
      }
      if (r.a || r.w) map.r = r;
    }
    if (spec.metadata && typeof spec.metadata === 'object' && Object.keys(spec.metadata).length > 0) {
      map.m = spec.metadata;
    }
    const cborBytes = cborEncodeValue(map);
    if (cborBytes.length === 0 || cborBytes.length > 0xffff) {
      throw new RangeError('ERC-8021 Schema 2 CBOR payload must be 1..65535 bytes');
    }
    const len2 = new Uint8Array([(cborBytes.length >>> 8) & 0xff, cborBytes.length & 0xff, 0x02]);
    return `0x${bytesToHex(concatBytes([cborBytes, len2, ERC8021_MARKER_BYTES]))}`;
  }

  if (!Array.isArray(spec.codes) || spec.codes.length === 0) {
    throw new TypeError('ERC-8021 Schema 0/1 requires a non-empty codes array');
  }
  const cleanCodes = spec.codes.map((c, idx) => validateAttributionCode(c, `codes[${idx}]`));
  const codesBytes = utf8ToBytes(cleanCodes.join(','));
  if (codesBytes.length > 255) {
    throw new RangeError('ERC-8021 Schema 0/1 codes payload cannot exceed 255 bytes');
  }

  if (spec.id === 1 || spec.codeRegistry) {
    if (!spec.codeRegistry || typeof spec.codeRegistry !== 'object') {
      throw new TypeError('ERC-8021 Schema 1 requires codeRegistry: { address, chainId }');
    }
    const regAddr = asFixedBytes(spec.codeRegistry.address, 20, 'codeRegistry.address');
    const chainIdBig = parseFlexibleUint256(spec.codeRegistry.chainId, 'codeRegistry.chainId');
    if (chainIdBig <= 0n) throw new RangeError('codeRegistry.chainId must be > 0');
    const chainIdBytes = uintToMinimalBytes(chainIdBig);
    const tail = new Uint8Array([codesBytes.length, 0x01]);
    return `0x${bytesToHex(
      concatBytes([
        regAddr,
        chainIdBytes,
        new Uint8Array([chainIdBytes.length]),
        codesBytes,
        tail,
        ERC8021_MARKER_BYTES
      ])
    )}`;
  }

  const tail = new Uint8Array([codesBytes.length, 0x00]);
  return `0x${bytesToHex(concatBytes([codesBytes, tail, ERC8021_MARKER_BYTES]))}`;
}

/**
 * Append an ERC-8021 attribution suffix to EVM transaction `calldata` (`0x...` hex or `Uint8Array`),
 * returning `0x`-prefixed hex calldata.
 */
function appendErc8021Suffix(calldata, attribution) {
  const baseBytes = !calldata || calldata === '0x' || calldata === '0X'
    ? new Uint8Array(0)
    : asBytesFlexible(calldata, 'calldata');
  const suffixBytes = hexToBytes(encodeErc8021Suffix(attribution));
  return `0x${bytesToHex(concatBytes([baseBytes, suffixBytes]))}`;
}

/**
 * Extract and decode an ERC-8021 attribution suffix from EVM transaction `calldata` (reading backwards
 * from the 16-byte `0x8021...8021` marker). Deterministic and never throws on arbitrary calldata.
 */
function decodeErc8021Suffix(calldata) {
  const none = (code, reason) => ({ ok: false, present: false, code, reason, schemaId: null, attribution: null });
  let raw;
  try {
    raw = asBytesFlexible(calldata, 'calldata');
  } catch (err) {
    return none('invalid_calldata', String((err && err.message) || err));
  }
  if (raw.length < 18) {
    return none('no_erc8021_marker', 'Calldata shorter than minimum ERC-8021 suffix (18 bytes).');
  }
  const markerSlice = raw.subarray(raw.length - 16);
  if (!bytesEqual(markerSlice, ERC8021_MARKER_BYTES)) {
    return none('no_erc8021_marker', 'Trailing 16 bytes do not match ERC-8021 marker.');
  }

  const schemaId = raw[raw.length - 17];

  if (schemaId === 0 || schemaId === 1) {
    if (raw.length < 19) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Truncated Schema 0/1 length byte.', schemaId, attribution: null };
    }
    const codesLen = raw[raw.length - 18];
    const codesEnd = raw.length - 18;
    const codesStart = codesEnd - codesLen;
    if (codesLen === 0 || codesStart < 0) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Invalid Schema 0/1 codesLength.', schemaId, attribution: null };
    }
    let codesStr;
    try {
      codesStr = bytesToUtf8(raw.subarray(codesStart, codesEnd));
    } catch {
      return { ok: false, present: true, code: 'invalid_erc8021_codes', reason: 'Invalid UTF-8 in ERC-8021 codes.', schemaId, attribution: null };
    }
    const codes = codesStr.split(',').filter(Boolean);
    if (codes.length === 0) {
      return { ok: false, present: true, code: 'invalid_erc8021_codes', reason: 'Empty ERC-8021 codes list.', schemaId, attribution: null };
    }

    if (schemaId === 0) {
      return {
        ok: true,
        present: true,
        code: 'verified',
        reason: `Decoded ERC-8021 Schema 0 Builder Code(s): ${codes.join(', ')}`,
        schemaId: 0,
        calldataWithoutSuffix: `0x${bytesToHex(raw.subarray(0, codesStart))}`,
        attribution: { id: 0, codes }
      };
    }

    // Schema 1: [address(20B)][chainId(N)][chainIdLen(1B)] immediately before codesStart
    if (codesStart < 22) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Truncated Schema 1 custom registry.', schemaId: 1, attribution: null };
    }
    const chainIdLen = raw[codesStart - 1];
    if (chainIdLen === 0 || chainIdLen > 32 || codesStart < 20 + 1 + chainIdLen) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Invalid Schema 1 chainIdLen.', schemaId: 1, attribution: null };
    }
    const chainIdStart = codesStart - 1 - chainIdLen;
    const addrStart = chainIdStart - 20;
    const regAddress = `0x${bytesToHex(raw.subarray(addrStart, chainIdStart))}`;
    const regChainId = Number(bytesToBigInt(raw.subarray(chainIdStart, codesStart - 1)));

    return {
      ok: true,
      present: true,
      code: 'verified',
      reason: `Decoded ERC-8021 Schema 1 Builder Code(s): ${codes.join(', ')}`,
      schemaId: 1,
      calldataWithoutSuffix: `0x${bytesToHex(raw.subarray(0, addrStart))}`,
      attribution: {
        id: 1,
        codes,
        codeRegistry: { address: regAddress, chainId: regChainId }
      }
    };
  }

  if (schemaId === 2) {
    if (raw.length < 20) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Truncated Schema 2 CBOR length.', schemaId: 2, attribution: null };
    }
    const cborLen = (raw[raw.length - 19] << 8) | raw[raw.length - 18];
    const cborEnd = raw.length - 19;
    const cborStart = cborEnd - cborLen;
    if (cborLen === 0 || cborStart < 0) {
      return { ok: false, present: true, code: 'truncated_erc8021', reason: 'Invalid Schema 2 cborLength.', schemaId: 2, attribution: null };
    }
    let decoded;
    try {
      const item = cborDecodeItem(raw.subarray(cborStart, cborEnd), 0, 0);
      if (item.next !== cborLen || !item.value || typeof item.value !== 'object' || Array.isArray(item.value)) {
        throw new Error('Schema 2 payload must be a canonical CBOR map');
      }
      decoded = item.value;
    } catch (err) {
      return { ok: false, present: true, code: 'invalid_erc8021_cbor', reason: String((err && err.message) || err), schemaId: 2, attribution: null };
    }

    const attribution = { id: 2 };
    if (typeof decoded.a === 'string') attribution.appCode = decoded.a;
    if (typeof decoded.w === 'string') attribution.walletCode = decoded.w;
    if (Array.isArray(decoded.s)) attribution.serviceCodes = decoded.s.map(String);
    if (decoded.r && typeof decoded.r === 'object') {
      const registries = {};
      if (decoded.r.a && decoded.r.a.a && decoded.r.a.c) {
        registries.app = { address: String(decoded.r.a.a), chainId: Number(BigInt(decoded.r.a.c)) };
      }
      if (decoded.r.w && decoded.r.w.a && decoded.r.w.c) {
        registries.wallet = { address: String(decoded.r.w.a), chainId: Number(BigInt(decoded.r.w.c)) };
      }
      if (registries.app || registries.wallet) attribution.registries = registries;
    }
    if (decoded.m && typeof decoded.m === 'object') {
      attribution.metadata = Object.assign({}, decoded.m);
    }

    return {
      ok: true,
      present: true,
      code: 'verified',
      reason: 'Decoded ERC-8021 Schema 2 (CBOR) attribution.',
      schemaId: 2,
      calldataWithoutSuffix: `0x${bytesToHex(raw.subarray(0, cborStart))}`,
      attribution
    };
  }

  return {
    ok: false,
    present: true,
    code: 'unsupported_erc8021_schema',
    reason: `Unsupported ERC-8021 schemaId=${schemaId}.`,
    schemaId,
    attribution: null
  };
}

exports.ROOT_ATTESTATION_VERSION = ROOT_ATTESTATION_VERSION;
exports.ERC8021_MARKER_HEX = ERC8021_MARKER_HEX;
exports.EMPTY_TRIE_ROOT_HEX = EMPTY_TRIE_ROOT_HEX;
exports.EMPTY_CODE_HASH_HEX = EMPTY_CODE_HASH_HEX;
exports.ERC20_TRANSFER_TOPIC0 = ERC20_TRANSFER_TOPIC0;
exports.ALLOWED_FINALITY_TIERS = ALLOWED_FINALITY_TIERS;
exports.CANONICAL_USDC_BY_NETWORK = CANONICAL_USDC_BY_NETWORK;
exports.keccak256Bytes = keccak256Bytes;
exports.keccak256Hex = keccak256Hex;
exports.uintToMinimalBytes = uintToMinimalBytes;
exports.bytesToBigInt = bytesToBigInt;
exports.rlpEncode = rlpEncode;
exports.rlpDecode = rlpDecode;
exports.normalizeEvmNetworkId = normalizeEvmNetworkId;
exports.deriveAccountTrieKey = deriveAccountTrieKey;
exports.deriveStorageTrieKey = deriveStorageTrieKey;
exports.computeMappingSlot = computeMappingSlot;
exports.computeNestedMappingSlot = computeNestedMappingSlot;
exports.computeEip3009AuthStateSlot = computeEip3009AuthStateSlot;
exports.verifyMptProof = verifyMptProof;
exports.buildMptProof = buildMptProof;
exports.encodeEvmAccount = encodeEvmAccount;
exports.decodeEvmAccount = decodeEvmAccount;
exports.verifyAccountProof = verifyAccountProof;
exports.verifyStorageProof = verifyStorageProof;
exports.verifyEip1186Proof = verifyEip1186Proof;
exports.encodeEvmReceipt = encodeEvmReceipt;
exports.decodeEvmReceipt = decodeEvmReceipt;
exports.buildReceiptTrieProof = buildReceiptTrieProof;
exports.verifyEvmReceiptProof = verifyEvmReceiptProof;
exports.verifyUsdcSettlementProofSync = verifyUsdcSettlementProofSync;
exports.rootAttestationSigningBytes = rootAttestationSigningBytes;
exports.validateRootAttestationStructure = validateRootAttestationStructure;
exports.issueRootAttestation = issueRootAttestation;
exports.verifyRootAttestation = verifyRootAttestation;
exports.evaluateReceiptOfflineProofsSync = evaluateReceiptOfflineProofsSync;
exports.verifyUsdcSettlementProof = verifyUsdcSettlementProof;
exports.encodeErc8021Suffix = encodeErc8021Suffix;
exports.appendErc8021Suffix = appendErc8021Suffix;
exports.decodeErc8021Suffix = decodeErc8021Suffix;
