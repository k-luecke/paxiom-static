// Pure Web-standard byte & RFC 4648 base64 / base64url / hex utilities.
// Zero `node:*` imports and zero `Buffer` references — runs identically on
// Cloudflare Workers, Deno, Bun, browsers, and Node.js.

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

const HEX_BYTE = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
const STRICT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const STRICT_BASE64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

export function isByteArray(value) {
  return value instanceof Uint8Array || ArrayBuffer.isView(value);
}

export function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new TypeError('Expected Uint8Array, ArrayBufferView, or ArrayBuffer');
}

export function utf8ToBytes(str) {
  return UTF8_ENCODER.encode(String(str));
}

export function bytesToUtf8(bytes) {
  return UTF8_DECODER.decode(asUint8Array(bytes));
}

export function bytesToHex(bytes) {
  const u8 = asUint8Array(bytes);
  let out = '';
  for (let i = 0; i < u8.length; i++) {
    out += HEX_BYTE[u8[i]];
  }
  return out;
}

export function hexToBytes(hexStr) {
  const clean = String(hexStr || '').trim().replace(/^0x/i, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new TypeError('Invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    const u8 = asUint8Array(c);
    out.set(u8, offset);
    offset += u8.byteLength;
  }
  return out;
}

export function bytesToBase64(bytes) {
  const u8 = asUint8Array(bytes);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < u8.length; i += chunkSize) {
    const slice = u8.subarray(i, i + chunkSize);
    for (let j = 0; j < slice.length; j++) {
      binary += String.fromCharCode(slice[j]);
    }
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Base64 input must be a string');
  }
  const clean = value.trim();
  if (!clean) return new Uint8Array(0);
  if (clean.length % 4 !== 0 || !STRICT_BASE64_RE.test(clean)) {
    throw new TypeError('Invalid RFC 4648 base64 string');
  }
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function strictDecodeBase64Bytes(value, expectedByteLength, label) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !STRICT_BASE64_RE.test(value)
  ) {
    throw new Error(`${label} must be canonical base64`);
  }
  const raw = base64ToBytes(value);
  if (raw.length !== expectedByteLength || bytesToBase64(raw) !== value) {
    throw new Error(`${label} must decode to ${expectedByteLength} canonical bytes`);
  }
  return raw;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64UrlToBytes(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Base64url input must be a string');
  }
  const clean = value.trim();
  if (!clean) return new Uint8Array(0);
  if (!STRICT_BASE64URL_RE.test(clean)) {
    throw new TypeError('Invalid RFC 4648 base64url string');
  }
  const unpadded = clean.replace(/=+$/, '');
  if (unpadded.length % 4 === 1) {
    throw new TypeError('Invalid RFC 4648 base64url length');
  }
  const std = unpadded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function decodeFlexibleBase64JsonObject(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  for (const decodeFn of [base64ToBytes, base64UrlToBytes]) {
    try {
      const bytes = decodeFn(trimmed);
      const parsed = JSON.parse(bytesToUtf8(bytes));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // try next encoding
    }
  }
  return null;
}
