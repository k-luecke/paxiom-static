// Pure Web-Standard / Cloudflare Workers / Edge / Browser implementation of @paxiom/receipts.
// Uses ONLY `globalThis.crypto.subtle` (Ed25519 + SHA-256), `Uint8Array`, `TextEncoder`,
// `TextDecoder`, `btoa`/`atob`, and `fetch` — zero `node:*` imports and zero `Buffer` references.

import { canonicalize, signingInputBytes, signingInput, MAX_DEPTH } from './canonicalize.mjs';
import {
  RECEIPT_VERSION,
  RECEIPT_SCHEMA,
  normalizePayToId,
  validateReceiptSchema
} from './schema.mjs';
import {
  isByteArray,
  asUint8Array,
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
  concatBytes,
  bytesToBase64,
  base64ToBytes,
  strictDecodeBase64Bytes,
  bytesToBase64Url,
  base64UrlToBytes,
  decodeFlexibleBase64JsonObject
} from './bytes.mjs';
import { explain } from './explain.mjs';
import {
  ALLOWED_FINALITY_TIERS,
  verifyRootAttestation,
  evaluateReceiptOfflineProofsSync
} from './proofs.mjs';

export {
  RECEIPT_VERSION,
  RECEIPT_SCHEMA,
  MAX_DEPTH,
  canonicalize,
  signingInputBytes,
  signingInput,
  explain,
  isByteArray,
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes
};

export const STANDARD_RECEIPT_HEADER_NAME = 'payment-receipt';
export const RECEIPT_HEADER_NAME = 'x-paxiom-receipt';
export const DEFAULT_PAXIOM_API_URL = 'https://api.paxiom.org';
export const PAXIOM_LIVE_VERIFIER_PUBLIC_KEY = 'hsRfDKd2AWxv0KwTs3gsDLMY7nPtVGky1Tc6NWgSxIY=';
export const PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS = Object.freeze([PAXIOM_LIVE_VERIFIER_PUBLIC_KEY]);
export const PAXIOM_TRUSTED_PUBLIC_KEYS = PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS;

const SHA256_HEX_RE = /^0x[0-9a-f]{64}$/;
const EVM_TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const SOLANA_TX_SIG_RE = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;
const HEX_SEED_32_RE = /^(?:0x)?[0-9a-fA-F]{64}$/;
const DEC_UINT_RE = /^[0-9]+$/;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const STRICT_BASE64_32_RE = /^[A-Za-z0-9+/]{43}=$/;

const MAX_CAPTURE_BYTES = 256 * 1024;
const DEFAULT_CLIENT_TIMEOUT_MS = 15000;
const MAX_CLIENT_RESPONSE_BYTES = 1024 * 1024;
const MAX_KEYS_RESPONSE_BYTES = 64 * 1024;
const ALLOWED_PREFLIGHT_METHODS = new Set(['POST', 'GET', 'HEAD']);

// RFC 8410 Ed25519 PKCS#8 v1 ASN.1 DER prefix (16 bytes preceding the 32-byte private seed).
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

// RFC 8032 Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
const ED25519_L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

const MAX_KEY_CACHE_ENTRIES = 32;
const PEM_KEY_CACHE = new Map();

function getWebCrypto(explicitCrypto) {
  const c = explicitCrypto || globalThis.crypto;
  if (!c || !c.subtle) {
    throw new TypeError(
      'WebCrypto globalThis.crypto.subtle is required for @paxiom/receipts/web (Cloudflare Workers, Deno, Bun, modern browsers, or Node >= 20)'
    );
  }
  return c;
}

function isCanonicalEd25519Scalar(sig64) {
  if (!(sig64 instanceof Uint8Array) || sig64.length !== 64) return false;
  if ((sig64[63] & 0xe0) !== 0) return false;
  let s = 0n;
  for (let i = 63; i >= 32; i--) {
    s = (s << 8n) | BigInt(sig64[i]);
  }
  return s < ED25519_L;
}

function randomHex(byteLen, webCrypto) {
  const buf = new Uint8Array(byteLen);
  webCrypto.getRandomValues(buf);
  return bytesToHex(buf);
}

function defaultReceiptId(webCrypto) {
  if (typeof webCrypto.randomUUID === 'function') {
    return `rcpt_${webCrypto.randomUUID().replace(/-/g, '')}`;
  }
  return `rcpt_${randomHex(16, webCrypto)}`;
}

function formatPemBlock(label, derBytes) {
  const b64 = bytesToBase64(derBytes);
  const lines = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function parsePkcs8PemToDer(pemText) {
  const normalized = pemText.replace(/\\n/g, '\n').trim();
  const beginTag = '-----BEGIN PRIVATE KEY-----';
  const endTag = '-----END PRIVATE KEY-----';
  const startIdx = normalized.indexOf(beginTag);
  const endIdx = normalized.indexOf(endTag);
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
    throw new TypeError('Invalid PKCS#8 PEM: expected -----BEGIN PRIVATE KEY----- armor');
  }
  const body = normalized.slice(startIdx + beginTag.length, endIdx).replace(/\s+/g, '');
  if (!body) throw new TypeError('Empty PKCS#8 PEM body');
  return base64ToBytes(body);
}

async function importPkcs8Ed25519(derBytes, subtle) {
  const cryptoKey = await subtle.importKey('pkcs8', derBytes, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', cryptoKey);
  if (!jwk || typeof jwk.x !== 'string') {
    throw new Error('WebCrypto Ed25519 JWK export did not expose public coordinate x');
  }
  const rawPub = base64UrlToBytes(jwk.x);
  if (rawPub.length !== 32) {
    throw new Error('Derived Ed25519 public key did not produce 32 bytes');
  }
  return {
    cryptoKey,
    publicKey: bytesToBase64(rawPub),
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }
  };
}

function wrapSeedAsPkcs8(seed32) {
  if (seed32.length !== 32) {
    throw new TypeError(`Ed25519 seed must be 32 bytes, got ${seed32.length}`);
  }
  return concatBytes([ED25519_PKCS8_PREFIX, seed32]);
}

async function resolvePublicKeyInput(pubInput, subtle) {
  if (typeof pubInput === 'string') {
    const raw = strictDecodeBase64Bytes(pubInput, 32, 'Ed25519 publicKey');
    return bytesToBase64(raw);
  }
  if (isByteArray(pubInput)) {
    const u8 = asUint8Array(pubInput);
    if (u8.length !== 32) throw new TypeError('Ed25519 publicKey Uint8Array must be 32 bytes');
    return bytesToBase64(u8);
  }
  if (pubInput && typeof pubInput === 'object' && pubInput.type === 'public') {
    const raw = new Uint8Array(await subtle.exportKey('raw', pubInput));
    if (raw.length !== 32) throw new Error('Exported Ed25519 public CryptoKey was not 32 bytes');
    return bytesToBase64(raw);
  }
  throw new TypeError('Unsupported publicKey companion format');
}

async function resolveWebPrivateKey(privateKey, webCrypto) {
  if (!privateKey) {
    throw new TypeError('privateKey is required to sign a Paxiom receipt');
  }
  const subtle = webCrypto.subtle;
  const useCache = webCrypto === globalThis.crypto;

  if (typeof privateKey === 'string') {
    const trimmed = privateKey.trim();
    if (useCache && PEM_KEY_CACHE.has(trimmed)) {
      return PEM_KEY_CACHE.get(trimmed);
    }
    const promise = (async () => {
      if (trimmed.includes('BEGIN PRIVATE KEY')) {
        const der = parsePkcs8PemToDer(trimmed);
        return importPkcs8Ed25519(der, subtle);
      }
      if (HEX_SEED_32_RE.test(trimmed)) {
        const seed = hexToBytes(trimmed);
        return importPkcs8Ed25519(wrapSeedAsPkcs8(seed), subtle);
      }
      throw new TypeError(
        'Unsupported string privateKey: supply an Ed25519 PKCS#8 PEM or 32-byte hex seed'
      );
    })();
    if (useCache) {
      if (PEM_KEY_CACHE.size >= MAX_KEY_CACHE_ENTRIES) {
        const oldest = PEM_KEY_CACHE.keys().next().value;
        PEM_KEY_CACHE.delete(oldest);
      }
      PEM_KEY_CACHE.set(trimmed, promise);
      promise.catch(() => PEM_KEY_CACHE.delete(trimmed));
    }
    return promise;
  }

  if (isByteArray(privateKey)) {
    const u8 = asUint8Array(privateKey);
    if (u8.length === 32) {
      return importPkcs8Ed25519(wrapSeedAsPkcs8(u8), subtle);
    }
    if (u8.length === 48) {
      return importPkcs8Ed25519(u8, subtle);
    }
    throw new TypeError(`Ed25519 byte privateKey must be a 32-byte seed or 48-byte PKCS#8 DER, got ${u8.length} bytes`);
  }

  if (typeof privateKey === 'object') {
    // Ed25519 JWK
    if (privateKey.kty === 'OKP' && privateKey.crv === 'Ed25519' && typeof privateKey.d === 'string') {
      const seed = base64UrlToBytes(privateKey.d);
      if (seed.length !== 32) {
        throw new TypeError('Ed25519 JWK private scalar d must decode to 32 bytes');
      }
      const imported = await importPkcs8Ed25519(wrapSeedAsPkcs8(seed), subtle);
      if (typeof privateKey.x === 'string' && privateKey.x !== imported.publicKeyJwk.x) {
        throw new TypeError('Ed25519 JWK public coordinate x does not match private scalar d');
      }
      return imported;
    }

    // { privateKey: CryptoKey, publicKey?: ... } bundle (supports non-extractable CryptoKey)
    if (privateKey.privateKey && typeof privateKey.privateKey === 'object' && privateKey.privateKey.type === 'private') {
      const ck = privateKey.privateKey;
      if (privateKey.publicKey !== undefined) {
        const pubB64 = await resolvePublicKeyInput(privateKey.publicKey, subtle);
        return { cryptoKey: ck, publicKey: pubB64 };
      }
      if (ck.extractable) {
        const jwk = await subtle.exportKey('jwk', ck);
        const rawPub = base64UrlToBytes(jwk.x);
        return { cryptoKey: ck, publicKey: bytesToBase64(rawPub) };
      }
      throw new TypeError('Non-extractable CryptoKey requires { privateKey, publicKey }');
    }

    // Direct WebCrypto CryptoKey
    if (privateKey.type === 'private') {
      const algName = privateKey.algorithm && typeof privateKey.algorithm === 'object'
        ? privateKey.algorithm.name
        : '';
      if (algName && String(algName).toLowerCase() !== 'ed25519') {
        throw new TypeError(`Expected Ed25519 CryptoKey, got ${algName}`);
      }
      if (!privateKey.extractable) {
        throw new TypeError('Non-extractable CryptoKey requires passing { privateKey, publicKey }');
      }
      const jwk = await subtle.exportKey('jwk', privateKey);
      const rawPub = base64UrlToBytes(jwk.x);
      if (rawPub.length !== 32) {
        throw new Error('Derived Ed25519 public key did not produce 32 bytes');
      }
      return { cryptoKey: privateKey, publicKey: bytesToBase64(rawPub) };
    }
  }

  throw new TypeError(
    'Unsupported privateKey format: supply PKCS#8 PEM, 32-byte seed, Ed25519 JWK, or WebCrypto CryptoKey'
  );
}

export function normalizeTransactionId(rawTx) {
  if (rawTx === null || rawTx === undefined) return null;
  const s = String(rawTx);
  if (EVM_TX_HASH_RE.test(s)) return s.toLowerCase();
  if (SOLANA_TX_SIG_RE.test(s)) return s;
  throw new TypeError(
    `settlement.transactionHash must be 0x + 64 hex chars (EVM), 64-88 base58 chars (Solana), or null, got ${rawTx}`
  );
}

/**
 * Compute lowercase 0x-prefixed SHA-256 digest using WebCrypto `crypto.subtle.digest`.
 */
export async function sha256Hex(input, opts = {}) {
  const webCrypto = getWebCrypto(opts?.crypto);
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : asUint8Array(input);
  const digest = await webCrypto.subtle.digest('SHA-256', bytes);
  return '0x' + bytesToHex(new Uint8Array(digest));
}

/**
 * Compute lowercase 0x-prefixed SHA-256 digest of the canonical JSON representation of `value`.
 */
export async function hashCanonical(value, opts = {}) {
  const encoded = utf8ToBytes(canonicalize(value));
  return sha256Hex(encoded, opts);
}

/**
 * Derive the canonical 32-byte base64 Ed25519 public key from any supported private key input.
 */
export async function publicKeyFromPrivateKey(privateKey, opts = {}) {
  const webCrypto = getWebCrypto(opts?.crypto);
  const resolved = await resolveWebPrivateKey(privateKey, webCrypto);
  return resolved.publicKey;
}

/**
 * Generate a fresh Ed25519 signing keypair via WebCrypto (`crypto.subtle.generateKey`).
 */
export async function generateReceiptKeyPair(opts = {}) {
  const isStringOpt = typeof opts === 'string';
  const safeOpts = !isStringOpt && opts && typeof opts === 'object' ? opts : {};
  const webCrypto = getWebCrypto(safeOpts.crypto);
  const keyId = isStringOpt ? opts : (safeOpts.keyId ?? `key_${randomHex(6, webCrypto)}`);

  const { publicKey, privateKey } = await webCrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );
  const rawPub = new Uint8Array(await webCrypto.subtle.exportKey('raw', publicKey));
  const pkcs8Der = new Uint8Array(await webCrypto.subtle.exportKey('pkcs8', privateKey));
  const pubJwk = await webCrypto.subtle.exportKey('jwk', publicKey);

  return {
    keyId,
    algorithm: 'ed25519',
    publicKey: bytesToBase64(rawPub),
    privateKeyPem: formatPemBlock('PRIVATE KEY', pkcs8Der),
    publicKeyJwk: { ...pubJwk, kid: keyId }
  };
}

async function resolveDigestOrValueAsync(explicitHash, value, fallbackEmpty, cryptoOpt) {
  if (typeof explicitHash === 'string') {
    const normalized = explicitHash.toLowerCase();
    if (!SHA256_HEX_RE.test(normalized)) {
      throw new TypeError(`Invalid sha256Hex digest: ${explicitHash}`);
    }
    return normalized;
  }
  if (value === undefined) {
    return sha256Hex(utf8ToBytes(fallbackEmpty), cryptoOpt);
  }
  if (isByteArray(value)) {
    return sha256Hex(asUint8Array(value), cryptoOpt);
  }
  if (typeof value === 'string') {
    return sha256Hex(utf8ToBytes(value), cryptoOpt);
  }
  return hashCanonical(value, cryptoOpt);
}

/**
 * Issue and Ed25519-sign a schema-valid `paxiom.receipt.v0` receipt using pure WebCrypto.
 */
export async function issueReceipt({
  privateKey,
  receiptId,
  issuedAt = new Date().toISOString(),
  expiresAt,
  issuer,
  service,
  request = {},
  payment = {},
  output,
  outputHash: explicitOutputHash,
  mimeType = 'application/json',
  canonicalization: explicitCanonicalization,
  statusCode,
  evidence,
  crypto: explicitCrypto
} = {}) {
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('issuer.name and issuer.keyId are required');
  }
  if (!service || !service.name || !service.resource || !service.method) {
    throw new TypeError('service.name, service.resource, and service.method are required');
  }

  const webCrypto = getWebCrypto(explicitCrypto);
  const cryptoOpt = { crypto: webCrypto };
  const effectiveReceiptId = receiptId ?? defaultReceiptId(webCrypto);

  const { cryptoKey, publicKey } = await resolveWebPrivateKey(privateKey, webCrypto);

  const method = String(request.method || service.method).toUpperCase();
  const resource = String(request.resource || service.resource);
  const resourceHash = await resolveDigestOrValueAsync(request.resourceHash, resource, '', cryptoOpt);
  const bodyHash = await resolveDigestOrValueAsync(request.bodyHash, request.body, '', cryptoOpt);
  const requestHash = request.requestHash
    ? await resolveDigestOrValueAsync(request.requestHash, undefined, '', cryptoOpt)
    : await hashCanonical({ bodyHash, method, resource }, cryptoOpt);

  const paymentRequirementsHash = await resolveDigestOrValueAsync(
    payment.paymentRequirementsHash,
    payment.paymentRequirements,
    'none',
    cryptoOpt
  );
  const paymentPayloadHash = await resolveDigestOrValueAsync(
    payment.paymentPayloadHash,
    payment.paymentPayload,
    'none',
    cryptoOpt
  );

  const settlementInput = payment.settlement || {};
  const txHash = normalizeTransactionId(settlementInput.transactionHash);
  const checkedByVerifier = Boolean(
    settlementInput.checkedByVerifier ?? settlementInput.checkedByPaxiom ?? false
  );

  const settlement = {
    status: settlementInput.status || (txHash ? 'claimed_not_checked' : 'not_required'),
    transactionHash: txHash,
    checkedByVerifier,
    ...(settlementInput.verifier !== undefined ? { verifier: settlementInput.verifier } : {}),
    ...(Object.hasOwn(settlementInput, 'checkedByPaxiom')
      ? { checkedByPaxiom: Boolean(settlementInput.checkedByPaxiom) }
      : {})
  };

  const isRawBytes = isByteArray(output);
  let canonicalizationMode = explicitCanonicalization || (isRawBytes ? 'raw-sha256' : undefined);
  if (canonicalizationMode && canonicalizationMode !== 'jcs-sha256' && canonicalizationMode !== 'raw-sha256') {
    throw new TypeError(`Invalid canonicalization mode: ${canonicalizationMode}`);
  }

  let computedOutputHash;
  if (explicitOutputHash) {
    computedOutputHash = await resolveDigestOrValueAsync(explicitOutputHash, undefined, '', cryptoOpt);
  } else if (output !== undefined) {
    if (canonicalizationMode === 'raw-sha256') {
      if (isRawBytes) {
        computedOutputHash = await sha256Hex(asUint8Array(output), cryptoOpt);
      } else if (typeof output === 'string') {
        computedOutputHash = await sha256Hex(utf8ToBytes(output), cryptoOpt);
      } else {
        throw new TypeError('canonicalization="raw-sha256" requires Uint8Array or string output');
      }
    } else {
      computedOutputHash = await hashCanonical(output, cryptoOpt);
      if (!canonicalizationMode) canonicalizationMode = 'jcs-sha256';
    }
  } else {
    throw new TypeError('Either output or outputHash is required to issue a receipt');
  }

  const issuerObj = {
    name: String(issuer.name),
    keyId: String(issuer.keyId),
    ...(issuer.uri ? { uri: String(issuer.uri) } : {}),
    ...(issuer.payTo ? { payTo: String(issuer.payTo) } : {}),
    ...(issuer.keysUri ? { keysUri: String(issuer.keysUri) } : {})
  };

  const deliveryObj = {
    outputHash: computedOutputHash,
    mimeType: String(mimeType),
    ...(canonicalizationMode ? { canonicalization: canonicalizationMode } : {}),
    ...(statusCode !== undefined && statusCode !== null ? { statusCode: Number(statusCode) } : {})
  };

  const payload = {
    receiptId: String(effectiveReceiptId),
    issuedAt: issuedAt instanceof Date ? issuedAt.toISOString() : String(issuedAt),
    ...(expiresAt ? { expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : String(expiresAt) } : {}),
    issuer: issuerObj,
    service: {
      name: String(service.name),
      resource: String(service.resource),
      method: String(service.method).toUpperCase()
    },
    request: {
      requestHash,
      resourceHash,
      bodyHash
    },
    payment: {
      scheme: String(payment.scheme || 'x402'),
      network: String(payment.network || 'eip155:8453'),
      asset: String(payment.asset || 'USDC'),
      amountAtomic: String(payment.amountAtomic ?? '0'),
      amountDisplay: String(payment.amountDisplay ?? '0'),
      ...(payment.payer ? { payer: String(payment.payer) } : {}),
      ...(payment.payTo ? { payTo: String(payment.payTo) } : {}),
      paymentRequirementsHash,
      paymentPayloadHash,
      settlement
    },
    delivery: deliveryObj,
    evidence: Array.isArray(evidence) && evidence.length > 0
      ? evidence
      : [{ type: 'none', status: 'not_provided', hash: null, uri: null }]
  };

  const inputBytes = signingInputBytes({
    receiptVersion: RECEIPT_VERSION,
    payload
  });
  const sigBuf = new Uint8Array(
    await webCrypto.subtle.sign({ name: 'Ed25519' }, cryptoKey, inputBytes)
  );

  const receipt = {
    receiptVersion: RECEIPT_VERSION,
    payload,
    signature: {
      algorithm: 'ed25519',
      keyId: issuerObj.keyId,
      publicKey,
      value: bytesToBase64(sigBuf)
    }
  };

  const receiptHeader = bytesToBase64Url(utf8ToBytes(JSON.stringify(receipt)));
  return { receipt, receiptHeader };
}

/**
 * Decode a base64url `Payment-Receipt` or `X-Paxiom-Receipt` HTTP header back into a receipt object.
 */
export function decodeReceiptHeader(headerValue) {
  if (typeof headerValue !== 'string' || !headerValue.trim()) {
    throw new TypeError('Receipt header must be a non-empty base64url string');
  }
  return JSON.parse(bytesToUtf8(base64UrlToBytes(headerValue.trim())));
}

const CHECK = { PASS: 'pass', FAIL: 'fail', SKIP: 'not_checked' };

/**
 * Verify a `paxiom.receipt.v0` receipt offline using pure WebCrypto (`crypto.subtle.verify`).
 * Deterministic and never throws.
 */
export async function verifyReceipt(receipt, opts = {}) {
  const safeOpts = opts && typeof opts === 'object' ? opts : {};
  const hasOutput = Object.prototype.hasOwnProperty.call(safeOpts, 'output') && safeOpts.output !== undefined;
  const hasExpectedKeys = Array.isArray(safeOpts.expectedIssuerPublicKeys) || safeOpts.expectedIssuerPublicKeys instanceof Set;
  const hasExpectedPayTo = typeof safeOpts.expectedPayTo === 'string' && safeOpts.expectedPayTo.trim() !== '';

  const checks = {
    schema: CHECK.SKIP,
    signature: CHECK.SKIP,
    issuerAuthorization: (hasExpectedKeys || hasExpectedPayTo) ? CHECK.SKIP : 'unpinned',
    outputHash: hasOutput ? CHECK.SKIP : 'not_provided',
    requestBinding: CHECK.SKIP,
    paymentBinding: CHECK.SKIP,
    settlement: CHECK.SKIP,
    proof: CHECK.SKIP
  };
  let receiptHash = null;
  const done = (trustState, summary) => ({
    valid: trustState === 'verified',
    trustState,
    checks,
    receiptHash,
    summary
  });

  let webCrypto;
  try {
    webCrypto = getWebCrypto(safeOpts.crypto);
  } catch (err) {
    return done('error', String((err && err.message) || err));
  }
  const cryptoOpt = { crypto: webCrypto };

  // (1) version gate
  if (!receipt || receipt.receiptVersion !== RECEIPT_VERSION) {
    return done(
      'unsupported_format',
      `Unsupported receiptVersion: ${receipt && receipt.receiptVersion}. Expected ${RECEIPT_VERSION}.`
    );
  }

  // (2) schema
  const schemaErrs = validateReceiptSchema(receipt, RECEIPT_SCHEMA, 'receipt', RECEIPT_SCHEMA);
  if (schemaErrs.length) {
    checks.schema = CHECK.FAIL;
    return done('schema_invalid', `Receipt does not conform to ${RECEIPT_VERSION} schema: ${schemaErrs[0]}.`);
  }
  checks.schema = CHECK.PASS;

  let input;
  try {
    input = signingInputBytes(receipt);
    receiptHash = await sha256Hex(input, cryptoOpt);
  } catch (err) {
    return done('error', `Failed to canonicalize signing input: ${(err && err.message) || err}.`);
  }

  // (3) signature + keyId consistency + strict RFC 8032 S < L check
  if (receipt.payload.issuer.keyId !== receipt.signature.keyId) {
    checks.signature = CHECK.FAIL;
    return done(
      'invalid_signature',
      `payload.issuer.keyId (${receipt.payload.issuer.keyId}) does not match signature.keyId (${receipt.signature.keyId}).`
    );
  }

  let sigOk = false;
  try {
    const rawPub = strictDecodeBase64Bytes(receipt.signature.publicKey, 32, 'Ed25519 publicKey');
    const sigBuf = strictDecodeBase64Bytes(receipt.signature.value, 64, 'Ed25519 signature.value');
    if (isCanonicalEd25519Scalar(sigBuf)) {
      const pubCryptoKey = await webCrypto.subtle.importKey(
        'raw',
        rawPub,
        { name: 'Ed25519' },
        false,
        ['verify']
      );
      sigOk = await webCrypto.subtle.verify({ name: 'Ed25519' }, pubCryptoKey, sigBuf, input);
    }
  } catch {
    sigOk = false;
  }

  if (!sigOk) {
    checks.signature = CHECK.FAIL;
    return done('invalid_signature', 'Ed25519 signature does not verify over the canonical signing input.');
  }
  checks.signature = CHECK.PASS;

  const p = receipt.payload;

  // (4) signer authorization
  if (hasExpectedKeys) {
    const allowedSet = new Set(safeOpts.expectedIssuerPublicKeys);
    if (!allowedSet.has(receipt.signature.publicKey)) {
      checks.issuerAuthorization = CHECK.FAIL;
      return done(
        'unauthorized_issuer',
        'Receipt signature is valid, but signature.publicKey is not in expectedIssuerPublicKeys for this resource.'
      );
    }
  }
  if (hasExpectedPayTo) {
    const wantPayTo = normalizePayToId(safeOpts.expectedPayTo);
    const receiptPayTo = p.payment.payTo || p.issuer.payTo || null;
    if (!receiptPayTo || normalizePayToId(receiptPayTo) !== wantPayTo) {
      checks.issuerAuthorization = CHECK.FAIL;
      return done(
        'unauthorized_issuer',
        receiptPayTo
          ? `Receipt payTo (${receiptPayTo}) does not match expectedPayTo (${safeOpts.expectedPayTo}).`
          : `Caller pinned expectedPayTo (${safeOpts.expectedPayTo}), but receipt does not bind a payTo address.`
      );
    }
  }
  if (hasExpectedKeys || hasExpectedPayTo) {
    checks.issuerAuthorization = CHECK.PASS;
  }

  // (5) expiry
  const nowMs = safeOpts.now !== undefined
    ? (safeOpts.now instanceof Date
      ? safeOpts.now.getTime()
      : typeof safeOpts.now === 'number'
      ? safeOpts.now
      : Date.parse(String(safeOpts.now)))
    : Date.now();
  if (p.expiresAt && Date.parse(p.expiresAt) < nowMs) {
    return done('expired', `Receipt expired at ${p.expiresAt}.`);
  }

  // (6)(7) bindings
  checks.requestBinding = CHECK.PASS;
  checks.paymentBinding = CHECK.PASS;

  // (8) output hash
  if (hasOutput) {
    let recomputed;
    const mode = p.delivery.canonicalization || 'jcs-sha256';
    try {
      if (mode === 'raw-sha256') {
        if (isByteArray(safeOpts.output)) {
          recomputed = await sha256Hex(asUint8Array(safeOpts.output), cryptoOpt);
        } else if (typeof safeOpts.output === 'string') {
          recomputed = await sha256Hex(utf8ToBytes(safeOpts.output), cryptoOpt);
        } else {
          throw new TypeError('delivery.canonicalization="raw-sha256" requires Uint8Array or string output');
        }
      } else {
        recomputed = await hashCanonical(safeOpts.output, cryptoOpt);
      }
    } catch (err) {
      checks.outputHash = 'error';
      return done('error', `Could not hash supplied output (${mode}): ${(err && err.message) || err}.`);
    }
    if (recomputed !== p.delivery.outputHash) {
      checks.outputHash = CHECK.FAIL;
      return done(
        'output_hash_mismatch',
        `Supplied output hash ${recomputed} != receipt delivery.outputHash ${p.delivery.outputHash}.`
      );
    }
    checks.outputHash = CHECK.PASS;
  }

  // proof/evidence interpretation
  const evidence = p.evidence || [];
  const anyInvalid = evidence.some((e) => e.status === 'invalid');
  const anyUnavailable = evidence.some((e) => e.status === 'unavailable');
  const anyProvided = evidence.some((e) => e.type !== 'none' && e.status !== 'not_provided');
  checks.proof = anyInvalid ? 'invalid'
    : anyUnavailable ? 'unavailable'
    : anyProvided ? 'provided'
    : 'not_provided';

  const st = p.payment.settlement.status;
  checks.settlement = st;

  // (9) settlement failed
  if (st === 'failed') return done('settlement_failed', 'Receipt reports a failed settlement.');

  // (10) evidence retrieved-and-invalid / referenced-but-unreachable
  if (anyInvalid) return done('proof_invalid', 'A provided evidence record failed verification.');
  if (anyUnavailable) return done('proof_unavailable', 'A referenced evidence record could not be retrieved.');

  // (10.5) Optional offline cryptographic proofs (EIP-1186 state claimProof & EVM receipt-trie settlementProof)
  const rawTrustedKeys = safeOpts.trustedVerifierPublicKeys || safeOpts.trustedPaxiomPublicKeys || null;
  const rawRootKeys = safeOpts.trustedRootPublicKeys || rawTrustedKeys || null;
  const rawAtt =
    safeOpts.rootAttestation ||
    (safeOpts.settlementProof && safeOpts.settlementProof.rootAttestation) ||
    (safeOpts.claimProof && safeOpts.claimProof.rootAttestation) ||
    null;

  let verifiedRootAtt = null;
  let rootAttErr = null;
  if (rawAtt) {
    if (!rawRootKeys) {
      rootAttErr = {
        code: 'untrusted_root_signer',
        reason: 'rootAttestation supplied without trustedRootPublicKeys or trustedVerifierPublicKeys.'
      };
    } else {
      const attCheck = await verifyRootAttestation(rawAtt, {
        trustedRootPublicKeys: rawRootKeys,
        allowedFinalityTiers: safeOpts.allowedFinalityTiers,
        now: nowMs,
        crypto: webCrypto
      });
      if (attCheck.ok) {
        verifiedRootAtt = attCheck;
      } else {
        rootAttErr = attCheck;
      }
    }
  } else if (safeOpts.allowedFinalityTiers && !Array.isArray(safeOpts.allowedFinalityTiers)) {
    return done('error', `allowedFinalityTiers must be an array of: ${ALLOWED_FINALITY_TIERS.join(', ')}`);
  }

  let offlineProofSettled = false;
  let unanchoredProofNote = null;
  if (safeOpts.claimProof !== undefined || safeOpts.settlementProof !== undefined) {
    const proofEval = evaluateReceiptOfflineProofsSync({
      receipt,
      opts: safeOpts,
      verifiedRootAttestation: verifiedRootAtt,
      rootAttestationError: rootAttErr
    });
    if (proofEval.outcome === 'fail') {
      if (proofEval.checkSettlement) checks.settlement = proofEval.checkSettlement;
      if (proofEval.checkProof) checks.proof = proofEval.checkProof;
      return done(proofEval.trustState, proofEval.summary);
    }
    if (proofEval.outcome === 'verified_settled') {
      offlineProofSettled = true;
      checks.settlement = 'verified_settled';
      checks.proof = 'verified';
    } else if (proofEval.outcome === 'unanchored_settlement_proof') {
      checks.proof = proofEval.checkProof;
      unanchoredProofNote = proofEval.summary;
    } else if (proofEval.outcome === 'claim_verified') {
      checks.proof = 'verified';
    }
  }

  // (11) unconfirmed onchain settlement or untrusted counter-verifier claim
  const trustedVerifierSet = rawTrustedKeys ? new Set(rawTrustedKeys) : null;
  const isTrustedVerifierSigner = Boolean(trustedVerifierSet && trustedVerifierSet.has(receipt.signature.publicKey));
  const assertsVerifierCheck = Boolean(p.payment.settlement.checkedByVerifier || p.payment.settlement.checkedByPaxiom);

  if (!offlineProofSettled) {
    if (assertsVerifierCheck && !isTrustedVerifierSigner) {
      return done(
        'settlement_claimed_not_checked',
        unanchoredProofNote ||
          'Receipt asserts independent verifier settlement check, but signer is not in trustedVerifierPublicKeys.'
      );
    }
    if (
      (st === 'not_required' || st === 'disabled' || st === 'verify_only') &&
      p.payment.settlement.transactionHash !== null
    ) {
      return done(
        'settlement_claimed_not_checked',
        unanchoredProofNote ||
          'Receipt carries a non-null settlement.transactionHash under a non-settled status that this offline verifier did not check.'
      );
    }
    const counterVerified = st === 'verified_settled' && assertsVerifierCheck && isTrustedVerifierSigner;
    if (st === 'claimed_not_checked' || (st === 'verified_settled' && !counterVerified)) {
      return done(
        'settlement_claimed_not_checked',
        unanchoredProofNote ||
          (hasOutput
            ? 'Signature and output hash verified. Receipt claims an onchain settlement that this offline verifier did not check.'
            : 'Signature verified. Receipt claims an onchain settlement that this offline verifier did not check.')
      );
    }
  }

  // (12) output not supplied, or settlement unknown
  if (!hasOutput) {
    return done(
      'valid_signature_only',
      'Signature valid. No output supplied, so payment-to-output binding was not checked.'
    );
  }
  if (st === 'unknown' && !offlineProofSettled) {
    return done('valid_signature_only', 'Signature and output verified, but settlement status is unknown.');
  }

  // (13) verified
  const effectiveSettlement = offlineProofSettled ? 'verified_settled (offline MPT proof)' : st;
  return done(
    'verified',
    `Receipt verified: schema, Ed25519 signature, output binding, and settlement (${effectiveSettlement}) all consistent.`
  );
}

function extractHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function normalizeCaip2Network(rawNet) {
  if (!rawNet || typeof rawNet !== 'string') return null;
  const trimmed = rawNet.trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'base' || lower === 'base-mainnet') return 'eip155:8453';
  if (lower === 'base-sepolia') return 'eip155:84532';
  if (lower === 'ethereum' || lower === 'mainnet' || lower === 'eth') return 'eip155:1';
  if (lower === 'sepolia' || lower === 'ethereum-sepolia') return 'eip155:11155111';
  if (lower === 'arbitrum' || lower === 'arbitrum-one') return 'eip155:42161';
  if (lower === 'arbitrum-sepolia') return 'eip155:421614';
  if (lower === 'optimism' || lower === 'op-mainnet') return 'eip155:10';
  if (lower === 'polygon' || lower === 'polygon-pos') return 'eip155:137';
  if (lower === 'arc' || lower === 'arc-mainnet') return 'eip155:5042';
  if (lower === 'arc-testnet') return 'eip155:5042002';
  if (lower === 'solana' || lower === 'solana-mainnet') return 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
  if (lower === 'solana-devnet') return 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
  if (lower.startsWith('eip155:')) return lower;
  return trimmed;
}

function formatUsdcDisplay(atomicStr) {
  if (!DEC_UINT_RE.test(atomicStr)) return '0';
  const n = BigInt(atomicStr);
  const whole = n / 1000000n;
  const frac = (n % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}

/**
 * Parse x402 v1 / v2 HTTP headers (`PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`, `PAYMENT-REQUIRED`)
 * into normalized CAIP-2 payment & settlement fields without Node `Buffer`.
 */
export function parseX402Headers(arg1 = {}, responseHeaders = null) {
  let paymentSignature = '';
  let paymentResponse = '';
  let paymentRequired = '';
  if (
    responseHeaders !== null ||
    typeof arg1?.get === 'function' ||
    (arg1 &&
      typeof arg1 === 'object' &&
      !Object.hasOwn(arg1, 'paymentSignature') &&
      !Object.hasOwn(arg1, 'paymentResponse') &&
      !Object.hasOwn(arg1, 'paymentRequired'))
  ) {
    paymentSignature = extractHeader(arg1, 'payment-signature') || extractHeader(arg1, 'x-payment') || '';
    paymentRequired = extractHeader(arg1, 'payment-required') || extractHeader(responseHeaders, 'payment-required') || '';
    paymentResponse =
      extractHeader(responseHeaders, 'payment-response') ||
      extractHeader(responseHeaders, 'x-payment-response') ||
      extractHeader(arg1, 'payment-response') ||
      '';
  } else if (arg1 && typeof arg1 === 'object') {
    paymentSignature = arg1.paymentSignature || '';
    paymentResponse = arg1.paymentResponse || '';
    paymentRequired = arg1.paymentRequired || '';
  }

  const sigObj = decodeFlexibleBase64JsonObject(paymentSignature);
  const resObj = decodeFlexibleBase64JsonObject(paymentResponse);
  const reqObj = decodeFlexibleBase64JsonObject(paymentRequired);

  const accepted =
    (sigObj && typeof sigObj.accepted === 'object' && sigObj.accepted) ||
    (reqObj && Array.isArray(reqObj.accepts) && reqObj.accepts[0]) ||
    null;
  const auth =
    (sigObj && sigObj.payload && typeof sigObj.payload.authorization === 'object' && sigObj.payload.authorization) ||
    null;

  let txHash = null;
  if (resObj) {
    const rawTx = resObj.transaction || resObj.txHash || resObj.transactionHash || null;
    if (typeof rawTx === 'string' && rawTx.trim()) {
      try {
        txHash = normalizeTransactionId(rawTx.trim());
      } catch {
        txHash = null;
      }
    }
  }

  const rawNetwork =
    (resObj && (resObj.network || resObj.networkId)) ||
    (accepted && accepted.network) ||
    (sigObj && sigObj.network) ||
    null;
  const network = normalizeCaip2Network(rawNetwork);

  const scheme = (accepted && accepted.scheme) || (sigObj && sigObj.scheme) || null;
  const asset = (accepted && accepted.asset) || null;
  const rawAmount =
    (accepted && (accepted.amount ?? accepted.maxAmountRequired)) ??
    (auth && auth.value) ??
    null;
  const amountAtomic =
    rawAmount !== null && rawAmount !== undefined && DEC_UINT_RE.test(String(rawAmount))
      ? String(rawAmount)
      : null;

  const payTo = (accepted && accepted.payTo) || (auth && auth.to) || null;
  const payer = (resObj && resObj.payer) || (auth && auth.from) || null;
  const settlementFailed = Boolean(resObj && resObj.success === false);

  return {
    txHash,
    transactionHash: txHash,
    settlementFailed,
    network,
    scheme: typeof scheme === 'string' && scheme ? scheme : null,
    asset: typeof asset === 'string' && asset ? asset : null,
    amountAtomic,
    amountDisplay: amountAtomic ? formatUsdcDisplay(amountAtomic) : null,
    payer: typeof payer === 'string' && payer ? payer : null,
    payTo: typeof payTo === 'string' && payTo ? payTo : null
  };
}

function isJsonContentType(ct) {
  return !ct || ct === 'application/json' || ct.endsWith('+json');
}

function appendExposeHeaders(existing, headerNames) {
  const cur = existing ? String(existing) : '';
  const parts = cur ? cur.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const lowerSet = new Set(parts.map((s) => s.toLowerCase()));
  for (const h of headerNames) {
    if (!lowerSet.has(h.toLowerCase())) {
      parts.push(h);
      lowerSet.add(h.toLowerCase());
    }
  }
  return parts.join(', ');
}

/**
 * Wrap a Web Standard `(request: Request, ...rest) => Promise<Response>` handler (Cloudflare
 * Workers, Hono, Vercel Edge, Deno Deploy, Bun) using pure WebCrypto (`crypto.subtle`).
 */
export function withPaxiomReceipt(handler, options = {}) {
  const {
    privateKey: rawPrivateKey,
    privateKeyPem,
    issuer,
    serviceName,
    paymentDefaults = {},
    resolvePayment,
    onReceipt,
    crypto: explicitCrypto
  } = options;
  const privateKey = rawPrivateKey || privateKeyPem;
  if (!privateKey) throw new TypeError('withPaxiomReceipt requires options.privateKey');
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('withPaxiomReceipt requires options.issuer { name, keyId }');
  }

  return async function paxiomWebWrappedFetchHandler(request, ...rest) {
    const clonedReq = request.clone();
    const rawReqBytes = new Uint8Array(await clonedReq.arrayBuffer());
    const response = await handler(request, ...rest);

    if (!response || response.status < 200 || response.status >= 300) {
      return response;
    }
    if (rawReqBytes.byteLength > MAX_CAPTURE_BYTES) {
      return response;
    }

    const rawResBytes = new Uint8Array(await response.clone().arrayBuffer());
    if (rawResBytes.byteLength > MAX_CAPTURE_BYTES) {
      return response;
    }

    const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    const jsonMode = isJsonContentType(contentType);
    let outputForIssue;
    let canonicalization;
    if (jsonMode) {
      try {
        outputForIssue = JSON.parse(bytesToUtf8(rawResBytes));
        canonicalization = 'jcs-sha256';
      } catch {
        if (!contentType) {
          outputForIssue = rawResBytes;
          canonicalization = 'raw-sha256';
        } else {
          return response;
        }
      }
    } else {
      outputForIssue = rawResBytes;
      canonicalization = 'raw-sha256';
    }

    const paymentSigHeader =
      extractHeader(request.headers, 'payment-signature') ||
      extractHeader(request.headers, 'x-payment') ||
      '';
    const paymentResHeader =
      extractHeader(response.headers, 'payment-response') ||
      extractHeader(response.headers, 'x-payment-response') ||
      '';
    const paymentReqHeader = extractHeader(response.headers, 'payment-required') || '';
    const parsedX402 = parseX402Headers({
      paymentSignature: paymentSigHeader,
      paymentResponse: paymentResHeader,
      paymentRequired: paymentReqHeader
    });
    const txHash = parsedX402.txHash;

    const dynamicPayment = typeof resolvePayment === 'function'
      ? await resolvePayment({ request, response, txHash, parsedX402 })
      : {};

    const payment = {
      scheme: parsedX402.scheme || 'x402',
      network: parsedX402.network || 'eip155:8453',
      asset: parsedX402.asset || 'USDC',
      amountAtomic: parsedX402.amountAtomic || '0',
      amountDisplay: parsedX402.amountDisplay || '0',
      ...(parsedX402.payer ? { payer: parsedX402.payer } : {}),
      ...(parsedX402.payTo ? { payTo: parsedX402.payTo } : {}),
      ...(paymentReqHeader ? { paymentRequirements: paymentReqHeader } : {}),
      paymentPayload: paymentSigHeader || 'none',
      ...paymentDefaults,
      ...dynamicPayment,
      settlement: {
        status: parsedX402.settlementFailed
          ? 'failed'
          : (txHash ? 'claimed_not_checked' : (paymentSigHeader ? 'verify_only' : 'not_required')),
        transactionHash: txHash,
        checkedByVerifier: false,
        ...(paymentDefaults.settlement || {}),
        ...(dynamicPayment && dynamicPayment.settlement ? dynamicPayment.settlement : {})
      }
    };

    const { receipt, receiptHeader } = await issueReceipt({
      privateKey,
      issuer,
      service: {
        name: serviceName || issuer.name,
        resource: request.url,
        method: request.method
      },
      request: {
        method: request.method,
        resource: request.url,
        body: rawReqBytes.length > 0 ? rawReqBytes : ''
      },
      payment,
      output: outputForIssue,
      mimeType: contentType || (canonicalization === 'jcs-sha256' ? 'application/json' : 'application/octet-stream'),
      canonicalization,
      statusCode: response.status,
      crypto: explicitCrypto
    });

    if (typeof onReceipt === 'function') {
      Promise.resolve(onReceipt(receipt)).catch(() => {});
    }

    const headers = new Headers(response.headers);
    headers.set(STANDARD_RECEIPT_HEADER_NAME, receiptHeader);
    headers.set(RECEIPT_HEADER_NAME, receiptHeader);
    headers.set(
      'access-control-expose-headers',
      appendExposeHeaders(headers.get('access-control-expose-headers'), [
        'Payment-Receipt',
        'X-Paxiom-Receipt'
      ])
    );

    return new Response(rawResBytes, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  };
}

function isLoopbackHttpHost(hostname) {
  const bare = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  return bare === '127.0.0.1' || bare === 'localhost' || bare === '::1';
}

export function resolveSafeApiOrigin(rawBaseUrl = DEFAULT_PAXIOM_API_URL) {
  if (typeof rawBaseUrl !== 'string' || !rawBaseUrl.trim()) {
    throw new TypeError('baseUrl must be a non-empty URL string');
  }
  let parsed;
  try {
    parsed = new URL(rawBaseUrl.trim());
  } catch {
    throw new TypeError(`Invalid baseUrl: ${rawBaseUrl}`);
  }
  if (parsed.username || parsed.password) {
    throw new TypeError('baseUrl must not contain embedded credentials');
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackHttpHost(parsed.hostname))) {
    throw new TypeError('baseUrl must use https:// (plaintext http:// is permitted only on loopback for local tests)');
  }
  return parsed.origin;
}

function extractHeaderValue(responseOrHeaders, headerName) {
  if (!responseOrHeaders || typeof responseOrHeaders !== 'object') return undefined;
  const targetHeaders =
    (Object.hasOwn(responseOrHeaders, 'headers') || typeof responseOrHeaders.headers === 'object') &&
    responseOrHeaders.headers
      ? responseOrHeaders.headers
      : responseOrHeaders;

  if (typeof targetHeaders.get === 'function') {
    const val = targetHeaders.get(headerName);
    return val === null || val === undefined ? undefined : String(val);
  }
  const lower = headerName.toLowerCase();
  for (const [k, v] of Object.entries(targetHeaders)) {
    if (k.toLowerCase() === lower && v !== undefined && v !== null) {
      return Array.isArray(v) ? String(v[0]) : String(v);
    }
  }
  return undefined;
}

async function readBoundedFetchResponse(
  fetchImpl,
  url,
  init,
  { timeoutMs = DEFAULT_CLIENT_TIMEOUT_MS, maxBytes = MAX_CLIENT_RESPONSE_BYTES } = {}
) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('No fetch implementation available; pass options.fetch');
  }
  const effectiveTimeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_CLIENT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), effectiveTimeout);
  try {
    const res = await fetchImpl(url, {
      ...init,
      redirect: 'manual',
      signal: controller.signal
    });

    if (res.status >= 300 && res.status < 400) {
      throw new Error(`Refusing HTTP ${res.status} redirect from endpoint`);
    }

    let bodyBytes = new Uint8Array(0);
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const u8 = asUint8Array(value);
        total += u8.byteLength;
        if (total > maxBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          throw new Error(`Response exceeded ${maxBytes} bytes`);
        }
        chunks.push(u8);
      }
      bodyBytes = concatBytes(chunks);
    } else if (typeof res.text === 'function') {
      const txt = await res.text();
      bodyBytes = utf8ToBytes(txt);
      if (bodyBytes.byteLength > maxBytes) {
        throw new Error(`Response exceeded ${maxBytes} bytes`);
      }
    }

    return {
      response: res,
      status: Number(res.status) || 0,
      bodyText: bytesToUtf8(bodyBytes)
    };
  } finally {
    clearTimeout(timer);
  }
}

function buildJsonHeaders({ apiKey, paymentHeader } = {}) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/json'
  };
  if (apiKey !== undefined && apiKey !== null && String(apiKey).trim() !== '') {
    headers['x-api-key'] = String(apiKey).trim();
  }
  if (paymentHeader !== undefined && paymentHeader !== null && String(paymentHeader).trim() !== '') {
    headers['payment-signature'] = String(paymentHeader).trim();
  }
  return headers;
}

function extractDidWebEd25519Keys(parsed) {
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.verificationMethod)) {
    return [];
  }
  const out = [];
  for (const vm of parsed.verificationMethod) {
    if (!vm || typeof vm !== 'object' || !vm.publicKeyJwk || typeof vm.publicKeyJwk !== 'object') {
      continue;
    }
    const jwk = vm.publicKeyJwk;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
      continue;
    }
    const xTrim = jwk.x.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(xTrim)) continue;
    let raw;
    try {
      raw = base64UrlToBytes(xTrim);
    } catch {
      continue;
    }
    if (raw.length !== 32 || bytesToBase64Url(raw) !== xTrim) continue;
    const publicKey = bytesToBase64(raw);
    if (!STRICT_BASE64_32_RE.test(publicKey)) continue;
    let keyId = typeof jwk.kid === 'string' && jwk.kid.trim() ? jwk.kid.trim() : '';
    if (!keyId && typeof vm.id === 'string') {
      const hashIdx = vm.id.indexOf('#');
      keyId = hashIdx >= 0 ? vm.id.slice(hashIdx + 1) : vm.id;
    }
    out.push({
      keyId: keyId || 'did-web-ed25519',
      algorithm: 'ed25519',
      publicKey
    });
  }
  return out;
}

/**
 * Discover authorized Ed25519 receipt signing keys for a seller origin via
 * `/.well-known/x402-keys.json`, W3C `did:web` (`/.well-known/did.json`), or
 * fallback `/.well-known/paxiom-keys.json` (zero `Buffer` dependencies).
 */
export async function discoverIssuerKeys(originOrResourceUrl, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const origin = resolveSafeApiOrigin(originOrResourceUrl);
  const fetchImpl = opts.fetch || opts.fetchImpl || globalThis.fetch;
  const paths = ['/.well-known/x402-keys.json', '/.well-known/did.json', '/.well-known/paxiom-keys.json'];

  for (const path of paths) {
    const url = `${origin}${path}`;
    const { status, bodyText } = await readBoundedFetchResponse(
      fetchImpl,
      url,
      { method: 'GET', headers: { accept: 'application/json' } },
      { timeoutMs: opts.timeoutMs, maxBytes: MAX_KEYS_RESPONSE_BYTES }
    );
    if (status === 404) continue;
    if (status < 200 || status >= 300) {
      return { ok: false, status, origin, keysUrl: url, keys: [], publicKeys: [] };
    }
    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      return { ok: false, status, origin, keysUrl: url, keys: [], publicKeys: [] };
    }
    const rawKeys = parsed && Array.isArray(parsed.keys) ? parsed.keys : [];
    const manifestKeys = rawKeys.filter((k) => {
      if (!k || typeof k !== 'object') return false;
      if (k.algorithm !== undefined && k.algorithm !== 'ed25519') return false;
      if (typeof k.publicKey !== 'string' || !STRICT_BASE64_32_RE.test(k.publicKey)) return false;
      try {
        return strictDecodeBase64Bytes(k.publicKey, 32, 'publicKey').length === 32;
      } catch {
        return false;
      }
    });
    const validKeys = manifestKeys.length > 0 ? manifestKeys : extractDidWebEd25519Keys(parsed);
    if (path === '/.well-known/did.json' && validKeys.length === 0) {
      continue;
    }
    const issuerVal = parsed && typeof parsed.issuer === 'string'
      ? parsed.issuer
      : (parsed && typeof parsed.id === 'string' ? parsed.id : null);
    return {
      ok: validKeys.length > 0,
      status,
      origin,
      keysUrl: url,
      issuer: issuerVal,
      payTo: parsed && typeof parsed.payTo === 'string' ? parsed.payTo : null,
      keys: validKeys,
      publicKeys: validKeys.map((k) => k.publicKey)
    };
  }
  return { ok: false, status: 404, origin, keysUrl: null, keys: [], publicKeys: [] };
}

/**
 * Inspect a Fetch `Response` or headers map for `Payment-Receipt` (or `X-Paxiom-Receipt`)
 * and verify it deterministically offline via WebCrypto. Never throws.
 */
export async function verifyResponseReceipt(responseOrHeaders, options = {}) {
  const stdHeader = extractHeaderValue(responseOrHeaders, STANDARD_RECEIPT_HEADER_NAME);
  const paxHeader = extractHeaderValue(responseOrHeaders, RECEIPT_HEADER_NAME);
  const cleanStd = stdHeader && stdHeader.trim() ? stdHeader.trim() : '';
  const cleanPax = paxHeader && paxHeader.trim() ? paxHeader.trim() : '';

  if (!cleanStd && !cleanPax) {
    return {
      present: false,
      valid: false,
      trustState: null,
      receipt: null,
      verdict: null
    };
  }

  if (cleanStd && cleanPax && cleanStd !== cleanPax) {
    return {
      present: true,
      valid: false,
      trustState: 'malformed_header',
      receipt: null,
      verdict: null,
      error: 'Conflicting Payment-Receipt and X-Paxiom-Receipt headers on response'
    };
  }

  const rawHeader = cleanStd || cleanPax;
  let receipt;
  try {
    receipt = decodeReceiptHeader(rawHeader);
  } catch (err) {
    return {
      present: true,
      valid: false,
      trustState: 'malformed_header',
      receipt: null,
      verdict: null,
      error: String((err && err.message) || err)
    };
  }

  const verifyOpts = {};
  if (options && typeof options === 'object') {
    if (Object.hasOwn(options, 'output') && options.output !== undefined) {
      verifyOpts.output = options.output;
    }
    if (options.expectedIssuerPublicKeys) {
      verifyOpts.expectedIssuerPublicKeys = options.expectedIssuerPublicKeys;
    }
    if (options.expectedPayTo) {
      verifyOpts.expectedPayTo = options.expectedPayTo;
    }
    if (options.crypto) {
      verifyOpts.crypto = options.crypto;
    }
    const trusted = options.trustedVerifierPublicKeys || options.trustedPaxiomPublicKeys;
    verifyOpts.trustedVerifierPublicKeys = Array.isArray(trusted)
      ? trusted
      : PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS;
  } else {
    verifyOpts.trustedVerifierPublicKeys = PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS;
  }

  const verdict = await verifyReceipt(receipt, verifyOpts);
  return {
    present: true,
    valid: verdict.valid,
    trustState: verdict.trustState,
    checks: verdict.checks,
    receipt,
    verdict
  };
}

/**
 * Run a pre-payment x402 seller readiness & USDC safety scan (`POST /v1/x402/preflight`)
 * using pure Web-standard `fetch` + WebCrypto receipt verification.
 */
export async function preflightX402(targetUrl, options = {}) {
  if (typeof targetUrl !== 'string' || !targetUrl.trim()) {
    throw new TypeError('targetUrl must be a non-empty https:// URL string');
  }
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl.trim());
  } catch {
    throw new TypeError(`Invalid targetUrl: ${targetUrl}`);
  }
  if (parsedTarget.protocol !== 'https:') {
    throw new TypeError('targetUrl must use https://');
  }

  const opts = options && typeof options === 'object' ? options : {};
  const origin = resolveSafeApiOrigin(opts.baseUrl ?? DEFAULT_PAXIOM_API_URL);
  const method = opts.method !== undefined ? String(opts.method).toUpperCase() : 'POST';
  if (!ALLOWED_PREFLIGHT_METHODS.has(method)) {
    throw new TypeError('options.method must be POST, GET, or HEAD');
  }

  const reqBody = { url: parsedTarget.toString(), method };
  if (opts.maxBudgetAtomic !== undefined && opts.maxBudgetAtomic !== null && opts.maxBudgetAtomic !== '') {
    const budgetStr = String(opts.maxBudgetAtomic);
    if (!DEC_UINT_RE.test(budgetStr)) {
      throw new TypeError('options.maxBudgetAtomic must be a non-negative base-10 integer string');
    }
    reqBody.maxBudgetAtomic = budgetStr;
  }
  if (opts.expectedNetwork !== undefined && opts.expectedNetwork !== null && opts.expectedNetwork !== '') {
    reqBody.expectedNetwork = String(opts.expectedNetwork);
  }

  const fetchImpl = opts.fetch || opts.fetchImpl || globalThis.fetch;
  const { response, status, bodyText } = await readBoundedFetchResponse(
    fetchImpl,
    `${origin}/v1/x402/preflight`,
    {
      method: 'POST',
      headers: buildJsonHeaders({ apiKey: opts.apiKey, paymentHeader: opts.paymentHeader }),
      body: JSON.stringify(reqBody)
    },
    { timeoutMs: opts.timeoutMs }
  );

  let bodyJson = null;
  try {
    bodyJson = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    bodyJson = null;
  }

  if (status === 402) {
    const headerChallenge = decodeFlexibleBase64JsonObject(extractHeaderValue(response, 'payment-required'));
    return {
      ok: false,
      status: 402,
      paymentRequired: true,
      challenge: headerChallenge || bodyJson,
      report: null,
      receiptVerification: null,
      paymentResponse: null
    };
  }

  if (status < 200 || status >= 300 || !bodyJson || typeof bodyJson !== 'object') {
    return {
      ok: false,
      status,
      paymentRequired: false,
      error: (bodyJson && bodyJson.error) || { code: 'preflight_http_error', message: `HTTP ${status}` },
      report: null,
      receiptVerification: null,
      paymentResponse: null
    };
  }

  const rawTrusted = opts.trustedVerifierPublicKeys || opts.trustedPaxiomPublicKeys;
  const trustedKeys = Array.isArray(rawTrusted)
    ? rawTrusted
    : PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS;
  const receiptVerification = await verifyResponseReceipt(response, {
    output: bodyJson,
    trustedVerifierPublicKeys: trustedKeys,
    crypto: opts.crypto
  });
  const paymentResponse = decodeFlexibleBase64JsonObject(
    extractHeaderValue(response, 'payment-response') || extractHeaderValue(response, 'x-payment-response')
  );

  return {
    ok: true,
    status,
    paymentRequired: false,
    verdict: bodyJson.verdict ?? null,
    riskLevel: bodyJson.riskLevel ?? null,
    report: bodyJson,
    receiptVerification,
    paymentResponse
  };
}

/**
 * Verify a `paxiom.receipt.v0` receipt's claimed Base / Base Sepolia USDC settlement
 * live on-chain (`POST /v1/receipt/verify-live`) using pure Web-standard `fetch` + WebCrypto.
 */
export async function verifyReceiptLive(receipt, options = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new TypeError('receipt must be a parsed paxiom.receipt.v0 JSON object');
  }

  const opts = options && typeof options === 'object' ? options : {};
  const origin = resolveSafeApiOrigin(opts.baseUrl ?? DEFAULT_PAXIOM_API_URL);

  const reqBody = { receipt };
  const hasOutput = Object.hasOwn(opts, 'output') && opts.output !== undefined;
  if (hasOutput) {
    reqBody.output = opts.output;
  }
  if (opts.expectedPayTo !== undefined && opts.expectedPayTo !== null && opts.expectedPayTo !== '') {
    const payToStr = String(opts.expectedPayTo);
    if (!EVM_ADDRESS_RE.test(payToStr)) {
      throw new TypeError('options.expectedPayTo must be a 0x-prefixed 20-byte EVM hex address');
    }
    reqBody.expectedPayTo = payToStr;
  }

  const fetchImpl = opts.fetch || opts.fetchImpl || globalThis.fetch;
  const { response, status, bodyText } = await readBoundedFetchResponse(
    fetchImpl,
    `${origin}/v1/receipt/verify-live`,
    {
      method: 'POST',
      headers: buildJsonHeaders({ apiKey: opts.apiKey, paymentHeader: opts.paymentHeader }),
      body: JSON.stringify(reqBody)
    },
    { timeoutMs: opts.timeoutMs }
  );

  let bodyJson = null;
  try {
    bodyJson = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    bodyJson = null;
  }

  if (status === 402) {
    const headerChallenge = decodeFlexibleBase64JsonObject(extractHeaderValue(response, 'payment-required'));
    return {
      ok: false,
      status: 402,
      paymentRequired: true,
      challenge: headerChallenge || bodyJson,
      result: null,
      counterAttestedReceipt: null,
      counterAttestedVerification: null,
      paymentResponse: null
    };
  }

  if (status < 200 || status >= 300 || !bodyJson || typeof bodyJson !== 'object') {
    return {
      ok: false,
      status,
      paymentRequired: false,
      error: (bodyJson && bodyJson.error) || { code: 'verify_live_http_error', message: `HTTP ${status}` },
      result: null,
      counterAttestedReceipt: null,
      counterAttestedVerification: null,
      paymentResponse: null
    };
  }

  const rawTrusted = opts.trustedVerifierPublicKeys || opts.trustedPaxiomPublicKeys;
  const trustedKeys = Array.isArray(rawTrusted)
    ? rawTrusted
    : PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS;
  const counterAttestedReceipt = bodyJson.counterAttestedReceipt || null;
  const counterAttestedVerification = counterAttestedReceipt
    ? await verifyReceipt(counterAttestedReceipt, {
        ...(hasOutput ? { output: opts.output } : {}),
        trustedVerifierPublicKeys: trustedKeys,
        crypto: opts.crypto
      })
    : null;
  const paymentResponse = decodeFlexibleBase64JsonObject(
    extractHeaderValue(response, 'payment-response') || extractHeaderValue(response, 'x-payment-response')
  );

  return {
    ok: true,
    status,
    paymentRequired: false,
    valid: Boolean(bodyJson.valid),
    trustState: bodyJson.trustState ?? null,
    result: bodyJson,
    counterAttestedReceipt,
    counterAttestedVerification,
    paymentResponse
  };
}
export {
  ESCROW_SCHEMES,
  DEFAULT_ALLOWED_SCHEMES,
  normalizeCaip2NetworkId,
  parseAtomicBigInt,
  resolveFirewallOrigin,
  extractPaymentChallenges,
  createMemorySpendLedger,
  evaluatePreSignPolicy,
  evaluateDeliveryArbiter,
  createGuardedFetch
} from './guard.mjs';
export {
  ROOT_ATTESTATION_VERSION,
  ERC8021_MARKER_HEX,
  EMPTY_TRIE_ROOT_HEX,
  EMPTY_CODE_HASH_HEX,
  ERC20_TRANSFER_TOPIC0,
  ALLOWED_FINALITY_TIERS,
  CANONICAL_USDC_BY_NETWORK,
  keccak256Bytes,
  keccak256Hex,
  uintToMinimalBytes,
  bytesToBigInt,
  rlpEncode,
  rlpDecode,
  normalizeEvmNetworkId,
  deriveAccountTrieKey,
  deriveStorageTrieKey,
  computeMappingSlot,
  computeNestedMappingSlot,
  computeEip3009AuthStateSlot,
  verifyMptProof,
  buildMptProof,
  encodeEvmAccount,
  decodeEvmAccount,
  verifyAccountProof,
  verifyStorageProof,
  verifyEip1186Proof,
  encodeEvmReceipt,
  decodeEvmReceipt,
  buildReceiptTrieProof,
  verifyEvmReceiptProof,
  verifyUsdcSettlementProofSync,
  verifyUsdcSettlementProof,
  rootAttestationSigningBytes,
  validateRootAttestationStructure,
  issueRootAttestation,
  verifyRootAttestation,
  encodeErc8021Suffix,
  appendErc8021Suffix,
  decodeErc8021Suffix
} from './proofs.mjs';
