import crypto from 'node:crypto';
import { signingInput } from './canonicalize.mjs';
import { sha256Hex, hashCanonical } from './hash.mjs';
import { RECEIPT_VERSION } from './verify.mjs';

const SHA256_HEX_RE = /^0x[0-9a-f]{64}$/;
const EVM_TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const SOLANA_TX_SIG_RE = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;

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
 * Normalize an Ed25519 private key input (KeyObject, PEM string, or JWK object)
 * into a Node crypto.KeyObject.
 */
export function normalizeEd25519PrivateKey(privateKey) {
  if (!privateKey) throw new TypeError('privateKey is required to sign a Paxiom receipt');
  if (typeof privateKey === 'object' && typeof privateKey.export === 'function') {
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new TypeError(`Expected ed25519 privateKey, got ${privateKey.asymmetricKeyType}`);
    }
    return privateKey;
  }
  if (typeof privateKey === 'string') {
    const keyObj = crypto.createPrivateKey(privateKey);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      throw new TypeError(`Expected ed25519 PEM privateKey, got ${keyObj.asymmetricKeyType}`);
    }
    return keyObj;
  }
  if (typeof privateKey === 'object' && privateKey.kty === 'OKP' && privateKey.crv === 'Ed25519') {
    return crypto.createPrivateKey({ format: 'jwk', key: privateKey });
  }
  throw new TypeError('Unsupported privateKey format: supply a Node KeyObject, PKCS#8 PEM string, or Ed25519 JWK');
}

/**
 * Derive the raw 32-byte base64 Ed25519 public key (paxiom.receipt.v0 format)
 * from any supported Ed25519 private key.
 */
export function publicKeyFromPrivateKey(privateKey) {
  const privObj = normalizeEd25519PrivateKey(privateKey);
  const pubObj = crypto.createPublicKey(privObj);
  const jwk = pubObj.export({ format: 'jwk' });
  const raw = Buffer.from(jwk.x, 'base64url');
  if (raw.length !== 32) {
    throw new Error('Derived Ed25519 public key did not produce 32 bytes');
  }
  return raw.toString('base64');
}

/**
 * Generate a fresh Ed25519 signing keypair formatted for paxiom.receipt.v0.
 */
export function generateReceiptKeyPair(opts = {}) {
  const keyId = typeof opts === 'string'
    ? opts
    : (opts?.keyId ?? `key_${crypto.randomBytes(6).toString('hex')}`);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const publicKeyB64 = Buffer.from(jwk.x, 'base64url').toString('base64');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return {
    keyId,
    algorithm: 'ed25519',
    publicKey: publicKeyB64,
    privateKeyPem,
    publicKeyJwk: { ...jwk, kid: keyId }
  };
}

function resolveDigestOrValue(explicitHash, value, fallbackEmpty = '') {
  if (typeof explicitHash === 'string') {
    const normalized = explicitHash.toLowerCase();
    if (!SHA256_HEX_RE.test(normalized)) {
      throw new TypeError(`Invalid sha256Hex digest: ${explicitHash}`);
    }
    return normalized;
  }
  if (value === undefined) {
    return sha256Hex(Buffer.from(fallbackEmpty, 'utf8'));
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return sha256Hex(value);
  }
  if (typeof value === 'string') {
    return sha256Hex(Buffer.from(value, 'utf8'));
  }
  return hashCanonical(value);
}

/**
 * Issue and Ed25519-sign a schema-valid paxiom.receipt.v0 receipt.
 *
 * Zero external dependencies. Supports both structured JSON (`jcs-sha256`) and
 * exact binary/text payloads (`raw-sha256`), CAIP-2 + Solana/EVM transaction IDs,
 * and vendor-neutral `checkedByVerifier` settlement metadata.
 */
export function issueReceipt({
  privateKey,
  receiptId = `rcpt_${crypto.randomUUID().replace(/-/g, '')}`,
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
  evidence
} = {}) {
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('issuer.name and issuer.keyId are required');
  }
  if (!service || !service.name || !service.resource || !service.method) {
    throw new TypeError('service.name, service.resource, and service.method are required');
  }

  const privObj = normalizeEd25519PrivateKey(privateKey);
  const publicKey = publicKeyFromPrivateKey(privObj);

  const method = String(request.method || service.method).toUpperCase();
  const resource = String(request.resource || service.resource);
  const resourceHash = resolveDigestOrValue(request.resourceHash, resource);
  const bodyHash = resolveDigestOrValue(request.bodyHash, request.body, '');
  const requestHash = request.requestHash
    ? resolveDigestOrValue(request.requestHash)
    : hashCanonical({ bodyHash, method, resource });

  const paymentRequirementsHash = resolveDigestOrValue(
    payment.paymentRequirementsHash,
    payment.paymentRequirements,
    'none'
  );
  const paymentPayloadHash = resolveDigestOrValue(
    payment.paymentPayloadHash,
    payment.paymentPayload,
    'none'
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

  const isRawBytes = Buffer.isBuffer(output) || output instanceof Uint8Array;
  let canonicalizationMode = explicitCanonicalization || (isRawBytes ? 'raw-sha256' : undefined);
  if (canonicalizationMode && canonicalizationMode !== 'jcs-sha256' && canonicalizationMode !== 'raw-sha256') {
    throw new TypeError(`Invalid canonicalization mode: ${canonicalizationMode}`);
  }

  let computedOutputHash;
  if (explicitOutputHash) {
    computedOutputHash = resolveDigestOrValue(explicitOutputHash);
  } else if (output !== undefined) {
    if (canonicalizationMode === 'raw-sha256') {
      if (isRawBytes) {
        computedOutputHash = sha256Hex(output);
      } else if (typeof output === 'string') {
        computedOutputHash = sha256Hex(Buffer.from(output, 'utf8'));
      } else {
        throw new TypeError('canonicalization="raw-sha256" requires Buffer, Uint8Array, or string output');
      }
    } else {
      computedOutputHash = hashCanonical(output);
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
    receiptId: String(receiptId),
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

  const receiptUnsigned = {
    receiptVersion: RECEIPT_VERSION,
    payload
  };
  const sigBytes = crypto.sign(null, signingInput(receiptUnsigned), privObj);
  const receipt = {
    receiptVersion: RECEIPT_VERSION,
    payload,
    signature: {
      algorithm: 'ed25519',
      keyId: issuerObj.keyId,
      publicKey,
      value: sigBytes.toString('base64')
    }
  };

  const receiptHeader = Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64url');
  return { receipt, receiptHeader };
}

/**
 * Decode a base64url `Payment-Receipt` or `X-Paxiom-Receipt` HTTP header back into a receipt object.
 */
export function decodeReceiptHeader(headerValue) {
  if (typeof headerValue !== 'string' || !headerValue.trim()) {
    throw new TypeError('Receipt header must be a non-empty base64url string');
  }
  return JSON.parse(Buffer.from(headerValue.trim(), 'base64url').toString('utf8'));
}
