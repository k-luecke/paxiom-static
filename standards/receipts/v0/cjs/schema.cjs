'use strict';
// Auto-generated from src/schema.mjs by scripts/build-cjs.mjs — do not edit directly.
const { MAX_DEPTH } = require('./canonicalize.cjs');

const RECEIPT_VERSION = 'paxiom.receipt.v0';

const RECEIPT_SCHEMA = Object.freeze({
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'https://paxiom.org/standards/receipts/v0/paxiom.receipt.v0.schema.json',
  title: 'Paxiom Receipt v0',
  description:
    'Open specification schema for a proof-bound delivery receipt for x402 and HTTP APIs. x402 proves a payment; a delivery receipt binds request, output digest, payment terms, settlement metadata, and optional evidence into a single Ed25519-signed, transport-portable object. Schema validity is structural only; cryptographic and settlement verification are reported via deterministic trust states.',
  type: 'object',
  additionalProperties: false,
  required: ['receiptVersion', 'payload', 'signature'],
  properties: {
    receiptVersion: {
      type: 'string',
      const: 'paxiom.receipt.v0'
    },
    payload: {
      type: 'object',
      additionalProperties: false,
      required: ['receiptId', 'issuedAt', 'issuer', 'service', 'request', 'payment', 'delivery', 'evidence'],
      properties: {
        receiptId: { type: 'string', minLength: 1 },
        issuedAt: { type: 'string', format: 'date-time' },
        expiresAt: { type: 'string', format: 'date-time' },
        issuer: {
          type: 'object',
          additionalProperties: false,
          required: ['name', 'keyId'],
          properties: {
            name: { type: 'string', minLength: 1 },
            uri: { type: 'string' },
            keyId: { type: 'string', minLength: 1 },
            payTo: { type: 'string', minLength: 1 },
            keysUri: { type: 'string', minLength: 1 }
          }
        },
        service: {
          type: 'object',
          additionalProperties: false,
          required: ['name', 'resource', 'method'],
          properties: {
            name: { type: 'string', minLength: 1 },
            resource: { type: 'string', minLength: 1 },
            method: { type: 'string', minLength: 1 }
          }
        },
        request: {
          type: 'object',
          additionalProperties: false,
          required: ['requestHash', 'resourceHash', 'bodyHash'],
          properties: {
            requestHash: { $ref: '#/$defs/sha256Hex' },
            resourceHash: { $ref: '#/$defs/sha256Hex' },
            bodyHash: { $ref: '#/$defs/sha256Hex' }
          }
        },
        payment: {
          type: 'object',
          additionalProperties: false,
          required: [
            'scheme',
            'network',
            'asset',
            'amountAtomic',
            'amountDisplay',
            'paymentRequirementsHash',
            'paymentPayloadHash',
            'settlement'
          ],
          properties: {
            scheme: { type: 'string', minLength: 1 },
            network: { type: 'string', minLength: 1 },
            asset: { type: 'string', minLength: 1 },
            amountAtomic: { type: 'string', pattern: '^[0-9]+$' },
            amountDisplay: { type: 'string', minLength: 1 },
            payer: { type: 'string', minLength: 1 },
            payTo: { type: 'string', minLength: 1 },
            paymentRequirementsHash: { $ref: '#/$defs/sha256Hex' },
            paymentPayloadHash: { $ref: '#/$defs/sha256Hex' },
            settlement: {
              type: 'object',
              additionalProperties: false,
              required: ['status', 'transactionHash'],
              properties: {
                status: {
                  type: 'string',
                  enum: [
                    'not_required',
                    'disabled',
                    'verify_only',
                    'claimed_not_checked',
                    'verified_settled',
                    'failed',
                    'unknown'
                  ]
                },
                transactionHash: {
                  oneOf: [{ $ref: '#/$defs/transactionId' }, { type: 'null' }]
                },
                checkedByVerifier: { type: 'boolean' },
                verifier: {
                  oneOf: [{ type: 'string', minLength: 1 }, { type: 'null' }]
                },
                checkedByPaxiom: { type: 'boolean' }
              }
            }
          }
        },
        delivery: {
          type: 'object',
          additionalProperties: false,
          required: ['outputHash', 'mimeType'],
          properties: {
            outputHash: { $ref: '#/$defs/sha256Hex' },
            mimeType: { type: 'string', minLength: 1 },
            canonicalization: {
              type: 'string',
              enum: ['jcs-sha256', 'raw-sha256']
            },
            statusCode: {
              type: 'integer',
              minimum: 100,
              maximum: 599
            }
          }
        },
        evidence: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['type', 'status', 'hash', 'uri'],
            properties: {
              type: { type: 'string', enum: ['none', 'zk', 'attestation', 'tee', 'archive', 'other'] },
              status: { type: 'string', enum: ['not_provided', 'provided', 'unavailable', 'invalid', 'verified'] },
              hash: { oneOf: [{ $ref: '#/$defs/sha256Hex' }, { type: 'null' }] },
              uri: { oneOf: [{ type: 'string' }, { type: 'null' }] }
            }
          }
        }
      }
    },
    signature: {
      type: 'object',
      additionalProperties: false,
      required: ['algorithm', 'keyId', 'publicKey', 'value'],
      properties: {
        algorithm: { type: 'string', const: 'ed25519' },
        keyId: { type: 'string', minLength: 1 },
        publicKey: { type: 'string', minLength: 1 },
        value: { type: 'string', minLength: 1 }
      }
    }
  },
  $defs: {
    sha256Hex: {
      type: 'string',
      pattern: '^0x[0-9a-f]{64}$',
      description: 'SHA-256 digest, lowercase hex, 0x-prefixed.'
    },
    transactionId: {
      type: 'string',
      pattern: '^(?:0x[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{64,88})$',
      description:
        'Chain-native settlement transaction identifier: EVM 0x-prefixed 32-byte lowercase hex hash or Solana 64-88 char base58 signature.'
    }
  }
});

const ISO_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

function isValidIsoDateTime(value) {
  if (!ISO_DATETIME_RE.test(value)) return false;
  return !Number.isNaN(Date.parse(value));
}

function normalizePayToId(addr) {
  const s = String(addr || '').trim();
  return /^0x[0-9a-fA-F]{40}$/.test(s) ? s.toLowerCase() : s;
}

function validateReceiptSchema(node, sch = RECEIPT_SCHEMA, path = 'receipt', root = RECEIPT_SCHEMA, depth = 0) {
  if (depth > MAX_DEPTH) return [`${path}: nesting exceeds max depth ${MAX_DEPTH}`];
  const errs = [];
  const kind = (v) => (Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v);
  switch (sch.type) {
    case 'object':
      if (kind(node) !== 'object') return [`${path}: expected object`];
      for (const r of sch.required || []) {
        if (!Object.hasOwn(node, r)) errs.push(`${path}.${r}: required`);
      }
      if (sch.additionalProperties === false) {
        for (const k of Object.keys(node)) {
          if (!(sch.properties && Object.hasOwn(sch.properties, k))) errs.push(`${path}.${k}: not allowed`);
        }
      }
      for (const [k, s] of Object.entries(sch.properties || {})) {
        if (Object.hasOwn(node, k)) errs.push(...validateReceiptSchema(node[k], s, `${path}.${k}`, root, depth + 1));
      }
      break;
    case 'array':
      if (kind(node) !== 'array') return [`${path}: expected array`];
      if (sch.items) node.forEach((it, i) => errs.push(...validateReceiptSchema(it, sch.items, `${path}[${i}]`, root, depth + 1)));
      break;
    case 'string':
      if (typeof node !== 'string') return [`${path}: expected string`];
      if (sch.minLength && node.length < sch.minLength) errs.push(`${path}: too short`);
      if (sch.const && node !== sch.const) errs.push(`${path}: expected ${sch.const}`);
      if (sch.enum && !sch.enum.includes(node)) errs.push(`${path}: not in enum`);
      if (sch.pattern && !new RegExp(sch.pattern).test(node)) errs.push(`${path}: pattern mismatch`);
      if (sch.format === 'date-time' && !isValidIsoDateTime(node)) errs.push(`${path}: invalid date-time`);
      break;
    case 'integer':
      if (!Number.isInteger(node)) errs.push(`${path}: expected integer`);
      else {
        if (sch.minimum !== undefined && node < sch.minimum) errs.push(`${path}: below minimum`);
        if (sch.maximum !== undefined && node > sch.maximum) errs.push(`${path}: above maximum`);
      }
      break;
    case 'boolean':
      if (typeof node !== 'boolean') errs.push(`${path}: expected boolean`);
      break;
    case 'null':
      if (node !== null) errs.push(`${path}: expected null`);
      break;
  }
  if (sch.$ref) {
    const def = sch.$ref.split('/').slice(1).reduce((o, k) => (o && Object.hasOwn(o, k) ? o[k] : undefined), root);
    if (!def) return [`${path}: unresolved $ref ${sch.$ref}`];
    errs.push(...validateReceiptSchema(node, def, path, root, depth + 1));
  }
  if (sch.oneOf) {
    const passes = sch.oneOf.filter((s) => validateReceiptSchema(node, s, path, root, depth + 1).length === 0).length;
    if (passes !== 1) errs.push(`${path}: oneOf matched ${passes}`);
  }
  return errs;
}

exports.RECEIPT_VERSION = RECEIPT_VERSION;
exports.RECEIPT_SCHEMA = RECEIPT_SCHEMA;
exports.isValidIsoDateTime = isValidIsoDateTime;
exports.normalizePayToId = normalizePayToId;
exports.validateReceiptSchema = validateReceiptSchema;
