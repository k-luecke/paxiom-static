'use strict';
// Auto-generated from src/hash.mjs by scripts/build-cjs.mjs — do not edit directly.
const crypto = require('node:crypto');
const { canonicalize } = require('./canonicalize.cjs');

// SHA-256, lowercase hex, 0x-prefixed (the v0 hash format).
function sha256Hex(buf) {
  return '0x' + crypto.createHash('sha256').update(buf).digest('hex');
}

// Hash of the canonical JSON of an object (how outputHash is computed in v0).
function hashCanonical(obj) {
  return sha256Hex(Buffer.from(canonicalize(obj), 'utf8'));
}

exports.sha256Hex = sha256Hex;
exports.hashCanonical = hashCanonical;
