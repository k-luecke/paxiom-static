import crypto from 'node:crypto';
import { canonicalize } from './canonicalize.mjs';

// SHA-256, lowercase hex, 0x-prefixed (the v0 hash format).
export function sha256Hex(buf) {
  return '0x' + crypto.createHash('sha256').update(buf).digest('hex');
}

// Hash of the canonical JSON of an object (how outputHash is computed in v0).
export function hashCanonical(obj) {
  return sha256Hex(Buffer.from(canonicalize(obj), 'utf8'));
}
