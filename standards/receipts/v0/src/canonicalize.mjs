// Paxiom v0 canonical JSON profile.
// See ../canonicalization.md — object keys sorted lexicographically (recursive),
// array order preserved, no insignificant whitespace, UTF-8.
//
// Two defensive guards (do not change canonical bytes for valid input):
//  - reject `undefined` (not representable) instead of emitting an invalid token;
//  - bound recursion depth so pathological deeply-nested input throws a clean
//    RangeError the caller can catch, rather than overflowing the process stack.
export const MAX_DEPTH = 256;

export function canonicalize(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new RangeError(`canonicalize: nesting exceeds max depth ${MAX_DEPTH}`);
  if (value === undefined) throw new TypeError('canonicalize: undefined is not representable');
  const t = typeof value;
  if (t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new TypeError(`canonicalize: ${t} is not representable in canonical JSON`);
  }
  if (t === 'number' && !Number.isFinite(value)) {
    throw new TypeError('canonicalize: non-finite numbers (NaN, Infinity) are not representable');
  }
  if (value === null || t !== 'object') return JSON.stringify(value);
  if (typeof value.toJSON === 'function') {
    return canonicalize(value.toJSON(), depth + 1);
  }
  if (value instanceof Map || value instanceof Set || value instanceof RegExp) {
    throw new TypeError('canonicalize: Map, Set, and RegExp instances are not representable in canonical JSON');
  }
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalize(v, depth + 1)).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k], depth + 1))
    .join(',') + '}';
}

// The exact bytes the receipt signature covers.
export function signingInput(receipt) {
  return Buffer.from(
    canonicalize({ receiptVersion: receipt.receiptVersion, payload: receipt.payload }),
    'utf8'
  );
}
