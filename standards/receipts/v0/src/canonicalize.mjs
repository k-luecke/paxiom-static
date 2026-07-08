// Paxiom v0 canonical JSON profile.
// See ../canonicalization.md — object keys sorted lexicographically (recursive),
// array order preserved, no insignificant whitespace, UTF-8.
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map(k => JSON.stringify(k) + ':' + canonicalize(value[k]))
    .join(',') + '}';
}

// The exact bytes the receipt signature covers.
export function signingInput(receipt) {
  return Buffer.from(
    canonicalize({ receiptVersion: receipt.receiptVersion, payload: receipt.payload }),
    'utf8'
  );
}
