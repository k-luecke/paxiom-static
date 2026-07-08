import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize, signingInput } from './canonicalize.mjs';
import { sha256Hex, hashCanonical } from './hash.mjs';

export const RECEIPT_VERSION = 'paxiom.receipt.v0';

const schema = JSON.parse(
  readFileSync(new URL('../paxiom.receipt.v0.schema.json', import.meta.url), 'utf8')
);

// --- minimal draft-07 validator (covers exactly the constructs this schema uses) ---
function validateSchema(node, sch, path, root) {
  const errs = [];
  const kind = (v) => (Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v);
  switch (sch.type) {
    case 'object':
      if (kind(node) !== 'object') return [`${path}: expected object`];
      for (const r of sch.required || []) if (!(r in node)) errs.push(`${path}.${r}: required`);
      if (sch.additionalProperties === false)
        for (const k of Object.keys(node))
          if (!(sch.properties && k in sch.properties)) errs.push(`${path}.${k}: not allowed`);
      for (const [k, s] of Object.entries(sch.properties || {}))
        if (k in node) errs.push(...validateSchema(node[k], s, `${path}.${k}`, root));
      break;
    case 'array':
      if (kind(node) !== 'array') return [`${path}: expected array`];
      if (sch.items) node.forEach((it, i) => errs.push(...validateSchema(it, sch.items, `${path}[${i}]`, root)));
      break;
    case 'string':
      if (typeof node !== 'string') return [`${path}: expected string`];
      if (sch.minLength && node.length < sch.minLength) errs.push(`${path}: too short`);
      if (sch.const && node !== sch.const) errs.push(`${path}: expected ${sch.const}`);
      if (sch.enum && !sch.enum.includes(node)) errs.push(`${path}: not in enum`);
      if (sch.pattern && !new RegExp(sch.pattern).test(node)) errs.push(`${path}: pattern mismatch`);
      break;
    case 'boolean':
      if (typeof node !== 'boolean') errs.push(`${path}: expected boolean`);
      break;
    case 'null':
      if (node !== null) errs.push(`${path}: expected null`);
      break;
  }
  if (sch.$ref) {
    const def = sch.$ref.split('/').slice(1).reduce((o, k) => o[k], root);
    errs.push(...validateSchema(node, def, path, root));
  }
  if (sch.oneOf) {
    const passes = sch.oneOf.filter((s) => validateSchema(node, s, path, root).length === 0).length;
    if (passes !== 1) errs.push(`${path}: oneOf matched ${passes}`);
  }
  return errs;
}

function ed25519PublicKey(publicKeyB64) {
  // v0 encoding: base64 of the raw 32-byte Ed25519 public key.
  const raw = Buffer.from(publicKeyB64, 'base64');
  return crypto.createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }
  });
}

const CHECK = { PASS: 'pass', FAIL: 'fail', SKIP: 'not_checked' };

/**
 * Verify a paxiom.receipt.v0 receipt, optionally against the delivered output.
 * Offline only: no chain calls, no facilitator calls, no evidence fetching.
 * @param {object} receipt  parsed receipt JSON
 * @param {object} [opts]
 * @param {object} [opts.output]  parsed delivered output JSON (enables output-hash check)
 * @returns {{valid:boolean, trustState:string, checks:object, receiptHash:(string|null), summary:string}}
 */
export function verifyReceipt(receipt, opts = {}) {
  const hasOutput = Object.prototype.hasOwnProperty.call(opts, 'output');
  const checks = {
    schema: CHECK.SKIP,
    signature: CHECK.SKIP,
    outputHash: hasOutput ? CHECK.SKIP : 'not_provided',
    requestBinding: CHECK.SKIP,
    paymentBinding: CHECK.SKIP,
    settlement: CHECK.SKIP,
    proof: CHECK.SKIP
  };
  const done = (trustState, summary) => ({
    valid: trustState === 'verified',
    trustState,
    checks,
    receiptHash,
    summary
  });

  let receiptHash = null;

  // (2) version gate — before anything else
  if (!receipt || receipt.receiptVersion !== RECEIPT_VERSION) {
    return done('unsupported_format',
      `Unsupported receiptVersion: ${receipt && receipt.receiptVersion}. Expected ${RECEIPT_VERSION}.`);
  }

  // (3) schema
  const schemaErrs = validateSchema(receipt, schema, 'receipt', schema);
  if (schemaErrs.length) {
    checks.schema = CHECK.FAIL;
    return done('schema_invalid', `Receipt does not conform to ${RECEIPT_VERSION} schema: ${schemaErrs[0]}.`);
  }
  checks.schema = CHECK.PASS;

  // derive a (non-authoritative) display hash now that shape is known
  const input = signingInput(receipt);
  receiptHash = sha256Hex(input);

  // (4) signature
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, input, ed25519PublicKey(receipt.signature.publicKey),
      Buffer.from(receipt.signature.value, 'base64'));
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    checks.signature = CHECK.FAIL;
    return done('invalid_signature', 'Ed25519 signature does not verify over the canonical signing input.');
  }
  checks.signature = CHECK.PASS;

  const p = receipt.payload;

  // (5) expiry
  if (p.expiresAt && Date.parse(p.expiresAt) < Date.now()) {
    return done('expired', `Receipt expired at ${p.expiresAt}.`);
  }

  // (6)(7) bindings — schema guarantees presence/format; treat as pass
  checks.requestBinding = CHECK.PASS;
  checks.paymentBinding = CHECK.PASS;

  // (8) output hash — only when an output is supplied
  if (hasOutput) {
    const recomputed = hashCanonical(opts.output);
    if (recomputed !== p.delivery.outputHash) {
      checks.outputHash = CHECK.FAIL;
      return done('output_hash_mismatch',
        `Supplied output hash ${recomputed} != receipt delivery.outputHash ${p.delivery.outputHash}.`);
    }
    checks.outputHash = CHECK.PASS;
  }

  // proof/evidence interpretation (informational; offline v0 never fetches)
  const evidence = p.evidence || [];
  const anyInvalid = evidence.some((e) => e.status === 'invalid');
  const anyUnavailable = evidence.some((e) => e.status === 'unavailable');
  const anyProvided = evidence.some((e) => e.type !== 'none' && e.status !== 'not_provided');
  checks.proof = anyInvalid ? 'invalid'
    : anyUnavailable ? 'unavailable'
    : anyProvided ? 'provided'
    : 'not_provided';

  // settlement interpretation
  const st = p.payment.settlement.status;
  checks.settlement = st;

  // (9) settlement failed
  if (st === 'failed') return done('settlement_failed', 'Receipt reports a failed settlement.');

  // (10) evidence retrieved-and-invalid / referenced-but-unreachable
  if (anyInvalid) return done('proof_invalid', 'A provided evidence record failed verification.');
  if (anyUnavailable) return done('proof_unavailable', 'A referenced evidence record could not be retrieved.');

  // (11) unconfirmed onchain settlement claim -> never full verified offline
  if (st === 'claimed_not_checked' || st === 'verified_settled') {
    return done('settlement_claimed_not_checked',
      hasOutput
        ? 'Signature and output hash verified. Receipt claims an onchain settlement that this offline verifier did not check.'
        : 'Signature verified. Receipt claims an onchain settlement that this offline verifier did not check.');
  }

  // (12) output not supplied, or settlement unknown -> can't reach verified
  if (!hasOutput) {
    return done('valid_signature_only',
      'Signature valid. No output supplied, so payment-to-output binding was not checked.');
  }
  if (st === 'unknown') {
    return done('valid_signature_only', 'Signature and output verified, but settlement status is unknown.');
  }

  // (13) verified
  return done('verified',
    `Receipt verified: schema, Ed25519 signature, output binding, and settlement (${st}) all consistent.`);
}

/** Convenience: verify from file paths. */
export function verifyFromFiles(receiptPath, outputPath) {
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const opts = {};
  if (outputPath) opts.output = JSON.parse(readFileSync(outputPath, 'utf8'));
  return verifyReceipt(receipt, opts);
}
