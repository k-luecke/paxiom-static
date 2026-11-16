import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { signingInput } from './canonicalize.mjs';
import { sha256Hex, hashCanonical } from './hash.mjs';
import {
  RECEIPT_VERSION,
  RECEIPT_SCHEMA,
  normalizePayToId,
  validateReceiptSchema
} from './schema.mjs';
import {
  strictDecodeBase64Bytes,
  bytesToBase64Url,
  isByteArray,
  utf8ToBytes
} from './bytes.mjs';

export { RECEIPT_VERSION, RECEIPT_SCHEMA };

function ed25519PublicKey(publicKeyB64) {
  const raw = strictDecodeBase64Bytes(publicKeyB64, 32, 'Ed25519 publicKey');
  return crypto.createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64Url(raw) }
  });
}

const CHECK = { PASS: 'pass', FAIL: 'fail', SKIP: 'not_checked' };

/**
 * Verify a paxiom.receipt.v0 receipt, optionally against the delivered output and
 * expected seller signing keys / payTo identity.
 * Offline only: no chain calls, no facilitator calls, no evidence fetching.
 */
export function verifyReceipt(receipt, opts = {}) {
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
  const done = (trustState, summary) => ({
    valid: trustState === 'verified',
    trustState,
    checks,
    receiptHash,
    summary
  });

  let receiptHash = null;

  // (1) version gate — before anything else
  if (!receipt || receipt.receiptVersion !== RECEIPT_VERSION) {
    return done('unsupported_format',
      `Unsupported receiptVersion: ${receipt && receipt.receiptVersion}. Expected ${RECEIPT_VERSION}.`);
  }

  // (2) schema
  const schemaErrs = validateReceiptSchema(receipt, RECEIPT_SCHEMA, 'receipt', RECEIPT_SCHEMA);
  if (schemaErrs.length) {
    checks.schema = CHECK.FAIL;
    return done('schema_invalid', `Receipt does not conform to ${RECEIPT_VERSION} schema: ${schemaErrs[0]}.`);
  }
  checks.schema = CHECK.PASS;

  const input = signingInput(receipt);
  receiptHash = sha256Hex(input);

  // (3) signature + keyId consistency
  if (receipt.payload.issuer.keyId !== receipt.signature.keyId) {
    checks.signature = CHECK.FAIL;
    return done('invalid_signature',
      `payload.issuer.keyId (${receipt.payload.issuer.keyId}) does not match signature.keyId (${receipt.signature.keyId}).`);
  }
  let sigOk = false;
  try {
    const pubKeyObj = ed25519PublicKey(receipt.signature.publicKey);
    const sigBuf = strictDecodeBase64Bytes(receipt.signature.value, 64, 'Ed25519 signature.value');
    sigOk = crypto.verify(null, input, pubKeyObj, sigBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    checks.signature = CHECK.FAIL;
    return done('invalid_signature', 'Ed25519 signature does not verify over the canonical signing input.');
  }
  checks.signature = CHECK.PASS;

  const p = receipt.payload;

  // (4) signer authorization (when caller pins expected seller public keys and/or payTo)
  if (hasExpectedKeys) {
    const allowedSet = new Set(safeOpts.expectedIssuerPublicKeys);
    if (!allowedSet.has(receipt.signature.publicKey)) {
      checks.issuerAuthorization = CHECK.FAIL;
      return done('unauthorized_issuer',
        'Receipt signature is valid, but signature.publicKey is not in expectedIssuerPublicKeys for this resource.');
    }
  }
  if (hasExpectedPayTo) {
    const wantPayTo = normalizePayToId(safeOpts.expectedPayTo);
    const receiptPayTo = p.payment.payTo || p.issuer.payTo || null;
    if (!receiptPayTo || normalizePayToId(receiptPayTo) !== wantPayTo) {
      checks.issuerAuthorization = CHECK.FAIL;
      return done('unauthorized_issuer',
        receiptPayTo
          ? `Receipt payTo (${receiptPayTo}) does not match expectedPayTo (${safeOpts.expectedPayTo}).`
          : `Caller pinned expectedPayTo (${safeOpts.expectedPayTo}), but receipt does not bind a payTo address.`);
    }
  }
  if (hasExpectedKeys || hasExpectedPayTo) {
    checks.issuerAuthorization = CHECK.PASS;
  }

  // (5) expiry
  const nowMs = safeOpts.now !== undefined
    ? (safeOpts.now instanceof Date ? safeOpts.now.getTime() : typeof safeOpts.now === 'number' ? safeOpts.now : Date.parse(String(safeOpts.now)))
    : Date.now();
  if (p.expiresAt && Date.parse(p.expiresAt) < nowMs) {
    return done('expired', `Receipt expired at ${p.expiresAt}.`);
  }

  // (6)(7) bindings — schema guarantees presence/format
  checks.requestBinding = CHECK.PASS;
  checks.paymentBinding = CHECK.PASS;

  // (8) output hash — supports both jcs-sha256 (canonical JSON) and raw-sha256 (exact bytes)
  if (hasOutput) {
    let recomputed;
    const mode = p.delivery.canonicalization || 'jcs-sha256';
    try {
      if (mode === 'raw-sha256') {
        if (isByteArray(safeOpts.output)) {
          recomputed = sha256Hex(safeOpts.output);
        } else if (typeof safeOpts.output === 'string') {
          recomputed = sha256Hex(utf8ToBytes(safeOpts.output));
        } else {
          throw new TypeError('delivery.canonicalization="raw-sha256" requires raw Buffer, Uint8Array, or string output');
        }
      } else {
        recomputed = hashCanonical(safeOpts.output);
      }
    } catch (err) {
      checks.outputHash = 'error';
      return done('error', `Could not hash supplied output (${mode}): ${(err && err.message) || err}.`);
    }
    if (recomputed !== p.delivery.outputHash) {
      checks.outputHash = CHECK.FAIL;
      return done('output_hash_mismatch',
        `Supplied output hash ${recomputed} != receipt delivery.outputHash ${p.delivery.outputHash}.`);
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

  // settlement interpretation
  const st = p.payment.settlement.status;
  checks.settlement = st;

  // (9) settlement failed
  if (st === 'failed') return done('settlement_failed', 'Receipt reports a failed settlement.');

  // (10) evidence retrieved-and-invalid / referenced-but-unreachable
  if (anyInvalid) return done('proof_invalid', 'A provided evidence record failed verification.');
  if (anyUnavailable) return done('proof_unavailable', 'A referenced evidence record could not be retrieved.');

  // (11) unconfirmed onchain settlement or untrusted counter-verifier claim
  const rawTrustedKeys = safeOpts.trustedVerifierPublicKeys || safeOpts.trustedPaxiomPublicKeys || null;
  const trustedVerifierSet = rawTrustedKeys ? new Set(rawTrustedKeys) : null;
  const isTrustedVerifierSigner = Boolean(trustedVerifierSet && trustedVerifierSet.has(receipt.signature.publicKey));
  const assertsVerifierCheck = Boolean(p.payment.settlement.checkedByVerifier || p.payment.settlement.checkedByPaxiom);

  if (assertsVerifierCheck && !isTrustedVerifierSigner) {
    return done('settlement_claimed_not_checked',
      'Receipt asserts independent verifier settlement check, but signer is not in trustedVerifierPublicKeys.');
  }
  if ((st === 'not_required' || st === 'disabled' || st === 'verify_only') &&
      p.payment.settlement.transactionHash !== null) {
    return done('settlement_claimed_not_checked',
      'Receipt carries a non-null settlement.transactionHash under a non-settled status that this offline verifier did not check.');
  }
  const counterVerified = st === 'verified_settled' && assertsVerifierCheck && isTrustedVerifierSigner;
  if (st === 'claimed_not_checked' || (st === 'verified_settled' && !counterVerified)) {
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

/** Convenience: verify from file paths (Node.js only). */
export function verifyFromFiles(receiptPath, outputPath, extraOpts = {}) {
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const opts = { ...extraOpts };
  if (outputPath) {
    const rawBuf = readFileSync(outputPath);
    const mode = receipt?.payload?.delivery?.canonicalization || 'jcs-sha256';
    opts.output = mode === 'raw-sha256' ? rawBuf : JSON.parse(rawBuf.toString('utf8'));
  }
  return verifyReceipt(receipt, opts);
}
