'use strict';
// Auto-generated from src/verify.mjs by scripts/build-cjs.mjs — do not edit directly.
const crypto = require('node:crypto');
const { readFileSync } = require('node:fs');
const { signingInput } = require('./canonicalize.cjs');
const { sha256Hex, hashCanonical } = require('./hash.cjs');
const { RECEIPT_VERSION, RECEIPT_SCHEMA, normalizePayToId, validateReceiptSchema } = require('./schema.cjs');
const { strictDecodeBase64Bytes, bytesToBase64Url, isByteArray, utf8ToBytes } = require('./bytes.cjs');
const { ALLOWED_FINALITY_TIERS, validateRootAttestationStructure, rootAttestationSigningBytes, evaluateReceiptOfflineProofsSync } = require('./proofs.cjs');



function ed25519PublicKey(publicKeyB64) {
  const raw = strictDecodeBase64Bytes(publicKeyB64, 32, 'Ed25519 publicKey');
  return crypto.createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64Url(raw) }
  });
}

function verifyRootAttestationSync(attestation, { trustedRootPublicKeys, allowedFinalityTiers, nowMs }) {
  const fail = (code, reason) => ({ ok: false, verified: false, code, reason, payload: null });
  const schemaErrs = validateRootAttestationStructure(attestation);
  if (schemaErrs.length > 0) {
    return fail('invalid_root_attestation', schemaErrs[0]);
  }
  let sigOk = false;
  try {
    const pubKeyObj = ed25519PublicKey(attestation.signature.publicKey);
    const sigBuf = strictDecodeBase64Bytes(attestation.signature.value, 64, 'rootAttestation signature.value');
    const msgBuf = rootAttestationSigningBytes(attestation.payload);
    sigOk = crypto.verify(null, msgBuf, pubKeyObj, sigBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return fail('invalid_signature', 'Ed25519 signature verification failed on rootAttestation.');
  }
  if (trustedRootPublicKeys !== undefined && trustedRootPublicKeys !== null) {
    const allowedSet = trustedRootPublicKeys instanceof Set
      ? trustedRootPublicKeys
      : new Set(Array.isArray(trustedRootPublicKeys) ? trustedRootPublicKeys : []);
    if (!allowedSet.has(attestation.signature.publicKey)) {
      return fail(
        'untrusted_root_signer',
        `Root attestation signer (${attestation.signature.publicKey}) is not in trustedRootPublicKeys.`
      );
    }
  }
  if (Array.isArray(allowedFinalityTiers) && allowedFinalityTiers.length > 0) {
    if (!allowedFinalityTiers.includes(attestation.payload.finalityTier)) {
      return fail(
        'disallowed_finality_tier',
        `Root attestation finalityTier "${attestation.payload.finalityTier}" is not in allowedFinalityTiers.`
      );
    }
  }
  if (attestation.payload.expiresAt && Date.parse(attestation.payload.expiresAt) < nowMs) {
    return fail('expired_root_attestation', `Root attestation expired at ${attestation.payload.expiresAt}.`);
  }
  return {
    ok: true,
    verified: true,
    code: 'verified',
    payload: attestation.payload,
    signerPublicKey: attestation.signature.publicKey
  };
}

const CHECK = { PASS: 'pass', FAIL: 'fail', SKIP: 'not_checked' };

/**
 * Verify a paxiom.receipt.v0 receipt, optionally against the delivered output and
 * expected seller signing keys / payTo identity.
 * Offline only: no chain calls, no facilitator calls, no evidence fetching.
 */
function verifyReceipt(receipt, opts = {}) {
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
      const attCheck = verifyRootAttestationSync(rawAtt, {
        trustedRootPublicKeys: rawRootKeys,
        allowedFinalityTiers: safeOpts.allowedFinalityTiers,
        nowMs
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
      return done('settlement_claimed_not_checked',
        unanchoredProofNote ||
        'Receipt asserts independent verifier settlement check, but signer is not in trustedVerifierPublicKeys.');
    }
    if ((st === 'not_required' || st === 'disabled' || st === 'verify_only') &&
        p.payment.settlement.transactionHash !== null) {
      return done('settlement_claimed_not_checked',
        unanchoredProofNote ||
        'Receipt carries a non-null settlement.transactionHash under a non-settled status that this offline verifier did not check.');
    }
    const counterVerified = st === 'verified_settled' && assertsVerifierCheck && isTrustedVerifierSigner;
    if (st === 'claimed_not_checked' || (st === 'verified_settled' && !counterVerified)) {
      return done('settlement_claimed_not_checked',
        unanchoredProofNote ||
        (hasOutput
          ? 'Signature and output hash verified. Receipt claims an onchain settlement that this offline verifier did not check.'
          : 'Signature verified. Receipt claims an onchain settlement that this offline verifier did not check.'));
    }
  }

  // (12) output not supplied, or settlement unknown -> can't reach verified
  if (!hasOutput) {
    return done('valid_signature_only',
      'Signature valid. No output supplied, so payment-to-output binding was not checked.');
  }
  if (st === 'unknown' && !offlineProofSettled) {
    return done('valid_signature_only', 'Signature and output verified, but settlement status is unknown.');
  }

  // (13) verified
  const effectiveSettlement = offlineProofSettled ? 'verified_settled (offline MPT proof)' : st;
  return done('verified',
    `Receipt verified: schema, Ed25519 signature, output binding, and settlement (${effectiveSettlement}) all consistent.`);
}

/** Convenience: verify from file paths (Node.js only). */
function verifyFromFiles(receiptPath, outputPath, extraOpts = {}) {
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const opts = { ...extraOpts };
  if (outputPath) {
    const rawBuf = readFileSync(outputPath);
    const mode = receipt?.payload?.delivery?.canonicalization || 'jcs-sha256';
    opts.output = mode === 'raw-sha256' ? rawBuf : JSON.parse(rawBuf.toString('utf8'));
  }
  return verifyReceipt(receipt, opts);
}

exports.RECEIPT_VERSION = RECEIPT_VERSION;
exports.RECEIPT_SCHEMA = RECEIPT_SCHEMA;
exports.verifyReceipt = verifyReceipt;
exports.verifyFromFiles = verifyFromFiles;
