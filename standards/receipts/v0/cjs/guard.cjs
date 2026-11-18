'use strict';
// Auto-generated from src/guard.mjs by scripts/build-cjs.mjs — do not edit directly.
// Zero-dependency Buyer Policy Firewall (Gate 1) & AuthCaptureEscrow Delivery Arbiter (Gate 2)
// Pure Web-Standard implementation: runs identically in Node >=18, Cloudflare Workers, Deno, Bun, and Browsers.

const { verifyReceipt, decodeReceiptHeader, sha256Hex, hashCanonical } = require('./web.cjs');
const { isByteArray, asUint8Array, utf8ToBytes, bytesToUtf8, decodeFlexibleBase64JsonObject } = require('./bytes.cjs');
const { normalizePayToId } = require('./schema.cjs');

const STANDARD_RECEIPT_HEADER_NAME = 'payment-receipt';
const RECEIPT_HEADER_NAME = 'x-paxiom-receipt';

const DEC_UINT_RE = /^[0-9]+$/;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;
const DEFAULT_WINDOW_MS = 60 * 60 * 1000; // 1 hour rolling per-origin window
const DEFAULT_COOLDOWN_MS = 5 * 60 * 1000; // 5 minute circuit-breaker cooldown
const DEFAULT_MAX_CONSECUTIVE_FAILURES = 3;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_FETCH_TIMEOUT_MS = 15000;
const DEFAULT_MIN_AUTH_WINDOW_SEC = 30;
const DEFAULT_MAX_AUTH_WINDOW_SEC = 7 * 24 * 60 * 60;
const MAX_FEE_BPS_CEILING = 10000n;

const ESCROW_SCHEMES = Object.freeze([
  'auth-capture',
  'auth_capture',
  'commerce-escrow',
  'escrow'
]);

const DEFAULT_ALLOWED_SCHEMES = Object.freeze([
  'exact',
  'auth-capture',
  'upto',
  'batch-settlement'
]);

function isEscrowScheme(scheme) {
  return ESCROW_SCHEMES.includes(String(scheme || '').toLowerCase());
}

function canonicalSchemeName(rawScheme) {
  if (typeof rawScheme !== 'string' || !rawScheme.trim()) return null;
  const lower = rawScheme.trim().toLowerCase();
  if (isEscrowScheme(lower)) return 'auth-capture';
  return lower;
}

function normalizeCaip2NetworkId(rawNet) {
  if (typeof rawNet !== 'string' || !rawNet.trim()) return null;
  const trimmed = rawNet.trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'base') return 'eip155:8453';
  if (lower === 'base-sepolia') return 'eip155:84532';
  if (lower === 'ethereum' || lower === 'mainnet') return 'eip155:1';
  if (lower === 'solana' || lower === 'solana-mainnet') return 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
  if (lower === 'solana-devnet') return 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
  return trimmed;
}

function parseAtomicBigInt(value, label = 'amount') {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new RangeError(`${label} must be non-negative`);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`${label} number must be a non-negative safe integer (prefer BigInt or decimal string)`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!DEC_UINT_RE.test(trimmed)) {
      throw new TypeError(`${label} must be a canonical non-negative integer string, got "${value}"`);
    }
    return BigInt(trimmed);
  }
  throw new TypeError(`${label} must be a BigInt, non-negative integer string, or safe integer`);
}

function tryParseAtomicBigInt(value) {
  try {
    return parseAtomicBigInt(value);
  } catch {
    return null;
  }
}

function isLoopbackHost(hostname) {
  const bare = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  return bare === '127.0.0.1' || bare === 'localhost' || bare === '::1';
}

function resolveFirewallOrigin(rawUrl, { allowLoopbackHttp = false } = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, code: 'invalid_origin', reason: 'Target URL must be a non-empty string.' };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { ok: false, code: 'invalid_origin', reason: `Invalid target URL: ${rawUrl}` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, code: 'invalid_origin', reason: 'Target URL must not contain embedded credentials.' };
  }
  if (parsed.protocol !== 'https:' && !(allowLoopbackHttp && parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname))) {
    return {
      ok: false,
      code: 'insecure_transport',
      reason: 'Target URL must use https:// (http:// is allowed only on loopback when allowLoopbackHttp is true).'
    };
  }
  return { ok: true, origin: parsed.origin.toLowerCase(), url: parsed };
}

function extractHeader(responseOrHeaders, name) {
  if (!responseOrHeaders || typeof responseOrHeaders !== 'object') return undefined;
  const headers = (
    Object.prototype.hasOwnProperty.call(responseOrHeaders, 'headers') ||
    typeof responseOrHeaders.headers === 'object'
  ) && responseOrHeaders.headers
    ? responseOrHeaders.headers
    : responseOrHeaders;

  if (typeof headers.get === 'function') {
    const val = headers.get(name);
    return val === null || val === undefined ? undefined : String(val);
  }
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower && v !== undefined && v !== null) {
      return Array.isArray(v) ? String(v[0]) : String(v);
    }
  }
  return undefined;
}

function normalizeSingleRequirement(reqObj, rawEnvelope = null) {
  if (!reqObj || typeof reqObj !== 'object' || Array.isArray(reqObj)) return null;
  const scheme = canonicalSchemeName(reqObj.scheme || (rawEnvelope && rawEnvelope.scheme));
  const network = normalizeCaip2NetworkId(reqObj.network || reqObj.networkId || (rawEnvelope && rawEnvelope.network));
  const rawAsset = reqObj.asset ?? reqObj.token ?? null;
  const asset = typeof rawAsset === 'string' && rawAsset.trim() ? rawAsset.trim() : null;
  const rawPayTo = reqObj.payTo ?? reqObj.receiver ?? (reqObj.extra && reqObj.extra.receiver) ?? null;
  const payTo = typeof rawPayTo === 'string' && rawPayTo.trim() ? rawPayTo.trim() : null;
  const rawAmount = reqObj.amount ?? reqObj.maxAmountRequired ?? reqObj.maxAmount ?? (reqObj.extra && reqObj.extra.maxAmount) ?? null;
  const amountBig = rawAmount !== null && rawAmount !== undefined ? tryParseAtomicBigInt(rawAmount) : null;

  const extra = (reqObj.extra && typeof reqObj.extra === 'object' && !Array.isArray(reqObj.extra))
    ? reqObj.extra
    : {};
  const paymentInfo = (extra.paymentInfo && typeof extra.paymentInfo === 'object' && !Array.isArray(extra.paymentInfo))
    ? extra.paymentInfo
    : extra;

  let authCapture = null;
  if (scheme === 'auth-capture' || paymentInfo.operator || reqObj.operator) {
    const rawOperator = paymentInfo.operator ?? reqObj.operator ?? null;
    const rawMinFee = paymentInfo.minFeeBps ?? reqObj.minFeeBps ?? 0;
    const rawMaxFee = paymentInfo.maxFeeBps ?? reqObj.maxFeeBps ?? null;
    const rawAuthExp = paymentInfo.authorizationExpiry ?? reqObj.authorizationExpiry ?? null;
    const rawPreExp = paymentInfo.preApprovalExpiry ?? reqObj.preApprovalExpiry ?? null;
    const rawRefundExp = paymentInfo.refundExpiry ?? reqObj.refundExpiry ?? null;
    const rawInfoHash = paymentInfo.paymentInfoHash ?? extra.paymentInfoHash ?? reqObj.paymentInfoHash ?? null;
    const rawFeeReceiver = paymentInfo.feeReceiver ?? reqObj.feeReceiver ?? null;
    const rawCollector = paymentInfo.collector ?? extra.collector ?? null;
    const rawEscrow = paymentInfo.escrowAddress ?? extra.escrowAddress ?? extra.escrow ?? null;

    authCapture = {
      operator: typeof rawOperator === 'string' && rawOperator.trim() ? rawOperator.trim() : null,
      minFeeBps: rawMinFee !== null && rawMinFee !== undefined ? tryParseAtomicBigInt(rawMinFee) : null,
      maxFeeBps: rawMaxFee !== null && rawMaxFee !== undefined ? tryParseAtomicBigInt(rawMaxFee) : null,
      authorizationExpiry: rawAuthExp !== null && rawAuthExp !== undefined ? tryParseAtomicBigInt(rawAuthExp) : null,
      preApprovalExpiry: rawPreExp !== null && rawPreExp !== undefined ? tryParseAtomicBigInt(rawPreExp) : null,
      refundExpiry: rawRefundExp !== null && rawRefundExp !== undefined ? tryParseAtomicBigInt(rawRefundExp) : null,
      paymentInfoHash: typeof rawInfoHash === 'string' && HEX32_RE.test(rawInfoHash.trim())
        ? rawInfoHash.trim().toLowerCase()
        : null,
      feeReceiver: typeof rawFeeReceiver === 'string' && rawFeeReceiver.trim() ? rawFeeReceiver.trim() : null,
      collector: typeof rawCollector === 'string' && rawCollector.trim() ? rawCollector.trim() : null,
      escrowAddress: typeof rawEscrow === 'string' && rawEscrow.trim() ? rawEscrow.trim() : null
    };
  }

  return {
    scheme,
    network,
    asset,
    payTo,
    amountAtomic: amountBig,
    amountAtomicString: amountBig !== null ? amountBig.toString() : null,
    authCapture,
    rawRequirement: reqObj
  };
}

/**
 * Extract one or more normalized payment challenge candidates from an HTTP 402 response,
 * `PAYMENT-REQUIRED` header string, or parsed x402 `PaymentRequired` JSON object.
 */
function extractPaymentChallenges(source) {
  if (!source) return [];
  let obj = null;
  if (typeof source === 'string') {
    obj = decodeFlexibleBase64JsonObject(source);
    if (!obj) {
      try {
        const parsed = JSON.parse(source);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) obj = parsed;
      } catch {
        obj = null;
      }
    }
  } else if (typeof source === 'object') {
    const hdr = extractHeader(source, 'payment-required') || extractHeader(source, 'x-payment-required');
    if (hdr) {
      obj = decodeFlexibleBase64JsonObject(hdr);
    }
    if (!obj && source.body && typeof source.body === 'object' && !Array.isArray(source.body)) {
      obj = source.body;
    }
    if (!obj && !Object.prototype.hasOwnProperty.call(source, 'headers')) {
      obj = source;
    }
  }

  if (!obj || typeof obj !== 'object') return [];
  if (Array.isArray(obj.accepts)) {
    return obj.accepts
      .map((item) => normalizeSingleRequirement(item, obj))
      .filter(Boolean);
  }
  const single = normalizeSingleRequirement(obj, obj);
  return single ? [single] : [];
}

/**
 * Create an in-memory, reservation-safe atomic spend & circuit-breaker ledger.
 */
function createMemorySpendLedger(options = {}) {
  const windowMs = Number.isFinite(options.windowMs) && options.windowMs > 0
    ? Math.floor(options.windowMs)
    : DEFAULT_WINDOW_MS;
  const maxTrackedOrigins = Number.isFinite(options.maxTrackedOrigins) && options.maxTrackedOrigins > 0
    ? Math.floor(options.maxTrackedOrigins)
    : 1024;
  const maxTrackedReceipts = Number.isFinite(options.maxTrackedReceipts) && options.maxTrackedReceipts > 0
    ? Math.floor(options.maxTrackedReceipts)
    : 4096;

  let committedSessionAtomic = 0n;
  let reservedSessionAtomic = 0n;
  let seq = 0;

  const origins = new Map();
  const reservations = new Map();
  const seenReceipts = new Set();

  function getOrCreateOriginState(origin) {
    const key = String(origin).toLowerCase();
    let st = origins.get(key);
    if (!st) {
      if (origins.size >= maxTrackedOrigins) {
        for (const [oldKey, oldSt] of origins.entries()) {
          if (oldSt.reservedAtomic === 0n) {
            origins.delete(oldKey);
            break;
          }
        }
      }
      st = {
        entries: [],
        reservedAtomic: 0n,
        consecutiveFailures: 0,
        cooldownUntilMs: 0,
        lastFailureReason: null
      };
      origins.set(key, st);
    }
    return st;
  }

  function pruneOriginWindow(st, nowMs) {
    const cutoff = nowMs - windowMs;
    let idx = 0;
    while (idx < st.entries.length && st.entries[idx].timestampMs <= cutoff) {
      idx++;
    }
    if (idx > 0) st.entries.splice(0, idx);
    let sum = 0n;
    for (const e of st.entries) sum += e.amountAtomic;
    return sum;
  }

  function recordSeenReceipt(receiptHash) {
    if (typeof receiptHash !== 'string' || !receiptHash) return;
    const norm = receiptHash.toLowerCase();
    if (seenReceipts.has(norm)) return;
    if (seenReceipts.size >= maxTrackedReceipts) {
      const oldest = seenReceipts.values().next().value;
      if (oldest !== undefined) seenReceipts.delete(oldest);
    }
    seenReceipts.add(norm);
  }

  return {
    get windowMs() {
      return windowMs;
    },

    isCircuitOpen(origin, nowMs = Date.now()) {
      const st = origins.get(String(origin).toLowerCase());
      if (!st) return { open: false, cooldownUntilMs: 0, consecutiveFailures: 0, lastFailureReason: null };
      if (st.cooldownUntilMs > nowMs) {
        return {
          open: true,
          cooldownUntilMs: st.cooldownUntilMs,
          consecutiveFailures: st.consecutiveFailures,
          lastFailureReason: st.lastFailureReason
        };
      }
      return {
        open: false,
        cooldownUntilMs: 0,
        consecutiveFailures: st.consecutiveFailures,
        lastFailureReason: st.lastFailureReason
      };
    },

    getUsage(origin, nowMs = Date.now()) {
      const st = origins.get(String(origin).toLowerCase());
      const originCommittedWindowAtomic = st ? pruneOriginWindow(st, nowMs) : 0n;
      const originReservedAtomic = st ? st.reservedAtomic : 0n;
      return {
        committedSessionAtomic,
        reservedSessionAtomic,
        activeSessionAtomic: committedSessionAtomic + reservedSessionAtomic,
        originCommittedWindowAtomic,
        originReservedAtomic,
        activeOriginWindowAtomic: originCommittedWindowAtomic + originReservedAtomic
      };
    },

    reserve({ origin, amountAtomic, scheme = 'exact', nowMs = Date.now() }) {
      const amt = parseAtomicBigInt(amountAtomic, 'amountAtomic');
      const key = String(origin).toLowerCase();
      const st = getOrCreateOriginState(key);
      pruneOriginWindow(st, nowMs);

      const reservationId = `rsv_${nowMs}_${++seq}`;
      st.reservedAtomic += amt;
      reservedSessionAtomic += amt;
      reservations.set(reservationId, {
        reservationId,
        origin: key,
        amountAtomic: amt,
        scheme: canonicalSchemeName(scheme) || 'exact',
        createdAtMs: nowMs
      });
      return reservationId;
    },

    commit(reservationId, { actualAmountAtomic, receiptHash, nowMs = Date.now() } = {}) {
      const rsv = reservations.get(reservationId);
      if (!rsv) return false;
      reservations.delete(reservationId);

      const st = getOrCreateOriginState(rsv.origin);
      st.reservedAtomic -= rsv.amountAtomic;
      reservedSessionAtomic -= rsv.amountAtomic;

      const settledAmt = actualAmountAtomic !== undefined && actualAmountAtomic !== null
        ? parseAtomicBigInt(actualAmountAtomic, 'actualAmountAtomic')
        : rsv.amountAtomic;

      if (settledAmt > 0n) {
        st.entries.push({ amountAtomic: settledAmt, timestampMs: nowMs });
        committedSessionAtomic += settledAmt;
      }
      st.consecutiveFailures = 0;
      st.cooldownUntilMs = 0;
      st.lastFailureReason = null;
      if (receiptHash) recordSeenReceipt(receiptHash);
      return true;
    },

    release(reservationId, {
      recordFailure = false,
      failureReason = null,
      retainOutlayInBudget = false,
      maxConsecutiveFailures = DEFAULT_MAX_CONSECUTIVE_FAILURES,
      cooldownMs = DEFAULT_COOLDOWN_MS,
      nowMs = Date.now()
    } = {}) {
      const rsv = reservations.get(reservationId);
      if (!rsv) return false;
      reservations.delete(reservationId);

      const st = getOrCreateOriginState(rsv.origin);
      st.reservedAtomic -= rsv.amountAtomic;
      reservedSessionAtomic -= rsv.amountAtomic;

      if (retainOutlayInBudget && rsv.amountAtomic > 0n) {
        st.entries.push({ amountAtomic: rsv.amountAtomic, timestampMs: nowMs });
        committedSessionAtomic += rsv.amountAtomic;
      }

      if (recordFailure) {
        st.consecutiveFailures += 1;
        st.lastFailureReason = failureReason || 'delivery_rejected';
        if (st.consecutiveFailures >= maxConsecutiveFailures) {
          st.cooldownUntilMs = nowMs + cooldownMs;
        }
      }
      return true;
    },

    recordOriginFailure(origin, {
      failureReason = 'delivery_rejected',
      maxConsecutiveFailures = DEFAULT_MAX_CONSECUTIVE_FAILURES,
      cooldownMs = DEFAULT_COOLDOWN_MS,
      nowMs = Date.now()
    } = {}) {
      const st = getOrCreateOriginState(origin);
      st.consecutiveFailures += 1;
      st.lastFailureReason = failureReason;
      if (st.consecutiveFailures >= maxConsecutiveFailures) {
        st.cooldownUntilMs = nowMs + cooldownMs;
      }
      return {
        consecutiveFailures: st.consecutiveFailures,
        cooldownUntilMs: st.cooldownUntilMs,
        circuitTripped: st.cooldownUntilMs > nowMs
      };
    },

    hasSeenReceipt(receiptHash) {
      if (typeof receiptHash !== 'string' || !receiptHash) return false;
      return seenReceipts.has(receiptHash.toLowerCase());
    },

    recordReceipt(receiptHash) {
      recordSeenReceipt(receiptHash);
    },

    snapshot(nowMs = Date.now()) {
      const originMap = Object.create(null);
      for (const [k, st] of origins.entries()) {
        const windowCommitted = pruneOriginWindow(st, nowMs);
        originMap[k] = {
          committedWindowAtomic: windowCommitted,
          reservedAtomic: st.reservedAtomic,
          consecutiveFailures: st.consecutiveFailures,
          cooldownUntilMs: st.cooldownUntilMs,
          circuitOpen: st.cooldownUntilMs > nowMs,
          lastFailureReason: st.lastFailureReason
        };
      }
      return {
        committedSessionAtomic,
        reservedSessionAtomic,
        activeSessionAtomic: committedSessionAtomic + reservedSessionAtomic,
        activeReservations: reservations.size,
        trackedReceiptHashes: seenReceipts.size,
        origins: originMap
      };
    }
  };
}

function validatePolicyConfig(policy) {
  if (!policy || typeof policy !== 'object') {
    throw new TypeError('BuyerFirewallPolicy object is required');
  }
  const caps = {
    maxPerCallAtomic: policy.maxPerCallAtomic !== undefined && policy.maxPerCallAtomic !== null
      ? parseAtomicBigInt(policy.maxPerCallAtomic, 'policy.maxPerCallAtomic')
      : null,
    maxPerOriginWindowAtomic: policy.maxPerOriginWindowAtomic !== undefined && policy.maxPerOriginWindowAtomic !== null
      ? parseAtomicBigInt(policy.maxPerOriginWindowAtomic, 'policy.maxPerOriginWindowAtomic')
      : null,
    maxSessionAtomic: policy.maxSessionAtomic !== undefined && policy.maxSessionAtomic !== null
      ? parseAtomicBigInt(policy.maxSessionAtomic, 'policy.maxSessionAtomic')
      : null,
    maxUnescrowedExactAtomic: policy.maxUnescrowedExactAtomic !== undefined && policy.maxUnescrowedExactAtomic !== null
      ? parseAtomicBigInt(policy.maxUnescrowedExactAtomic, 'policy.maxUnescrowedExactAtomic')
      : null,
    maxAllowedFeeBps: policy.maxAllowedFeeBps !== undefined && policy.maxAllowedFeeBps !== null
      ? parseAtomicBigInt(policy.maxAllowedFeeBps, 'policy.maxAllowedFeeBps')
      : MAX_FEE_BPS_CEILING
  };
  if (caps.maxAllowedFeeBps > MAX_FEE_BPS_CEILING) {
    throw new RangeError('policy.maxAllowedFeeBps cannot exceed 10000 (100%)');
  }
  return caps;
}

function evaluateCandidateAgainstPolicy(candidate, origin, policy, caps, nowSec) {
  if (
    !candidate ||
    !candidate.scheme ||
    !candidate.network ||
    !candidate.payTo ||
    candidate.amountAtomic === null
  ) {
    return {
      ok: false,
      code: 'malformed_challenge',
      reason: '402 challenge is missing required scheme, network, payTo, or integer atomic amount.'
    };
  }

  if (candidate.amountAtomic === 0n && policy.allowZeroAmount !== true) {
    return {
      ok: false,
      code: 'malformed_challenge',
      reason: 'Zero-amount 402 payment challenge is disallowed unless policy.allowZeroAmount is true.'
    };
  }

  const allowedSchemes = Array.isArray(policy.allowedSchemes) && policy.allowedSchemes.length > 0
    ? policy.allowedSchemes.map((s) => canonicalSchemeName(s)).filter(Boolean)
    : DEFAULT_ALLOWED_SCHEMES;
  if (!allowedSchemes.includes(candidate.scheme)) {
    return {
      ok: false,
      code: 'scheme_not_allowed',
      reason: `Payment scheme "${candidate.scheme}" is not in policy.allowedSchemes.`
    };
  }

  if (Array.isArray(policy.allowedNetworks) && policy.allowedNetworks.length > 0) {
    const normNets = new Set(policy.allowedNetworks.map((n) => normalizeCaip2NetworkId(n)).filter(Boolean));
    if (!normNets.has(candidate.network)) {
      return {
        ok: false,
        code: 'network_not_allowed',
        reason: `Payment network "${candidate.network}" is not in policy.allowedNetworks.`
      };
    }
  }

  if (Array.isArray(policy.allowedAssets) && policy.allowedAssets.length > 0) {
    const normAssets = new Set(policy.allowedAssets.map((a) => normalizePayToId(String(a))));
    if (!candidate.asset || !normAssets.has(normalizePayToId(candidate.asset))) {
      return {
        ok: false,
        code: 'asset_not_allowed',
        reason: `Payment asset "${candidate.asset}" is not in policy.allowedAssets.`
      };
    }
  }

  const normCandidatePayTo = normalizePayToId(candidate.payTo);
  if (policy.pinnedPayToByOrigin && typeof policy.pinnedPayToByOrigin === 'object') {
    let pinnedRaw;
    for (const [k, v] of Object.entries(policy.pinnedPayToByOrigin)) {
      if (k.toLowerCase() === origin) {
        pinnedRaw = v;
        break;
      }
    }
    if (pinnedRaw !== undefined && pinnedRaw !== null) {
      const allowedList = Array.isArray(pinnedRaw) ? pinnedRaw : [pinnedRaw];
      const allowedSet = new Set(allowedList.map((x) => normalizePayToId(String(x))));
      if (!allowedSet.has(normCandidatePayTo)) {
        return {
          ok: false,
          code: 'untrusted_pay_to',
          reason: `Challenge payTo (${candidate.payTo}) does not match pinnedPayToByOrigin for ${origin}.`
        };
      }
    }
  }

  if (Array.isArray(policy.allowedPayTo) && policy.allowedPayTo.length > 0) {
    const allowedSet = new Set(policy.allowedPayTo.map((x) => normalizePayToId(String(x))));
    if (!allowedSet.has(normCandidatePayTo)) {
      return {
        ok: false,
        code: 'untrusted_pay_to',
        reason: `Challenge payTo (${candidate.payTo}) is not in policy.allowedPayTo.`
      };
    }
  }

  if (caps.maxPerCallAtomic !== null && candidate.amountAtomic > caps.maxPerCallAtomic) {
    return {
      ok: false,
      code: 'per_call_cap_exceeded',
      reason: `Requested amount (${candidate.amountAtomic}) exceeds maxPerCallAtomic (${caps.maxPerCallAtomic}).`
    };
  }

  if (
    candidate.scheme === 'exact' &&
    caps.maxUnescrowedExactAtomic !== null &&
    candidate.amountAtomic > caps.maxUnescrowedExactAtomic
  ) {
    return {
      ok: false,
      code: 'escrow_required_above_microcap',
      reason: `Irreversible "exact" amount (${candidate.amountAtomic}) exceeds maxUnescrowedExactAtomic (${caps.maxUnescrowedExactAtomic}); auth-capture escrow required.`
    };
  }

  if (candidate.scheme === 'auth-capture') {
    const ac = candidate.authCapture;
    if (!ac || !ac.operator || !EVM_ADDRESS_RE.test(ac.operator)) {
      return {
        ok: false,
        code: 'invalid_escrow_terms',
        reason: 'auth-capture challenge must provide a valid EVM operator address in extra/paymentInfo.'
      };
    }

    if (Array.isArray(policy.trustedOperators) && policy.trustedOperators.length > 0) {
      const trustedSet = new Set(policy.trustedOperators.map((op) => normalizePayToId(String(op))));
      if (!trustedSet.has(normalizePayToId(ac.operator))) {
        return {
          ok: false,
          code: 'untrusted_escrow_operator',
          reason: `Escrow operator (${ac.operator}) is not in policy.trustedOperators.`
        };
      }
    } else if (policy.allowUnpinnedEscrowOperator !== true) {
      return {
        ok: false,
        code: 'untrusted_escrow_operator',
        reason: 'auth-capture requires policy.trustedOperators (unless allowUnpinnedEscrowOperator is explicitly true).'
      };
    }

    if (ac.maxFeeBps === null || ac.minFeeBps === null || ac.minFeeBps > ac.maxFeeBps) {
      return {
        ok: false,
        code: 'invalid_escrow_terms',
        reason: 'auth-capture challenge must specify integer minFeeBps <= maxFeeBps.'
      };
    }
    if (ac.maxFeeBps > caps.maxAllowedFeeBps) {
      return {
        ok: false,
        code: 'escrow_fee_cap_exceeded',
        reason: `Escrow maxFeeBps (${ac.maxFeeBps}) exceeds policy.maxAllowedFeeBps (${caps.maxAllowedFeeBps}).`
      };
    }

    const minWindowSec = BigInt(
      Number.isFinite(policy.minAuthWindowSec) && policy.minAuthWindowSec >= 0
        ? Math.floor(policy.minAuthWindowSec)
        : DEFAULT_MIN_AUTH_WINDOW_SEC
    );
    const maxWindowSec = BigInt(
      Number.isFinite(policy.maxAuthWindowSec) && policy.maxAuthWindowSec > 0
        ? Math.floor(policy.maxAuthWindowSec)
        : DEFAULT_MAX_AUTH_WINDOW_SEC
    );
    if (
      ac.authorizationExpiry === null ||
      ac.authorizationExpiry < nowSec + minWindowSec ||
      ac.authorizationExpiry > nowSec + maxWindowSec
    ) {
      return {
        ok: false,
        code: 'escrow_expiry_out_of_bounds',
        reason: `Escrow authorizationExpiry (${ac.authorizationExpiry}) must fall within [${nowSec + minWindowSec}, ${nowSec + maxWindowSec}].`
      };
    }
  }

  return { ok: true };
}

/**
 * Gate 1: Evaluate a 402 payment challenge BEFORE invoking any wallet signer.
 * Atomically reserves budget in `ledger` when allowed. Never throws on wire input.
 */
function evaluatePreSignPolicy(input = {}, policy = {}, ledger = null) {
  const caps = validatePolicyConfig(policy);
  const nowMs = typeof input.nowMs === 'number' && Number.isFinite(input.nowMs) ? input.nowMs : Date.now();
  const nowSec = BigInt(Math.floor(nowMs / 1000));

  const deny = (code, reason, extra = {}) => ({
    allow: false,
    code,
    reason,
    origin: extra.origin ?? null,
    challenge: extra.challenge ?? null,
    reservationId: null,
    reservedAtomic: 0n
  });

  const originRes = resolveFirewallOrigin(input.url, {
    allowLoopbackHttp: Boolean(policy.allowLoopbackHttp)
  });
  if (!originRes.ok) {
    return deny(originRes.code, originRes.reason);
  }
  const { origin } = originRes;

  if (Array.isArray(policy.deniedOrigins) && policy.deniedOrigins.length > 0) {
    const denied = new Set(policy.deniedOrigins.map((o) => String(o).trim().toLowerCase()));
    if (denied.has(origin)) {
      return deny('origin_denied', `Origin ${origin} is blocked by policy.deniedOrigins.`, { origin });
    }
  }

  if (Array.isArray(policy.allowedOrigins) && policy.allowedOrigins.length > 0) {
    const allowed = new Set(policy.allowedOrigins.map((o) => String(o).trim().toLowerCase()));
    if (!allowed.has(origin)) {
      return deny('origin_not_allowed', `Origin ${origin} is not in policy.allowedOrigins.`, { origin });
    }
  }

  if (ledger && typeof ledger.isCircuitOpen === 'function') {
    const cb = ledger.isCircuitOpen(origin, nowMs);
    if (cb.open) {
      return deny(
        'circuit_breaker_open',
        `Circuit breaker open for ${origin} until ${new Date(cb.cooldownUntilMs).toISOString()} (${cb.consecutiveFailures} consecutive failures; last: ${cb.lastFailureReason}).`,
        { origin }
      );
    }
  }

  const candidates = extractPaymentChallenges(input.challenge ?? input.response);
  if (candidates.length === 0) {
    return deny('malformed_challenge', 'No decodable x402 payment challenge found in 402 response.', { origin });
  }

  // Prefer auth-capture over exact when multiple accepts exist and amount exceeds microcap
  const ordered = [...candidates].sort((a, b) => {
    const aEscrow = a.scheme === 'auth-capture' ? 0 : 1;
    const bEscrow = b.scheme === 'auth-capture' ? 0 : 1;
    if (caps.maxUnescrowedExactAtomic !== null && a.amountAtomic !== null && a.amountAtomic > caps.maxUnescrowedExactAtomic) {
      return aEscrow - bEscrow;
    }
    return 0;
  });

  let selected = null;
  let firstError = null;
  for (const cand of ordered) {
    const check = evaluateCandidateAgainstPolicy(cand, origin, policy, caps, nowSec);
    if (check.ok) {
      selected = cand;
      break;
    }
    if (!firstError) firstError = { check, cand };
  }

  if (!selected) {
    return deny(firstError.check.code, firstError.check.reason, {
      origin,
      challenge: firstError.cand
    });
  }

  if (ledger && typeof ledger.getUsage === 'function') {
    const usage = ledger.getUsage(origin, nowMs);
    if (
      caps.maxPerOriginWindowAtomic !== null &&
      usage.activeOriginWindowAtomic + selected.amountAtomic > caps.maxPerOriginWindowAtomic
    ) {
      return deny(
        'origin_window_cap_exceeded',
        `Origin ${origin} spend (${usage.activeOriginWindowAtomic} + ${selected.amountAtomic}) exceeds maxPerOriginWindowAtomic (${caps.maxPerOriginWindowAtomic}).`,
        { origin, challenge: selected }
      );
    }
    if (
      caps.maxSessionAtomic !== null &&
      usage.activeSessionAtomic + selected.amountAtomic > caps.maxSessionAtomic
    ) {
      return deny(
        'session_budget_exceeded',
        `Session spend (${usage.activeSessionAtomic} + ${selected.amountAtomic}) exceeds maxSessionAtomic (${caps.maxSessionAtomic}).`,
        { origin, challenge: selected }
      );
    }
  }

  const reservationId = ledger && typeof ledger.reserve === 'function'
    ? ledger.reserve({
        origin,
        amountAtomic: selected.amountAtomic,
        scheme: selected.scheme,
        nowMs
      })
    : null;

  return {
    allow: true,
    code: 'allowed',
    reason: `Authorized ${selected.scheme} challenge for ${selected.amountAtomic} atomic units on ${selected.network}.`,
    origin,
    challenge: selected,
    reservationId,
    reservedAtomic: selected.amountAtomic
  };
}

function toRawBodyBytes(body) {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (isByteArray(body)) return asUint8Array(body);
  if (typeof body === 'string') return utf8ToBytes(body);
  return utf8ToBytes(JSON.stringify(body));
}

async function verifyRequestBinding(receipt, reqSpec, cryptoOpt) {
  if (!reqSpec || typeof reqSpec !== 'object') return { ok: true };
  const svc = receipt && receipt.payload && receipt.payload.service;
  const reqObj = receipt && receipt.payload && receipt.payload.request;
  if (!svc || !reqObj) {
    return { ok: false, reason: 'Receipt is missing service or request binding block.' };
  }

  if (reqSpec.method) {
    const wantMethod = String(reqSpec.method).toUpperCase();
    if (String(svc.method || '').toUpperCase() !== wantMethod) {
      return {
        ok: false,
        reason: `Receipt service.method (${svc.method}) does not match request method (${wantMethod}).`
      };
    }
  }

  if (reqSpec.url) {
    let parsed;
    try {
      parsed = new URL(String(reqSpec.url));
    } catch {
      return { ok: false, reason: `Invalid expected request.url: ${reqSpec.url}` };
    }
    const pathAndQuery = `${parsed.pathname}${parsed.search}`;
    const gotResource = String(svc.resource || '');
    if (gotResource !== parsed.href && gotResource !== pathAndQuery) {
      return {
        ok: false,
        reason: `Receipt service.resource (${gotResource}) does not match request URL (${parsed.href}).`
      };
    }
    const computedResourceHash = await sha256Hex(utf8ToBytes(gotResource), cryptoOpt);
    if (computedResourceHash !== reqObj.resourceHash) {
      return {
        ok: false,
        reason: `Receipt request.resourceHash (${reqObj.resourceHash}) != sha256(service.resource) (${computedResourceHash}).`
      };
    }
  }

  const hasBodySpec = Object.prototype.hasOwnProperty.call(reqSpec, 'body') ||
    Object.prototype.hasOwnProperty.call(reqSpec, 'bodyBytes');
  if (hasBodySpec) {
    const rawReqBytes = toRawBodyBytes(reqSpec.bodyBytes !== undefined ? reqSpec.bodyBytes : reqSpec.body);
    const rawBodyHash = await sha256Hex(rawReqBytes, cryptoOpt);
    let bodyMatches = reqObj.bodyHash === rawBodyHash;
    if (!bodyMatches && rawReqBytes.byteLength > 0) {
      try {
        const parsedReqJson = JSON.parse(bytesToUtf8(rawReqBytes));
        const jcsBodyHash = await hashCanonical(parsedReqJson, cryptoOpt);
        bodyMatches = reqObj.bodyHash === jcsBodyHash;
      } catch {
        bodyMatches = false;
      }
    }
    if (!bodyMatches) {
      return {
        ok: false,
        reason: `Receipt request.bodyHash (${reqObj.bodyHash}) does not match sent request body digest.`
      };
    }
  }

  const expectedRequestHash = await hashCanonical({
    bodyHash: reqObj.bodyHash,
    method: String(svc.method).toUpperCase(),
    resource: String(svc.resource)
  }, cryptoOpt);
  if (expectedRequestHash !== reqObj.requestHash) {
    return {
      ok: false,
      reason: `Receipt request.requestHash (${reqObj.requestHash}) does not match canonical { bodyHash, method, resource } digest.`
    };
  }

  return { ok: true };
}

function verifyPaymentBinding(receipt, expectedChallenge) {
  if (!expectedChallenge || typeof expectedChallenge !== 'object') return { ok: true };
  const pay = receipt && receipt.payload && receipt.payload.payment;
  if (!pay) return { ok: false, reason: 'Receipt is missing payload.payment.' };

  if (expectedChallenge.network) {
    const wantNet = normalizeCaip2NetworkId(expectedChallenge.network);
    const gotNet = normalizeCaip2NetworkId(pay.network);
    if (wantNet && gotNet !== wantNet) {
      return {
        ok: false,
        reason: `Receipt payment.network (${pay.network}) does not match expected network (${wantNet}).`
      };
    }
  }

  if (expectedChallenge.payTo) {
    const receiptPayTo = pay.payTo || (receipt.payload.issuer && receipt.payload.issuer.payTo) || null;
    if (!receiptPayTo || normalizePayToId(receiptPayTo) !== normalizePayToId(expectedChallenge.payTo)) {
      return {
        ok: false,
        reason: `Receipt payTo (${receiptPayTo}) does not match expected challenge payTo (${expectedChallenge.payTo}).`
      };
    }
  }

  if (expectedChallenge.amountAtomic !== undefined && expectedChallenge.amountAtomic !== null) {
    const wantAmt = parseAtomicBigInt(expectedChallenge.amountAtomic, 'expectedChallenge.amountAtomic');
    const gotAmt = tryParseAtomicBigInt(pay.amountAtomic);
    if (gotAmt === null || gotAmt > wantAmt || (wantAmt > 0n && gotAmt === 0n)) {
      return {
        ok: false,
        reason: `Receipt payment.amountAtomic (${pay.amountAtomic}) is inconsistent with authorized amount (${wantAmt}).`
      };
    }
  }

  return { ok: true };
}

/**
 * Gate 2: Evaluate an HTTP delivery + signed `Payment-Receipt` + domain content predicate,
 * returning a deterministic `CAPTURE` vs `VOID` decision for `AuthCaptureEscrow` operators
 * and updating the spend/circuit-breaker ledger. Never throws.
 */
async function evaluateDeliveryArbiter(input = {}, options = {}) {
  const safeOpts = options && typeof options === 'object' ? options : {};
  const ledger = safeOpts.ledger || null;
  const reservationId = input.reservationId || safeOpts.reservationId || null;
  const challenge = input.challenge || safeOpts.expectedChallenge || null;
  const scheme = canonicalSchemeName((challenge && challenge.scheme) || input.scheme || 'auth-capture') || 'auth-capture';
  const settlementFinality = scheme === 'exact' ? 'irreversible_exact' : 'escrow_hold';
  const paymentInfoHash = (challenge && challenge.authCapture && challenge.authCapture.paymentInfoHash) ||
    input.paymentInfoHash ||
    null;

  const nowMs = typeof safeOpts.nowMs === 'number' && Number.isFinite(safeOpts.nowMs) ? safeOpts.nowMs : Date.now();
  const maxResponseBytes = Number.isFinite(safeOpts.maxResponseBytes) && safeOpts.maxResponseBytes > 0
    ? Math.floor(safeOpts.maxResponseBytes)
    : DEFAULT_MAX_RESPONSE_BYTES;
  const maxConsecutiveFailures = Number.isFinite(safeOpts.maxConsecutiveFailures) && safeOpts.maxConsecutiveFailures > 0
    ? Math.floor(safeOpts.maxConsecutiveFailures)
    : DEFAULT_MAX_CONSECUTIVE_FAILURES;
  const cooldownMs = Number.isFinite(safeOpts.cooldownMs) && safeOpts.cooldownMs > 0
    ? Math.floor(safeOpts.cooldownMs)
    : DEFAULT_COOLDOWN_MS;
  const cryptoOpt = safeOpts.crypto ? { crypto: safeOpts.crypto } : {};

  let origin = input.origin || null;
  if (!origin && input.request && input.request.url) {
    try {
      origin = new URL(String(input.request.url)).origin.toLowerCase();
    } catch {
      origin = null;
    }
  }

  const response = input.response || {};
  const status = typeof response.status === 'number' ? response.status : 200;
  const rawBodyBytes = toRawBodyBytes(input.bodyBytes !== undefined ? input.bodyBytes : input.body);

  const settleVoid = async (reasonCode, reason, extra = {}) => {
    if (ledger) {
      if (reservationId && typeof ledger.release === 'function') {
        ledger.release(reservationId, {
          recordFailure: true,
          failureReason: reasonCode,
          retainOutlayInBudget: settlementFinality === 'irreversible_exact',
          maxConsecutiveFailures,
          cooldownMs,
          nowMs
        });
      } else if (origin && typeof ledger.recordOriginFailure === 'function') {
        ledger.recordOriginFailure(origin, {
          failureReason: reasonCode,
          maxConsecutiveFailures,
          cooldownMs,
          nowMs
        });
      }
    }

    let bodySha256 = null;
    try {
      bodySha256 = await sha256Hex(rawBodyBytes, cryptoOpt);
    } catch {
      bodySha256 = null;
    }

    const receipt = extra.receipt || null;
    const verification = extra.verification || null;
    const nonRepudiable = Boolean(
      verification &&
      verification.checks &&
      verification.checks.signature === 'pass' &&
      verification.checks.outputHash === 'pass'
    );

    const fraudEvidence = {
      recordedAt: new Date(nowMs).toISOString(),
      reasonCode,
      reason,
      nonRepudiable,
      origin,
      status,
      paymentInfoHash,
      settlementFinality,
      issuerKeyId: receipt && receipt.signature ? receipt.signature.keyId : null,
      issuerPublicKey: receipt && receipt.signature ? receipt.signature.publicKey : null,
      receiptId: receipt && receipt.payload ? receipt.payload.receiptId : null,
      receiptHash: verification ? verification.receiptHash : null,
      claimedOutputHash: receipt && receipt.payload && receipt.payload.delivery
        ? receipt.payload.delivery.outputHash
        : null,
      observedBodySha256: bodySha256,
      rawReceiptHeader: extra.rawReceiptHeader || null
    };

    return {
      action: 'VOID',
      ok: false,
      reasonCode,
      reason,
      settlementFinality,
      paymentInfoHash,
      captureAmountAtomic: 0n,
      receipt,
      receiptHash: verification ? verification.receiptHash : null,
      verification,
      parsedOutput: extra.parsedOutput !== undefined ? extra.parsedOutput : null,
      fraudEvidence
    };
  };

  // (1) HTTP transport status & size bounds
  if (status < 200 || status >= 300) {
    return settleVoid('http_error_after_auth', `Upstream returned non-2xx HTTP status (${status}) after payment authorization.`);
  }
  if (rawBodyBytes.byteLength > maxResponseBytes) {
    return settleVoid('response_too_large', `Response body (${rawBodyBytes.byteLength} bytes) exceeds maxResponseBytes (${maxResponseBytes}).`);
  }

  // (2) Receipt extraction
  const rawReceiptHeader = extractHeader(response, STANDARD_RECEIPT_HEADER_NAME) ||
    (safeOpts.strictStandardHeaderOnly ? undefined : extractHeader(response, RECEIPT_HEADER_NAME)) ||
    input.receiptHeader;

  let receipt = input.receipt || null;
  if (!receipt && rawReceiptHeader) {
    try {
      receipt = decodeReceiptHeader(rawReceiptHeader);
    } catch (err) {
      return settleVoid(
        'malformed_receipt_header',
        `Malformed Payment-Receipt header: ${(err && err.message) || err}`,
        { rawReceiptHeader }
      );
    }
  }

  const requireReceipt = safeOpts.requireReceipt !== false;
  if (!receipt && requireReceipt) {
    return settleVoid('missing_delivery_receipt', 'Seller response omitted required Payment-Receipt header.');
  }

  let parsedOutput = rawBodyBytes;
  let verification = null;

  // (3) Cryptographic verification & request/payment/replay binding
  if (receipt) {
    const canonMode = (receipt.payload && receipt.payload.delivery && receipt.payload.delivery.canonicalization) || 'jcs-sha256';
    if (canonMode === 'jcs-sha256') {
      try {
        parsedOutput = JSON.parse(bytesToUtf8(rawBodyBytes));
      } catch {
        return settleVoid(
          'invalid_json_output',
          'Receipt specifies jcs-sha256 canonicalization, but HTTP body is not valid UTF-8 JSON.',
          { receipt, rawReceiptHeader }
        );
      }
    }

    const expectedPayTo = safeOpts.expectedPayTo || (challenge && challenge.payTo) || undefined;
    verification = await verifyReceipt(receipt, {
      output: canonMode === 'jcs-sha256' ? parsedOutput : rawBodyBytes,
      expectedIssuerPublicKeys: safeOpts.expectedIssuerPublicKeys,
      expectedPayTo,
      trustedVerifierPublicKeys: safeOpts.trustedVerifierPublicKeys,
      now: nowMs,
      crypto: safeOpts.crypto
    });

    const allowUncheckedClaim = safeOpts.allowUncheckedSettlementClaim !== false;
    const cryptoAccepted = verification.trustState === 'verified' || (
      allowUncheckedClaim &&
      verification.trustState === 'settlement_claimed_not_checked' &&
      verification.checks.signature === 'pass' &&
      verification.checks.outputHash === 'pass' &&
      verification.checks.issuerAuthorization !== 'fail'
    );

    if (!cryptoAccepted) {
      return settleVoid(
        `receipt_${verification.trustState}`,
        verification.summary || `Receipt failed verification with trustState=${verification.trustState}.`,
        { receipt, verification, rawReceiptHeader, parsedOutput }
      );
    }

    if (ledger && typeof ledger.hasSeenReceipt === 'function' && verification.receiptHash) {
      if (ledger.hasSeenReceipt(verification.receiptHash)) {
        return settleVoid(
          'replayed_receipt',
          `Replay detected: receiptHash ${verification.receiptHash} was already consumed in this session.`,
          { receipt, verification, rawReceiptHeader, parsedOutput }
        );
      }
    }

    if (safeOpts.enforceRequestBinding !== false && input.request) {
      const reqBind = await verifyRequestBinding(receipt, input.request, cryptoOpt);
      if (!reqBind.ok) {
        return settleVoid(
          'request_binding_mismatch',
          reqBind.reason,
          { receipt, verification, rawReceiptHeader, parsedOutput }
        );
      }
    }

    if (safeOpts.enforcePaymentBinding !== false && challenge) {
      const payBind = verifyPaymentBinding(receipt, challenge);
      if (!payBind.ok) {
        return settleVoid(
          'payment_binding_mismatch',
          payBind.reason,
          { receipt, verification, rawReceiptHeader, parsedOutput }
        );
      }
    }
  } else {
    const ct = String(extractHeader(response, 'content-type') || '').toLowerCase();
    if (ct.includes('json')) {
      try {
        parsedOutput = JSON.parse(bytesToUtf8(rawBodyBytes));
      } catch {
        parsedOutput = rawBodyBytes;
      }
    }
  }

  // (4) Domain content predicate (Regime I / II / III validation)
  let captureAmountAtomic = challenge && challenge.amountAtomic !== null && challenge.amountAtomic !== undefined
    ? parseAtomicBigInt(challenge.amountAtomic, 'challenge.amountAtomic')
    : (receipt && receipt.payload && receipt.payload.payment
      ? (tryParseAtomicBigInt(receipt.payload.payment.amountAtomic) ?? 0n)
      : 0n);

  if (typeof safeOpts.validateContent === 'function') {
    let predResult;
    try {
      predResult = await safeOpts.validateContent(parsedOutput, {
        request: input.request || null,
        response,
        receipt,
        verification,
        rawBodyBytes
      });
    } catch (err) {
      return settleVoid(
        'content_rejected',
        `Domain content validator threw: ${(err && err.message) || err}`,
        { receipt, verification, rawReceiptHeader, parsedOutput }
      );
    }

    if (predResult === false || (predResult && typeof predResult === 'object' && predResult.ok === false)) {
      const customReason = (predResult && typeof predResult === 'object' && predResult.reason)
        ? String(predResult.reason)
        : 'Domain content predicate rejected delivered payload.';
      return settleVoid(
        'content_rejected',
        customReason,
        { receipt, verification, rawReceiptHeader, parsedOutput }
      );
    }

    if (
      predResult &&
      typeof predResult === 'object' &&
      predResult.captureAmountAtomic !== undefined &&
      predResult.captureAmountAtomic !== null
    ) {
      const overrideAmt = parseAtomicBigInt(predResult.captureAmountAtomic, 'captureAmountAtomic');
      if (challenge && challenge.amountAtomic !== null && overrideAmt > challenge.amountAtomic) {
        return settleVoid(
          'capture_exceeds_authorized',
          `Validator requested captureAmountAtomic (${overrideAmt}) exceeding authorized amount (${challenge.amountAtomic}).`,
          { receipt, verification, rawReceiptHeader, parsedOutput }
        );
      }
      captureAmountAtomic = overrideAmt;
    }
  }

  // (5) All gates passed -> CAPTURE
  if (ledger) {
    if (reservationId && typeof ledger.commit === 'function') {
      ledger.commit(reservationId, {
        actualAmountAtomic: captureAmountAtomic,
        receiptHash: verification ? verification.receiptHash : null,
        nowMs
      });
    } else if (verification && verification.receiptHash && typeof ledger.recordReceipt === 'function') {
      ledger.recordReceipt(verification.receiptHash);
    }
  }

  return {
    action: 'CAPTURE',
    ok: true,
    reasonCode: 'verified_delivery',
    reason: 'Delivery verified: HTTP 2xx, receipt signature/bindings valid, and content predicate passed.',
    settlementFinality,
    paymentInfoHash,
    captureAmountAtomic,
    receipt,
    receiptHash: verification ? verification.receiptHash : null,
    verification,
    parsedOutput,
    fraudEvidence: null
  };
}

async function readBoundedBytes(response, maxBytes) {
  if (!response) return { ok: true, bytes: new Uint8Array(0) };
  if (response.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const u8 = asUint8Array(value);
      total += u8.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch { /* ignore */ }
        return { ok: false, byteLength: total };
      }
      chunks.push(u8);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.byteLength;
    }
    return { ok: true, bytes: merged };
  }
  if (typeof response.arrayBuffer === 'function') {
    const ab = await response.arrayBuffer();
    if (ab.byteLength > maxBytes) return { ok: false, byteLength: ab.byteLength };
    return { ok: true, bytes: new Uint8Array(ab) };
  }
  if (typeof response.text === 'function') {
    const txt = await response.text();
    const b = utf8ToBytes(txt);
    if (b.byteLength > maxBytes) return { ok: false, byteLength: b.byteLength };
    return { ok: true, bytes: b };
  }
  return { ok: true, bytes: new Uint8Array(0) };
}

/**
 * Wrap `fetch` with Gate 1 (`evaluatePreSignPolicy`) + caller wallet signer + Gate 2 (`evaluateDeliveryArbiter`).
 * Prevents redirects (`redirect: 'error'`) so signed `PAYMENT-SIGNATURE` headers never leak cross-origin.
 */
function createGuardedFetch(options = {}) {
  const {
    policy,
    ledger = createMemorySpendLedger(),
    signPayment,
    fetchImpl = globalThis.fetch,
    expectedIssuerPublicKeys,
    trustedVerifierPublicKeys,
    requireReceipt = true,
    validateContent,
    onCapture,
    onVoid,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    timeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
    crypto
  } = options;

  validatePolicyConfig(policy);
  if (typeof signPayment !== 'function') {
    throw new TypeError('createGuardedFetch requires a signPayment({ challenge, preSign, request }) callback');
  }
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('createGuardedFetch requires a valid fetch implementation');
  }

  return async function guardedFetch(urlOrRequest, init = {}, callOverrides = {}) {
    const targetUrl = typeof urlOrRequest === 'string'
      ? urlOrRequest
      : (urlOrRequest && typeof urlOrRequest.url === 'string' ? urlOrRequest.url : String(urlOrRequest));
    const method = String(
      init.method || (typeof urlOrRequest === 'object' && urlOrRequest.method) || 'GET'
    ).toUpperCase();
    const reqBodyBytes = init.body !== undefined ? toRawBodyBytes(init.body) : undefined;

    // Fast fail on origin/transport/circuit-breaker BEFORE making network round-trip
    const originCheck = resolveFirewallOrigin(targetUrl, {
      allowLoopbackHttp: Boolean(policy.allowLoopbackHttp)
    });
    if (!originCheck.ok) {
      return {
        ok: false,
        stage: 'pre_request',
        preSign: {
          allow: false,
          code: originCheck.code,
          reason: originCheck.reason,
          origin: null,
          challenge: null,
          reservationId: null,
          reservedAtomic: 0n
        },
        arbiter: null,
        response: null,
        bodyBytes: new Uint8Array(0),
        data: null
      };
    }

    const cb = ledger.isCircuitOpen(originCheck.origin);
    if (cb.open) {
      return {
        ok: false,
        stage: 'pre_request',
        preSign: {
          allow: false,
          code: 'circuit_breaker_open',
          reason: `Circuit breaker open for ${originCheck.origin}.`,
          origin: originCheck.origin,
          challenge: null,
          reservationId: null,
          reservedAtomic: 0n
        },
        arbiter: null,
        response: null,
        bodyBytes: new Uint8Array(0),
        data: null
      };
    }

    const execBoundedFetch = async (extraHeaders = null) => {
      const baseHeaders = new Headers(
        init.headers || (typeof urlOrRequest === 'object' && urlOrRequest.headers) || {}
      );
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) {
          if (v !== undefined && v !== null) baseHeaders.set(k, String(v));
        }
      }
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        return await fetchImpl(targetUrl, {
          ...init,
          method,
          headers: baseHeaders,
          redirect: 'error',
          signal: init.signal || ctrl.signal
        });
      } finally {
        clearTimeout(timer);
      }
    };

    const initialRes = await execBoundedFetch();
    if (initialRes.status !== 402) {
      const readRes = await readBoundedBytes(initialRes, maxResponseBytes);
      const rawBytes = readRes.ok ? readRes.bytes : new Uint8Array(0);
      return {
        ok: readRes.ok && initialRes.status >= 200 && initialRes.status < 300,
        stage: 'unpaid_pass_through',
        preSign: null,
        arbiter: null,
        response: initialRes,
        bodyBytes: rawBytes,
        data: null
      };
    }

    // Read optional 402 JSON body if header wasn't present
    const read402 = await readBoundedBytes(initialRes, 64 * 1024);
    let parsed402Body = null;
    if (read402.ok && read402.bytes.byteLength > 0) {
      try {
        parsed402Body = JSON.parse(bytesToUtf8(read402.bytes));
      } catch {
        parsed402Body = null;
      }
    }

    // Gate 1: Pre-Sign Policy Firewall
    const preSign = evaluatePreSignPolicy(
      {
        url: targetUrl,
        response: { headers: initialRes.headers, body: parsed402Body }
      },
      policy,
      ledger
    );

    if (!preSign.allow) {
      return {
        ok: false,
        stage: 'pre_sign',
        preSign,
        arbiter: null,
        response: initialRes,
        bodyBytes: new Uint8Array(0),
        data: null
      };
    }

    // Invoke caller's non-custodial wallet signer ONLY after Gate 1 passes
    let signedHeaders;
    try {
      const sigResult = await signPayment({
        challenge: preSign.challenge,
        preSign,
        request: { url: targetUrl, method, bodyBytes: reqBodyBytes }
      });
      if (typeof sigResult === 'string' && sigResult.trim()) {
        signedHeaders = { 'PAYMENT-SIGNATURE': sigResult.trim() };
      } else if (sigResult && typeof sigResult === 'object') {
        if (typeof sigResult.paymentSignature === 'string' && sigResult.paymentSignature.trim()) {
          signedHeaders = {
            'PAYMENT-SIGNATURE': sigResult.paymentSignature.trim(),
            ...(sigResult.headers || {})
          };
        } else if (sigResult.headers && typeof sigResult.headers === 'object') {
          signedHeaders = sigResult.headers;
        }
      }
      if (!signedHeaders || Object.keys(signedHeaders).length === 0) {
        throw new Error('signPayment did not return a PAYMENT-SIGNATURE header');
      }
    } catch (err) {
      ledger.release(preSign.reservationId, { recordFailure: false });
      throw err;
    }

    // Execute paid HTTP request (redirect: 'error' prevents credential/payment header leakage)
    let paidRes;
    try {
      paidRes = await execBoundedFetch(signedHeaders);
    } catch (err) {
      // Transport error after signing: keep irreversible exact outlay counted, release escrow hold
      const finality = preSign.challenge.scheme === 'exact' ? 'irreversible_exact' : 'escrow_hold';
      ledger.release(preSign.reservationId, {
        recordFailure: true,
        failureReason: 'network_error_after_sign',
        retainOutlayInBudget: finality === 'irreversible_exact',
        maxConsecutiveFailures: policy.maxConsecutiveFailures,
        cooldownMs: policy.cooldownMs
      });
      throw err;
    }

    const paidBodyRead = await readBoundedBytes(paidRes, maxResponseBytes);
    const rawPaidBytes = paidBodyRead.ok
      ? paidBodyRead.bytes
      : new Uint8Array(maxResponseBytes + 1);

    const resolvedIssuerKeys = callOverrides.expectedIssuerPublicKeys !== undefined
      ? callOverrides.expectedIssuerPublicKeys
      : (typeof expectedIssuerPublicKeys === 'function'
        ? await expectedIssuerPublicKeys(originCheck.origin)
        : expectedIssuerPublicKeys);

    // Gate 2: Post-Delivery Receipt & Content Arbiter
    const arbiter = await evaluateDeliveryArbiter(
      {
        origin: originCheck.origin,
        reservationId: preSign.reservationId,
        challenge: preSign.challenge,
        request: {
          url: targetUrl,
          method,
          ...(reqBodyBytes !== undefined ? { bodyBytes: reqBodyBytes } : {})
        },
        response: paidRes,
        bodyBytes: rawPaidBytes
      },
      {
        ledger,
        expectedIssuerPublicKeys: resolvedIssuerKeys,
        trustedVerifierPublicKeys,
        requireReceipt: callOverrides.requireReceipt ?? requireReceipt,
        validateContent: callOverrides.validateContent ?? validateContent,
        maxResponseBytes,
        maxConsecutiveFailures: policy.maxConsecutiveFailures,
        cooldownMs: policy.cooldownMs,
        crypto
      }
    );

    if (arbiter.action === 'CAPTURE' && typeof onCapture === 'function') {
      await onCapture(arbiter);
    } else if (arbiter.action === 'VOID' && typeof onVoid === 'function') {
      await onVoid(arbiter);
    }

    return {
      ok: arbiter.action === 'CAPTURE',
      stage: 'post_delivery',
      preSign,
      arbiter,
      response: paidRes,
      bodyBytes: paidBodyRead.ok ? rawPaidBytes : new Uint8Array(0),
      data: arbiter.parsedOutput
    };
  };
}

exports.ESCROW_SCHEMES = ESCROW_SCHEMES;
exports.DEFAULT_ALLOWED_SCHEMES = DEFAULT_ALLOWED_SCHEMES;
exports.normalizeCaip2NetworkId = normalizeCaip2NetworkId;
exports.parseAtomicBigInt = parseAtomicBigInt;
exports.resolveFirewallOrigin = resolveFirewallOrigin;
exports.extractPaymentChallenges = extractPaymentChallenges;
exports.createMemorySpendLedger = createMemorySpendLedger;
exports.evaluatePreSignPolicy = evaluatePreSignPolicy;
exports.evaluateDeliveryArbiter = evaluateDeliveryArbiter;
exports.createGuardedFetch = createGuardedFetch;
