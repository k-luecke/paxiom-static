// Public reference runtime for the Paxiom Receipt Verifier (`https://api.paxiom.org`, v0.2.0):
//   - Offline routes (`/health`, `/version`, `/v1/receipt/demo`, `POST /v1/receipt/verify`,
//     `GET /.well-known/x402-keys.json`, `GET /.well-known/paxiom-keys.json`, `POST /mcp`)
//     are always active with zero env vars and zero external calls.
//   - Free, rate-limited public reference routes (`POST /v1/receipt/verify-live` and
//     `POST /v1/x402/preflight`) activate when `LIVE_VERIFY_ENABLED=true` (enabled by
//     default on Render). Commercial x402/API-key gating is disabled by default on the
//     public reference host unless `PAXIOM_COMMERCIAL_GATE_ENABLED=true` is explicitly set.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyReceipt, RECEIPT_VERSION } from '../../standards/receipts/v0/src/verify.mjs';
import { issueReceipt, publicKeyFromPrivateKey } from '../../standards/receipts/v0/src/issue.mjs';
import {
  verifyOnchainUsdcSettlement,
  getSupportedNetworkConfig,
  EVM_ADDRESS_RE
} from './onchain-settlement.mjs';
import {
  authorizeMonetizedRequest,
  verifyMonetizedRequest,
  settleMonetizedRequest,
  buildX402PaymentRequirements,
  checkApiKey
} from './x402-gate.mjs';
import {
  validateTargetUrlLexical,
  validatePublicHttpsTarget,
  runX402Preflight
} from './x402-preflight.mjs';
import { handleMcpHttpRequest, buildMcpServerCard } from './mcp-http.mjs';

export const RUNTIME_VERSION = '0.2.0';
const MAX_BODY_BYTES = 256 * 1024; // 256 KiB
const MAX_DRAIN_AFTER_413 = 64 * 1024; // bounded post-413 drain window before destroying socket
const MAX_RATE_LIMIT_BUCKETS = 4096;

const EX = new URL('../../standards/receipts/v0/examples/', import.meta.url);
const demoReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const demoOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));
const openApiSpec = JSON.parse(
  readFileSync(new URL('../../standards/receipts/v0/openapi.json', import.meta.url), 'utf8')
);
let llmsTxtContent = '# Paxiom\nhttps://paxiom.org/llms.txt\n';
try {
  llmsTxtContent = readFileSync(new URL('../../llms.txt', import.meta.url), 'utf8');
} catch {
  // Fallback when runtime directory is deployed standalone without static site root
}

/**
 * Zero-dependency, bounded O(1)-memory per-IP rate limiter.
 */
export function createBoundedRateLimiter({
  windowMs = 60_000,
  maxBuckets = MAX_RATE_LIMIT_BUCKETS
} = {}) {
  const buckets = new Map();

  function sweepExpired(nowMs) {
    for (const [k, entry] of buckets.entries()) {
      if (entry.resetAt <= nowMs) buckets.delete(k);
    }
  }

  return function checkLimit(bucketKey, limitPerWindow, nowMs = Date.now()) {
    if (!Number.isFinite(limitPerWindow) || limitPerWindow <= 0) {
      return { allowed: true, limit: 0, remaining: 0, retryAfterSeconds: 0 };
    }
    let entry = buckets.get(bucketKey);
    if (!entry || entry.resetAt <= nowMs) {
      if (buckets.size >= maxBuckets) {
        sweepExpired(nowMs);
        if (buckets.size >= maxBuckets) {
          const oldestKey = buckets.keys().next().value;
          if (oldestKey !== undefined) buckets.delete(oldestKey);
        }
      }
      entry = { count: 1, resetAt: nowMs + windowMs };
      buckets.set(bucketKey, entry);
      return {
        allowed: true,
        limit: limitPerWindow,
        remaining: Math.max(0, limitPerWindow - 1),
        retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000))
      };
    }

    if (entry.count >= limitPerWindow) {
      return {
        allowed: false,
        limit: limitPerWindow,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((entry.resetAt - nowMs) / 1000))
      };
    }

    entry.count += 1;
    return {
      allowed: true,
      limit: limitPerWindow,
      remaining: Math.max(0, limitPerWindow - entry.count),
      retryAfterSeconds: Math.max(1, Math.ceil((entry.resetAt - nowMs) / 1000))
    };
  };
}

function resolveClientIp(req, env) {
  const trustProxy = isFlagEnabled(env.RENDER) || isFlagEnabled(env.TRUST_PROXY);
  if (trustProxy && req && req.headers) {
    const cfIp = String(req.headers['cf-connecting-ip'] || req.headers['true-client-ip'] || '').trim();
    if (cfIp) return cfIp.slice(0, 64);
    const xff = String(req.headers['x-forwarded-for'] || '').trim();
    if (xff) {
      const first = xff.split(',')[0].trim();
      if (first) return first.slice(0, 64);
    }
  }
  return String((req && req.socket && req.socket.remoteAddress) || 'local').slice(0, 64);
}

function parseRateLimit(rawVal, defaultLimit) {
  if (rawVal === undefined || rawVal === null || rawVal === '') return defaultLimit;
  const n = Number(rawVal);
  if (!Number.isFinite(n) || n < 0) return defaultLimit;
  return Math.floor(n);
}

function createFunnelStats() {
  const startedMs = Date.now();
  return {
    startedMs,
    startedAt: new Date(startedMs).toISOString(),
    discovery: {
      rootIndexReads: 0,
      openApiReads: 0,
      llmsTxtReads: 0,
      x402ManifestReads: 0,
      x402KeysReads: 0,
      didJsonReads: 0,
      paxiomKeysReads: 0,
      mcpCardReads: 0,
      mcpGetReads: 0,
      mcpJsonRpcCalls: 0,
      mcpToolCalls: {
        verify_receipt: 0,
        explain_receipt: 0,
        get_x402_verifier_info: 0
      }
    },
    offlineVerify: {
      demoReads: 0,
      calls: 0,
      validVerdicts: 0,
      invalidVerdicts: 0
    },
    verifyLive: {
      unpaid402Quotes: 0,
      rateLimited: 0,
      precheckRejected: 0,
      freePublicServed: 0,
      paidX402Settled: 0,
      paidApiKeyServed: 0,
      verifiedSettledUpgrades: 0
    },
    x402Preflight: {
      unpaid402Quotes: 0,
      rateLimited: 0,
      ssrfOrLexicalBlocked: 0,
      freePublicServed: 0,
      paidX402Settled: 0,
      paidApiKeyServed: 0,
      verdictProceed: 0,
      verdictCaution: 0,
      verdictBlock: 0
    }
  };
}

function snapshotFunnelStats(stats) {
  return {
    ok: true,
    service: 'paxiom-receipt-verifier',
    version: RUNTIME_VERSION,
    privacy: 'aggregate_counters_only_zero_pii',
    startedAt: stats.startedAt,
    uptimeSeconds: Math.max(0, Math.floor((Date.now() - stats.startedMs) / 1000)),
    discovery: {
      ...stats.discovery,
      mcpToolCalls: { ...stats.discovery.mcpToolCalls }
    },
    offlineVerify: { ...stats.offlineVerify },
    verifyLive: { ...stats.verifyLive },
    x402Preflight: { ...stats.x402Preflight }
  };
}

function buildRootServiceIndex(env = process.env) {
  const liveEnabled = isFlagEnabled(env.LIVE_VERIFY_ENABLED) || isFlagEnabled(env.X402_ENABLED);
  const x402Enabled = isFlagEnabled(env.X402_ENABLED);
  return {
    ok: true,
    service: 'paxiom-receipt-verifier',
    version: RUNTIME_VERSION,
    receiptVersion: RECEIPT_VERSION,
    license: 'MIT',
    docsUrl: 'https://paxiom.org/api.html',
    extensionSpecUrl: 'https://paxiom.org/standards/receipts/v0/x402-delivery-receipt-extension.md',
    sdk: {
      npm: '@paxiom/receipts',
      python: 'paxiom-receipts',
      pypiUrl: 'https://pypi.org/project/paxiom-receipts/'
    },
    discovery: {
      openApi: '/openapi.json',
      llmsTxt: '/llms.txt',
      mcpEndpoint: '/mcp',
      mcpCard: '/.well-known/mcp.json',
      x402Keys: '/.well-known/x402-keys.json',
      didJson: '/.well-known/did.json',
      paxiomKeys: '/.well-known/paxiom-keys.json',
      ...(x402Enabled ? { x402Manifest: '/.well-known/x402.json' } : {}),
      version: '/version',
      stats: '/stats'
    },
    endpoints: {
      freeOfflineVerify: 'POST /v1/receipt/verify',
      demoFixtures: 'GET /v1/receipt/demo',
      remoteMcp: 'POST /mcp',
      ...(liveEnabled
        ? {
            liveOnchainVerify: 'POST /v1/receipt/verify-live',
            x402SellerPreflight: 'POST /v1/x402/preflight'
          }
        : {})
    }
  };
}

const RENDER_PRODUCTION_DEFAULTS = Object.freeze({
  LIVE_VERIFY_ENABLED: 'true',
  BASE_RPC_URL: 'https://base-rpc.publicnode.com,https://mainnet.base.org,https://1rpc.io/base',
  BASE_SEPOLIA_RPC_URL: 'https://base-sepolia-rpc.publicnode.com,https://sepolia.base.org',
  X402_ENABLED: 'false',
  X402_NETWORK: 'base',
  X402_PRICE_ATOMIC: '2000',
  X402_PREFLIGHT_PRICE_ATOMIC: '10000',
  X402_PAY_TO: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
  X402_FACILITATOR_URL: 'https://facilitator.payai.network',
  X402_RESOURCE_URL: 'https://api.paxiom.org/v1/receipt/verify-live',
  X402_PREFLIGHT_RESOURCE_URL: 'https://api.paxiom.org/v1/x402/preflight',
  RATE_LIMIT_VERIFY_LIVE_PER_MIN: '60',
  RATE_LIMIT_PREFLIGHT_PER_MIN: '30'
});

export function resolveRuntimeEnv(rawEnv = process.env) {
  if (rawEnv && (rawEnv.RENDER === 'true' || rawEnv.PAXIOM_PRODUCTION_DEFAULTS === 'true')) {
    const merged = { ...RENDER_PRODUCTION_DEFAULTS };
    for (const [k, v] of Object.entries(rawEnv)) {
      if (v !== undefined && v !== '') merged[k] = v;
    }
    if (rawEnv.CDP_FACILITATOR_URL && !rawEnv.X402_FACILITATOR_URL) {
      merged.X402_FACILITATOR_URL = rawEnv.CDP_FACILITATOR_URL;
    }
    // Public reference utility guarantee: on Render production, ignore any legacy
    // X402_ENABLED / PAXIOM_API_KEYS dashboard variables unless PAXIOM_COMMERCIAL_GATE_ENABLED=true.
    if (!isFlagEnabled(rawEnv.PAXIOM_COMMERCIAL_GATE_ENABLED)) {
      merged.X402_ENABLED = 'false';
      merged.PAXIOM_API_KEYS = '';
    }
    return merged;
  }
  return rawEnv;
}

function buildVersionPayload(env = process.env) {
  const liveEnabled = isFlagEnabled(env.LIVE_VERIFY_ENABLED) || isFlagEnabled(env.X402_ENABLED);
  const x402Enabled = isFlagEnabled(env.X402_ENABLED);
  return {
    service: 'paxiom-receipt-verifier',
    version: RUNTIME_VERSION,
    receiptVersion: RECEIPT_VERSION,
    runtime: liveEnabled ? 'public-reference-live' : 'developer-preview',
    checks: [
      'schema',
      'signature',
      'issuerAuthorization',
      'outputHash',
      'bindingFields',
      'settlementStatusVocabulary',
      'evidenceStatusVocabulary',
      ...(liveEnabled ? ['onchainUsdcSettlement'] : [])
    ],
    notChecked: [
      ...(liveEnabled ? [] : ['onchainSettlement']),
      'facilitatorRecords',
      'proofSourceEvidence',
      'archiveAvailability'
    ],
    capabilities: {
      offlineVerification: true,
      signerKeyDiscovery: true,
      rawAndJcsPayloadBinding: true,
      liveSettlementVerification: liveEnabled,
      x402Preflight: liveEnabled,
      x402PaymentGating: x402Enabled,
      counterAttestation: Boolean(getConfiguredPaxiomKey(env))
    },
    rateLimits: liveEnabled && !x402Enabled
      ? {
          windowSeconds: Math.max(1, Math.floor((Number(env.RATE_LIMIT_WINDOW_MS) || 60_000) / 1000)),
          verifyLivePerMinute: parseRateLimit(env.RATE_LIMIT_VERIFY_LIVE_PER_MIN, 60),
          preflightPerMinute: parseRateLimit(env.RATE_LIMIT_PREFLIGHT_PER_MIN, 30)
        }
      : null,
    endpoints: {
      serviceIndex: 'GET /',
      openApi: 'GET /openapi.json',
      llmsTxt: 'GET /llms.txt',
      mcpCard: 'GET /.well-known/mcp.json',
      x402Keys: 'GET /.well-known/x402-keys.json',
      didJson: 'GET /.well-known/did.json',
      paxiomKeys: 'GET /.well-known/paxiom-keys.json',
      stats: 'GET /stats',
      freeOfflineVerify: 'POST /v1/receipt/verify',
      remoteMcp: 'POST /mcp',
      ...(liveEnabled ? {
        liveOnchainVerify: 'POST /v1/receipt/verify-live',
        x402SellerPreflight: 'POST /v1/x402/preflight'
      } : {})
    },
    x402Enabled,
    note: liveEnabled
      ? 'Free public reference verifier for paxiom.receipt.v0 (MIT). POST /v1/receipt/verify runs offline; POST /v1/receipt/verify-live confirms Base & Base Sepolia USDC Transfer logs via JSON-RPC; POST /v1/x402/preflight scans x402 seller endpoints before payment. Protected by per-IP burst rate limits.'
      : 'Developer-preview reference verifier for paxiom.receipt.v0. Verifies receipt schema, Ed25519 signature, signer authorization, and output binding offline. Free — no payment gating.'
  };
}

function isFlagEnabled(val) {
  return val === 'true' || val === '1';
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type, accept, authorization, x-api-key, payment-signature, x-payment, mcp-session-id, mcp-protocol-version',
  'Access-Control-Expose-Headers': 'Payment-Receipt, X-Paxiom-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE, Retry-After'
};

function send(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-content-type-options': 'nosniff',
    ...CORS,
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}

const errBody = (code, message) => ({ valid: false, trustState: 'error', error: { code, message } });

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (tooLarge) {
        if (size > MAX_BODY_BYTES + MAX_DRAIN_AFTER_413) req.destroy();
        return;
      }
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        chunks.length = 0;
        reject(Object.assign(new Error('body too large'), { code: 'body_too_large' }));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!tooLarge) resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
}

async function parseVerifyPayload(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch (err) {
    if (err.code === 'body_too_large') {
      send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`), { connection: 'close' });
      return null;
    }
    send(res, 400, errBody('read_error', 'Failed to read request body'));
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw || '{}');
  } catch {
    send(res, 400, errBody('invalid_json', 'Request body is not valid JSON'));
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || !parsed.receipt) {
    send(res, 400, errBody('missing_receipt', 'Request must be a JSON object with a "receipt" field'));
    return null;
  }
  return parsed;
}

function getConfiguredPaxiomKey(env) {
  const pem = env.PAXIOM_SIGNING_PRIVATE_KEY_PEM;
  if (!pem) return null;
  try {
    const publicKey = publicKeyFromPrivateKey(pem);
    const keyId = env.PAXIOM_SIGNING_KEY_ID || 'paxiom-live-verifier-001';
    return { privateKeyPem: pem, publicKey, keyId };
  } catch {
    return null;
  }
}

function precheckLiveSettlementEligibility(receipt) {
  const payment = receipt && receipt.payload && receipt.payload.payment;
  if (!payment || !payment.settlement || !payment.settlement.transactionHash) {
    return {
      eligible: false,
      reason: 'missing_transaction_hash',
      detail: 'Receipt does not contain a settlement.transactionHash to verify on-chain.'
    };
  }
  const netCfg = getSupportedNetworkConfig(String(payment.network || ''));
  if (!netCfg) {
    return {
      eligible: false,
      reason: 'unsupported_network',
      detail: `Unsupported payment.network "${payment.network}" for live on-chain verification.`
    };
  }
  if (String(payment.asset || '').toUpperCase() !== 'USDC' &&
      String(payment.asset || '').toLowerCase() !== netCfg.usdcAddress.toLowerCase()) {
    return {
      eligible: false,
      reason: 'unsupported_asset',
      detail: `Unsupported payment.asset "${payment.asset}"; v0 live verifier checks canonical USDC.`
    };
  }
  return { eligible: true, netCfg };
}

async function handleOfflineVerify(req, res, env, stats) {
  const parsed = await parseVerifyPayload(req, res);
  if (!parsed) return;
  try {
    const opts = {};
    if (Object.prototype.hasOwnProperty.call(parsed, 'output')) opts.output = parsed.output;
    if (Array.isArray(parsed.expectedIssuerPublicKeys)) {
      opts.expectedIssuerPublicKeys = parsed.expectedIssuerPublicKeys;
    }
    if (typeof parsed.expectedPayTo === 'string' && parsed.expectedPayTo.trim()) {
      opts.expectedPayTo = parsed.expectedPayTo;
    }
    if (Array.isArray(parsed.trustedVerifierPublicKeys)) {
      opts.trustedVerifierPublicKeys = parsed.trustedVerifierPublicKeys;
    } else if (Array.isArray(parsed.trustedPaxiomPublicKeys)) {
      opts.trustedPaxiomPublicKeys = parsed.trustedPaxiomPublicKeys;
    } else {
      const paxiomKey = getConfiguredPaxiomKey(env);
      if (paxiomKey) {
        opts.trustedVerifierPublicKeys = [paxiomKey.publicKey];
      }
    }
    const verdict = verifyReceipt(parsed.receipt, opts);
    if (stats) {
      stats.offlineVerify.calls += 1;
      if (verdict.valid) stats.offlineVerify.validVerdicts += 1;
      else stats.offlineVerify.invalidVerdicts += 1;
    }
    return send(res, 200, verdict);
  } catch (err) {
    return send(res, 500, errBody('verifier_error', String((err && err.message) || err)));
  }
}

async function handleLiveVerify(req, res, { env, fetchImpl, stats, checkRateLimit }) {
  const liveEnabled = isFlagEnabled(env.LIVE_VERIFY_ENABLED) || isFlagEnabled(env.X402_ENABLED);
  if (!liveEnabled) {
    return send(res, 503, errBody(
      'live_verify_disabled',
      'Live on-chain settlement verification is not enabled on this instance. Use POST /v1/receipt/verify for free offline verification.'
    ));
  }

  const hasPaymentOrAuthHeader = Boolean(
    req.headers && (
      req.headers['payment-signature'] ||
      req.headers['x-payment'] ||
      req.headers['x-api-key'] ||
      req.headers.authorization
    )
  );

  let rawBodyText = '';
  if (req.method === 'GET') {
    if (!hasPaymentOrAuthHeader && isFlagEnabled(env.X402_ENABLED) && env.X402_PAY_TO) {
      const auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
      if (stats && auth.status === 402) stats.verifyLive.unpaid402Quotes += 1;
      return send(res, auth.status, auth.body, auth.headers);
    }
    return send(res, 405, errBody('method_not_allowed', 'Send a JSON POST request with { receipt, output?, expectedPayTo? } to /v1/receipt/verify-live.'), { allow: 'POST, OPTIONS' });
  }

  // Enforce per-IP burst rate limit on unmetered public endpoints
  if (!isFlagEnabled(env.X402_ENABLED) && !checkApiKey(req, env).authorized && checkRateLimit) {
    const ip = resolveClientIp(req, env);
    const limit = parseRateLimit(env.RATE_LIMIT_VERIFY_LIVE_PER_MIN, 60);
    const rl = checkRateLimit(`verify-live:${ip}`, limit);
    if (!rl.allowed) {
      if (stats) stats.verifyLive.rateLimited += 1;
      return send(res, 429, errBody(
        'rate_limit_exceeded',
        `Rate limit exceeded (${rl.limit} requests/min per IP on public reference verifier). Retry after ${rl.retryAfterSeconds}s.`
      ), {
        'Retry-After': String(rl.retryAfterSeconds),
        'X-RateLimit-Limit': String(rl.limit),
        'X-RateLimit-Remaining': '0'
      });
    }
  }

  try {
    rawBodyText = await readBody(req);
  } catch (err) {
    if (err.code === 'body_too_large') {
      return send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`), { connection: 'close' });
    }
    return send(res, 400, errBody('read_error', 'Failed to read request body'));
  }

  let parsed;
  try {
    parsed = JSON.parse(rawBodyText || '{}');
  } catch {
    return send(res, 400, errBody('invalid_json', 'Request body is not valid JSON'));
  }

  if ((!parsed || typeof parsed !== 'object' || !parsed.receipt) &&
      !hasPaymentOrAuthHeader &&
      isFlagEnabled(env.X402_ENABLED) &&
      env.X402_PAY_TO) {
    const auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
    if (stats && auth.status === 402) stats.verifyLive.unpaid402Quotes += 1;
    return send(res, auth.status, auth.body, auth.headers);
  }

  if (typeof parsed !== 'object' || parsed === null || !parsed.receipt) {
    return send(res, 400, errBody('missing_receipt', 'Request must be a JSON object with a "receipt" field'));
  }

  if (!hasPaymentOrAuthHeader || (!isFlagEnabled(env.X402_ENABLED) && !checkApiKey(req, env).authorized)) {
    let authEarly;
    try {
      authEarly = await authorizeMonetizedRequest(req, { env, fetchImpl });
    } catch {
      return send(res, 502, errBody('payment_gate_error', 'Failed to contact x402 payment facilitator.'));
    }
    if (!authEarly.authorized) {
      if (stats && authEarly.status === 402) stats.verifyLive.unpaid402Quotes += 1;
      return send(res, authEarly.status, authEarly.body, authEarly.headers);
    }
  }

  const rawExpectedPayTo = Object.hasOwn(parsed, 'expectedPayTo') ? parsed.expectedPayTo : null;
  if (rawExpectedPayTo !== null && rawExpectedPayTo !== undefined && rawExpectedPayTo !== '' &&
      (typeof rawExpectedPayTo !== 'string' || !EVM_ADDRESS_RE.test(rawExpectedPayTo))) {
    return send(res, 400, errBody('invalid_expected_pay_to', 'expectedPayTo must be a 0x-prefixed 20-byte EVM hex address.'));
  }
  const normalizedExpectedPayTo = rawExpectedPayTo ? String(rawExpectedPayTo).toLowerCase() : null;

  const hasOutput = Object.prototype.hasOwnProperty.call(parsed, 'output') && parsed.output !== undefined;
  const paxiomKey = getConfiguredPaxiomKey(env);
  const rcptBoundPayTo = parsed.receipt?.payload?.payment?.payTo || parsed.receipt?.payload?.issuer?.payTo || null;
  const verifyOpts = {
    ...(hasOutput ? { output: parsed.output } : {}),
    ...(Array.isArray(parsed.expectedIssuerPublicKeys) ? { expectedIssuerPublicKeys: parsed.expectedIssuerPublicKeys } : {}),
    ...(normalizedExpectedPayTo && rcptBoundPayTo ? { expectedPayTo: normalizedExpectedPayTo } : {}),
    ...(paxiomKey ? { trustedVerifierPublicKeys: [paxiomKey.publicKey] } : {})
  };

  let baseResult;
  try {
    baseResult = verifyReceipt(parsed.receipt, verifyOpts);
  } catch {
    return send(res, 500, errBody('verifier_error', 'Offline receipt verification failed unexpectedly.'));
  }

  if (baseResult.trustState !== 'settlement_claimed_not_checked') {
    if (stats) stats.verifyLive.precheckRejected += 1;
    return send(res, 200, {
      ...baseResult,
      onchainSettlement: { checked: false, settled: false, reason: 'offline_verification_not_eligible' }
    });
  }

  const precheck = precheckLiveSettlementEligibility(parsed.receipt);
  if (!precheck.eligible) {
    if (stats) stats.verifyLive.precheckRejected += 1;
    return send(res, 200, {
      ...baseResult,
      valid: false,
      trustState: 'settlement_claimed_not_checked',
      onchainSettlement: {
        checked: false,
        settled: false,
        reason: precheck.reason,
        detail: precheck.detail
      },
      summary: precheck.detail
    });
  }

  let auth;
  try {
    auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
  } catch {
    return send(res, 502, errBody('payment_gate_error', 'Failed to contact x402 payment facilitator.'));
  }
  if (!auth.authorized) {
    if (stats && auth.status === 402) stats.verifyLive.unpaid402Quotes += 1;
    return send(res, auth.status, auth.body, auth.headers);
  }
  if (stats) {
    if (auth.mode === 'x402') stats.verifyLive.paidX402Settled += 1;
    else if (auth.mode === 'api_key') stats.verifyLive.paidApiKeyServed += 1;
    else stats.verifyLive.freePublicServed += 1;
  }

  let onchain;
  try {
    onchain = await verifyOnchainUsdcSettlement(parsed.receipt, {
      env,
      fetchImpl,
      expectedPayTo: normalizedExpectedPayTo,
      minConfirmations: Number(env.MIN_CONFIRMATIONS) || 1
    });
  } catch {
    return send(res, 502, errBody(
      'onchain_rpc_error',
      'Failed to query chain RPC for settlement verification.'
    ), auth.responseHeaders);
  }

  if (!onchain.settled) {
    const failedState = onchain.checked ? 'settlement_failed' : 'settlement_claimed_not_checked';
    return send(res, 200, {
      ...baseResult,
      valid: false,
      trustState: failedState,
      checks: {
        ...baseResult.checks,
        settlement: onchain.checked ? 'failed_onchain_check' : baseResult.checks.settlement
      },
      onchainSettlement: onchain,
      summary: onchain.detail
    }, auth.responseHeaders);
  }

  if (stats) stats.verifyLive.verifiedSettledUpgrades += 1;
  const finalTrustState = hasOutput ? 'verified' : 'valid_signature_only';
  const extraHeaders = { ...auth.responseHeaders };
  let counterAttestedReceipt = null;
  let counterAttestationSkippedReason = null;

  const alreadyCounterAttested = Boolean(
    parsed.receipt.payload.payment.settlement.checkedByVerifier ||
    parsed.receipt.payload.payment.settlement.checkedByPaxiom
  );

  // Strict counter-attestation guard (FERMI-PAX-01):
  // Only sign a portable verifier counter-attestation when `expectedPayTo` was explicitly pinned
  // and verified against the on-chain USDC Transfer recipient, and the input receipt was not already
  // counter-attested.
  const canCounterAttest = Boolean(
    paxiomKey &&
    normalizedExpectedPayTo &&
    onchain.recipientChecked &&
    !alreadyCounterAttested
  );

  if (canCounterAttest) {
    const orig = parsed.receipt.payload;
    const origSig = parsed.receipt.signature;
    const provenanceUri =
      `urn:paxiom:settlement-attestation:v0:${onchain.network}:${onchain.transactionHash}` +
      `?from=${onchain.matchedTransfer.from}` +
      `&to=${onchain.matchedTransfer.to}` +
      `&amountAtomic=${onchain.matchedTransfer.amountAtomic}` +
      `&origKeyId=${encodeURIComponent(origSig.keyId)}` +
      `&origPubKey=${encodeURIComponent(origSig.publicKey)}` +
      (orig.issuer && orig.issuer.uri ? `&origIssuerUri=${encodeURIComponent(orig.issuer.uri)}` : '');

    const issued = issueReceipt({
      privateKey: paxiomKey.privateKeyPem,
      issuer: {
        name: env.PAXIOM_ISSUER_NAME || 'Paxiom Receipt Verifier',
        uri: env.PAXIOM_ISSUER_URI || 'https://paxiom.org',
        keyId: paxiomKey.keyId,
        keysUri: 'https://api.paxiom.org/.well-known/x402-keys.json'
      },
      service: orig.service,
      request: orig.request,
      payment: {
        ...orig.payment,
        payTo: orig.payment.payTo || onchain.matchedTransfer.to,
        payer: orig.payment.payer || onchain.matchedTransfer.from,
        settlement: {
          status: 'verified_settled',
          transactionHash: onchain.transactionHash,
          checkedByVerifier: true,
          verifier: env.PAXIOM_VERIFIER_URI || 'https://api.paxiom.org'
        }
      },
      outputHash: orig.delivery.outputHash,
      canonicalization: orig.delivery.canonicalization || 'jcs-sha256',
      mimeType: orig.delivery.mimeType,
      statusCode: orig.delivery.statusCode,
      evidence: [
        {
          type: 'attestation',
          status: 'verified',
          hash: baseResult.receiptHash,
          uri: provenanceUri
        }
      ]
    });
    counterAttestedReceipt = issued.receipt;
    extraHeaders['Payment-Receipt'] = issued.receiptHeader;
    extraHeaders['X-Paxiom-Receipt'] = issued.receiptHeader;
  } else if (paxiomKey && !normalizedExpectedPayTo) {
    counterAttestationSkippedReason = 'expectedPayTo_required_for_counter_attestation';
  }

  return send(res, 200, {
    valid: finalTrustState === 'verified',
    trustState: finalTrustState,
    checks: {
      ...baseResult.checks,
      settlement: 'verified_settled'
    },
    receiptHash: baseResult.receiptHash,
    onchainSettlement: onchain,
    ...(counterAttestedReceipt ? { counterAttestedReceipt } : {}),
    ...(counterAttestationSkippedReason ? { counterAttestationSkippedReason } : {}),
    summary: finalTrustState === 'verified'
      ? `Receipt and on-chain USDC settlement (${onchain.transactionHash} on ${onchain.network}) verified.`
      : `Signature and on-chain USDC settlement (${onchain.transactionHash}) verified; supply output to verify outputHash binding.`
  }, extraHeaders);
}

const ALLOWED_PREFLIGHT_METHODS = new Set(['POST', 'GET', 'HEAD']);
const DEC_UINT_STRING_RE = /^[0-9]+$/;

async function handleX402Preflight(req, res, { env, fetchImpl, lookupImpl, stats, checkRateLimit }) {
  const liveEnabled = isFlagEnabled(env.LIVE_VERIFY_ENABLED) || isFlagEnabled(env.X402_ENABLED);
  if (!liveEnabled) {
    return send(res, 503, errBody(
      'preflight_disabled',
      'Live x402 preflight scanning is not enabled on this instance.'
    ));
  }

  const hasPaymentOrAuthHeader = Boolean(
    req.headers && (
      req.headers['payment-signature'] ||
      req.headers['x-payment'] ||
      req.headers['x-api-key'] ||
      req.headers.authorization
    )
  );

  if (req.method === 'GET') {
    if (!hasPaymentOrAuthHeader && isFlagEnabled(env.X402_ENABLED) && env.X402_PAY_TO) {
      const auth = await authorizeMonetizedRequest(req, { env, fetchImpl, route: 'preflight' });
      if (stats && auth.status === 402) stats.x402Preflight.unpaid402Quotes += 1;
      return send(res, auth.status, auth.body, auth.headers);
    }
    return send(res, 405, errBody('method_not_allowed', 'Send a JSON POST request with { url, method?, maxBudgetAtomic?, expectedNetwork? } to /v1/x402/preflight.'), { allow: 'POST, OPTIONS' });
  }

  // Enforce per-IP burst rate limit on unmetered public endpoints
  if (!isFlagEnabled(env.X402_ENABLED) && !checkApiKey(req, env).authorized && checkRateLimit) {
    const ip = resolveClientIp(req, env);
    const limit = parseRateLimit(env.RATE_LIMIT_PREFLIGHT_PER_MIN, 30);
    const rl = checkRateLimit(`preflight:${ip}`, limit);
    if (!rl.allowed) {
      if (stats) stats.x402Preflight.rateLimited += 1;
      return send(res, 429, errBody(
        'rate_limit_exceeded',
        `Rate limit exceeded (${rl.limit} requests/min per IP on public reference preflight scanner). Retry after ${rl.retryAfterSeconds}s.`
      ), {
        'Retry-After': String(rl.retryAfterSeconds),
        'X-RateLimit-Limit': String(rl.limit),
        'X-RateLimit-Remaining': '0'
      });
    }
  }

  let rawBodyText = '';
  try {
    rawBodyText = await readBody(req);
  } catch (err) {
    if (err.code === 'body_too_large') {
      return send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`), { connection: 'close' });
    }
    return send(res, 400, errBody('read_error', 'Failed to read request body'));
  }

  let parsed;
  try {
    parsed = JSON.parse(rawBodyText || '{}');
  } catch {
    return send(res, 400, errBody('invalid_json', 'Request body is not valid JSON'));
  }

  if ((!parsed || typeof parsed !== 'object' || !parsed.url) &&
      !hasPaymentOrAuthHeader &&
      isFlagEnabled(env.X402_ENABLED) &&
      env.X402_PAY_TO) {
    const auth = await authorizeMonetizedRequest(req, { env, fetchImpl, route: 'preflight' });
    if (stats && auth.status === 402) stats.x402Preflight.unpaid402Quotes += 1;
    return send(res, auth.status, auth.body, auth.headers);
  }

  if (!parsed || typeof parsed !== 'object' || typeof parsed.url !== 'string' || !parsed.url.trim()) {
    return send(res, 400, errBody('missing_target_url', 'Request must be a JSON object with a non-empty https:// "url" field.'));
  }

  const probeMethod = parsed.method !== undefined ? String(parsed.method).toUpperCase() : 'POST';
  if (!ALLOWED_PREFLIGHT_METHODS.has(probeMethod)) {
    return send(res, 400, errBody('invalid_probe_method', 'Field "method" must be one of POST, GET, or HEAD.'));
  }

  let maxBudgetAtomic = null;
  if (parsed.maxBudgetAtomic !== undefined && parsed.maxBudgetAtomic !== null && parsed.maxBudgetAtomic !== '') {
    const budgetStr = String(parsed.maxBudgetAtomic);
    if (!DEC_UINT_STRING_RE.test(budgetStr)) {
      return send(res, 400, errBody('invalid_max_budget', 'Field "maxBudgetAtomic" must be a base-10 non-negative integer string.'));
    }
    maxBudgetAtomic = budgetStr;
  }

  let expectedNetwork = null;
  if (parsed.expectedNetwork !== undefined && parsed.expectedNetwork !== null && parsed.expectedNetwork !== '') {
    const netStr = String(parsed.expectedNetwork);
    if (!getSupportedNetworkConfig(netStr)) {
      return send(res, 400, errBody('unsupported_expected_network', 'Field "expectedNetwork" must be base, eip155:8453, base-sepolia, or eip155:84532.'));
    }
    expectedNetwork = netStr;
  }

  // Pure offline lexical & IP-literal SSRF validation (zero DNS / facilitator I/O)
  const lexicalTarget = validateTargetUrlLexical(parsed.url);
  if (!lexicalTarget.ok) {
    if (stats) stats.x402Preflight.ssrfOrLexicalBlocked += 1;
    return send(res, 400, errBody(lexicalTarget.code, lexicalTarget.message));
  }

  // Phase 1 gate (`FERMI-PAX-R2-01` & `FERMI-PAX-R2-03`):
  // Block cross-origin browser unmetered probes (or verify opt-in gate) BEFORE live `dns.lookup`.
  let verifiedAuth;
  try {
    verifiedAuth = await verifyMonetizedRequest(req, { env, fetchImpl, route: 'preflight' });
  } catch {
    return send(res, 502, errBody('payment_gate_error', 'Failed to contact x402 payment facilitator.'));
  }
  if (!verifiedAuth.verified) {
    if (stats && verifiedAuth.status === 402) stats.x402Preflight.unpaid402Quotes += 1;
    return send(res, verifiedAuth.status, verifiedAuth.body, verifiedAuth.headers);
  }

  // Deterministic SSRF & DNS public-IP validation BEFORE any outbound probe or settlement
  const targetValidation = await validatePublicHttpsTarget(
    parsed.url,
    lookupImpl ? { lookupImpl } : {}
  );
  if (!targetValidation.ok) {
    if (stats) stats.x402Preflight.ssrfOrLexicalBlocked += 1;
    return send(res, 400, errBody(targetValidation.code, targetValidation.message));
  }

  let auth;
  try {
    auth = await settleMonetizedRequest(verifiedAuth, { fetchImpl });
  } catch {
    return send(res, 502, errBody('payment_gate_error', 'Failed to contact x402 payment facilitator.'));
  }
  if (!auth.authorized) {
    if (stats && auth.status === 402) stats.x402Preflight.unpaid402Quotes += 1;
    return send(res, auth.status, auth.body, auth.headers);
  }
  if (stats) {
    if (auth.mode === 'x402') stats.x402Preflight.paidX402Settled += 1;
    else if (auth.mode === 'api_key') stats.x402Preflight.paidApiKeyServed += 1;
    else stats.x402Preflight.freePublicServed += 1;
  }

  const probeFetchImpl = fetchImpl === globalThis.fetch ? null : fetchImpl;
  const report = await runX402Preflight(targetValidation, {
    method: probeMethod,
    maxBudgetAtomic,
    expectedNetwork
  }, { fetchImpl: probeFetchImpl });

  if (stats) {
    if (report.verdict === 'proceed') stats.x402Preflight.verdictProceed += 1;
    else if (report.verdict === 'caution') stats.x402Preflight.verdictCaution += 1;
    else if (report.verdict === 'block') stats.x402Preflight.verdictBlock += 1;
  }
  const extraHeaders = { ...auth.responseHeaders };
  const paxiomKey = getConfiguredPaxiomKey(env);
  if (paxiomKey) {
    const resourceUrl = env.X402_PREFLIGHT_RESOURCE_URL || 'https://api.paxiom.org/v1/x402/preflight';
    const priceAtomic = String(env.X402_PREFLIGHT_PRICE_ATOMIC || '10000');
    const rawTx = auth.mode === 'x402' && auth.settlement && typeof auth.settlement.transaction === 'string'
      ? auth.settlement.transaction.toLowerCase()
      : null;
    const validTx = rawTx && /^0x[0-9a-f]{64}$/.test(rawTx) ? rawTx : null;
    const isX402Paid = auth.mode === 'x402';

    const issued = issueReceipt({
      privateKey: paxiomKey.privateKeyPem,
      issuer: {
        name: env.PAXIOM_ISSUER_NAME || 'Paxiom Receipt Verifier',
        uri: env.PAXIOM_ISSUER_URI || 'https://paxiom.org',
        keyId: paxiomKey.keyId,
        keysUri: 'https://api.paxiom.org/.well-known/x402-keys.json'
      },
      service: {
        name: 'Paxiom x402 Seller Preflight',
        resource: resourceUrl,
        method: 'POST'
      },
      request: {
        method: 'POST',
        resource: resourceUrl,
        body: rawBodyText
      },
      payment: {
        scheme: isX402Paid ? 'x402' : 'public-reference',
        network: env.X402_NETWORK || 'eip155:8453',
        asset: 'USDC',
        amountAtomic: isX402Paid ? priceAtomic : '0',
        amountDisplay: isX402Paid ? (Number(priceAtomic) / 1e6).toString() : '0',
        paymentRequirements: auth.paymentRequirements,
        paymentPayload: auth.paymentPayload,
        settlement: {
          status: validTx ? 'claimed_not_checked' : 'not_required',
          transactionHash: validTx,
          checkedByVerifier: false
        }
      },
      output: report,
      statusCode: 200
    });
    extraHeaders['Payment-Receipt'] = issued.receiptHeader;
    extraHeaders['X-Paxiom-Receipt'] = issued.receiptHeader;
    if (!extraHeaders['Access-Control-Expose-Headers']) {
      extraHeaders['Access-Control-Expose-Headers'] = 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, Payment-Receipt, X-Paxiom-Receipt';
    }
  }

  return send(res, 200, report, extraHeaders);
}

export function createHandler({ env: rawEnv = process.env, fetchImpl = globalThis.fetch, lookupImpl } = {}) {
  const env = resolveRuntimeEnv(rawEnv);
  const stats = createFunnelStats();
  const checkRateLimit = createBoundedRateLimiter({
    windowMs: Math.max(1000, Number(env.RATE_LIMIT_WINDOW_MS) || 60_000)
  });
  const onMcpEvent = (ev) => {
    if (!ev) return;
    if (ev.kind === 'get_metadata') stats.discovery.mcpGetReads += 1;
    else if (ev.kind === 'jsonrpc') stats.discovery.mcpJsonRpcCalls += 1;
    else if (ev.kind === 'tool') {
      if (ev.tool === 'verify_receipt') stats.discovery.mcpToolCalls.verify_receipt += 1;
      else if (ev.tool === 'explain_receipt') stats.discovery.mcpToolCalls.explain_receipt += 1;
      else if (ev.tool === 'get_x402_verifier_info') stats.discovery.mcpToolCalls.get_x402_verifier_info += 1;
    }
  };

  return async function handleRequest(req, res) {
    const { method } = req;
    const path = (req.url || '').split('?')[0];

    const isRead = method === 'GET' || method === 'HEAD';
    if (method === 'OPTIONS') {
      res.writeHead(204, CORS);
      return res.end();
    }
    if (isRead && path === '/') {
      if (method === 'GET') stats.discovery.rootIndexReads += 1;
      return send(res, 200, buildRootServiceIndex(env));
    }
    if (isRead && path === '/openapi.json') {
      if (method === 'GET') stats.discovery.openApiReads += 1;
      return send(res, 200, openApiSpec);
    }
    if (isRead && path === '/llms.txt') {
      if (method === 'GET') stats.discovery.llmsTxtReads += 1;
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'x-content-type-options': 'nosniff',
        ...CORS
      });
      return res.end(method === 'HEAD' ? undefined : llmsTxtContent);
    }
    if (isRead && path === '/.well-known/mcp.json') {
      if (method === 'GET') stats.discovery.mcpCardReads += 1;
      return send(res, 200, buildMcpServerCard(env));
    }
    if (isRead && path === '/stats') {
      return send(res, 200, snapshotFunnelStats(stats));
    }
    if (isRead && path === '/health') {
      return send(res, 200, { ok: true, service: 'paxiom-receipt-verifier', version: RUNTIME_VERSION, receiptVersion: RECEIPT_VERSION });
    }
    if (isRead && path === '/version') {
      return send(res, 200, buildVersionPayload(env));
    }
    if (isRead && path === '/v1/receipt/demo') {
      if (method === 'GET') stats.offlineVerify.demoReads += 1;
      return send(res, 200, {
        receiptVersion: RECEIPT_VERSION,
        output: demoOutput,
        receipt: demoReceipt,
        verify: { method: 'POST', path: '/v1/receipt/verify', body: { receipt: '<receipt>', output: '<output?>' } }
      });
    }
    if (isRead && path === '/.well-known/did.json') {
      if (method === 'GET') stats.discovery.didJsonReads += 1;
      const paxiomKey = getConfiguredPaxiomKey(env);
      const didHost = String(env.PAXIOM_DID_DOMAIN || 'api.paxiom.org').trim();
      const didId = `did:web:${didHost}`;
      const vmId = paxiomKey ? `${didId}#${paxiomKey.keyId}` : null;
      return send(res, 200, {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ],
        id: didId,
        verificationMethod: paxiomKey
          ? [{
              id: vmId,
              type: 'JsonWebKey2020',
              controller: didId,
              publicKeyJwk: {
                kty: 'OKP',
                crv: 'Ed25519',
                alg: 'EdDSA',
                use: 'sig',
                kid: paxiomKey.keyId,
                x: Buffer.from(paxiomKey.publicKey, 'base64').toString('base64url')
              }
            }]
          : [],
        assertionMethod: vmId ? [vmId] : [],
        authentication: vmId ? [vmId] : []
      });
    }
    if (isRead && (path === '/.well-known/x402-keys.json' || path === '/.well-known/paxiom-keys.json')) {
      if (method === 'GET') {
        if (path === '/.well-known/x402-keys.json') stats.discovery.x402KeysReads += 1;
        else stats.discovery.paxiomKeysReads += 1;
      }
      const paxiomKey = getConfiguredPaxiomKey(env);
      return send(res, 200, {
        version: 'x402-keys.v1',
        issuer: env.PAXIOM_ISSUER_NAME || 'Paxiom Receipt Verifier',
        keys: paxiomKey
          ? [{ keyId: paxiomKey.keyId, algorithm: 'ed25519', publicKey: paxiomKey.publicKey }]
          : []
      });
    }
    if (isRead && (path === '/.well-known/x402.json' || path === '/.well-known/x402')) {
      if (!isFlagEnabled(env.X402_ENABLED) || !env.X402_PAY_TO) {
        return send(res, 404, errBody('x402_disabled', 'x402 payment discovery is not enabled on this public reference instance; all routes are free.'));
      }
      if (method === 'GET') stats.discovery.x402ManifestReads += 1;
      return send(res, 200, buildX402PaymentRequirements(env, { route: 'discovery' }));
    }
    if (method === 'POST' && path === '/v1/receipt/verify') {
      return handleOfflineVerify(req, res, env, stats);
    }
    if ((method === 'POST' || method === 'GET') && path === '/v1/receipt/verify-live') {
      return handleLiveVerify(req, res, { env, fetchImpl, stats, checkRateLimit });
    }
    if ((method === 'POST' || method === 'GET') && path === '/v1/x402/preflight') {
      return handleX402Preflight(req, res, { env, fetchImpl, lookupImpl, stats, checkRateLimit });
    }
    if (path === '/mcp') {
      return handleMcpHttpRequest(req, res, { env, readBody, corsHeaders: CORS, onMcpEvent });
    }
    return send(res, 404, errBody('not_found', `No route for ${method} ${path}`));
  };
}

export const handle = createHandler();

export function createServer(options = {}) {
  const srv = http.createServer(createHandler(options));
  srv.requestTimeout = 20000;
  srv.headersTimeout = 10000;
  srv.keepAliveTimeout = 5000;
  return srv;
}

export default handle;

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const port = Number(process.env.PORT) || 8787;
  createServer().listen(port, () => {
    process.stdout.write(`paxiom-receipt-verifier (${RUNTIME_VERSION}) on http://localhost:${port}\n`);
    process.stdout.write(`  GET  /health\n  GET  /version\n  GET  /.well-known/x402-keys.json\n  GET  /v1/receipt/demo\n  POST /v1/receipt/verify\n  POST /v1/receipt/verify-live\n  POST /v1/x402/preflight\n  POST /mcp\n`);
  });
}
