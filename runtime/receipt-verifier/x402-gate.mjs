// Dual-rail monetization gate for Paxiom Receipt Verifier:
//   1. B2B SaaS API Keys (`Authorization: Bearer <key>` or `X-API-Key: <key>`)
//   2. Coinbase / x402 per-request stablecoin micro-payments (`verify -> settle -> serve`)
//
// Zero external dependencies. Disabled by default (`X402_ENABLED=false` and empty
// `PAXIOM_API_KEYS`) so Phase 5D free preview deployments require zero secrets.
import crypto from 'node:crypto';
import { NETWORK_CONFIGS, getSupportedNetworkConfig } from './onchain-settlement.mjs';

const DEFAULT_FACILITATOR_URL = 'https://facilitator.payai.network';
const DEFAULT_FACILITATOR_VERIFY_TIMEOUT_MS = 10000;
const DEFAULT_FACILITATOR_SETTLE_TIMEOUT_MS = 15000;

async function fetchWithTimeout(fetchImpl, url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function sha256Buf(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest();
}

export function checkApiKey(req, env = process.env) {
  const configured = String(env.PAXIOM_API_KEYS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (configured.length === 0) return { configured: false, authorized: false };

  const authHeader = String((req.headers && req.headers.authorization) || '');
  const bearer = authHeader.toLowerCase().startsWith('bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const apiKeyHeader = String((req.headers && req.headers['x-api-key']) || '').trim();
  const candidate = apiKeyHeader || bearer;
  if (!candidate) return { configured: true, authorized: false };

  const candDigest = sha256Buf(candidate);
  for (const validKey of configured) {
    if (crypto.timingSafeEqual(candDigest, sha256Buf(validKey))) {
      return { configured: true, authorized: true };
    }
  }
  return { configured: true, authorized: false };
}

function buildVerifyLiveAccept(env = process.env) {
  const network = env.X402_NETWORK || 'base';
  const netCfg = getSupportedNetworkConfig(String(network)) || NETWORK_CONFIGS.base;
  const priceAtomic = String(env.X402_PRICE_ATOMIC || '2000'); // default $0.002 USDC (6 decimals)
  const payTo = env.X402_PAY_TO || '';
  const resource = env.X402_RESOURCE_URL || 'https://api.paxiom.org/v1/receipt/verify-live';

  return {
    scheme: 'exact',
    network,
    maxAmountRequired: priceAtomic,
    resource,
    description: 'Live on-chain USDC settlement verification + Paxiom Ed25519 counter-attestation for paxiom.receipt.v0',
    mimeType: 'application/json',
    payTo,
    maxTimeoutSeconds: 60,
    asset: netCfg.usdcAddress,
    outputSchema: {
      input: {
        discoverable: true,
        type: 'http',
        method: 'POST',
        bodyType: 'json',
        bodyFields: {
          receipt: { type: 'object', required: true, description: 'paxiom.receipt.v0 JSON object' },
          output: { type: 'object', required: false, description: 'Delivered API response JSON' },
          expectedPayTo: { type: 'string', required: false, description: 'Optional expected USDC recipient address' }
        }
      },
      output: {
        valid: { type: 'boolean' },
        trustState: { type: 'string' },
        checks: { type: 'object' },
        onchainSettlement: { type: 'object' },
        counterAttestedReceipt: { type: 'object' }
      }
    },
    extra: { name: netCfg.eip712Name || 'USD Coin', version: '2' }
  };
}

function buildPreflightAccept(env = process.env) {
  const network = env.X402_NETWORK || 'base';
  const netCfg = getSupportedNetworkConfig(String(network)) || NETWORK_CONFIGS.base;
  const priceAtomic = String(env.X402_PREFLIGHT_PRICE_ATOMIC || '10000'); // default $0.01 USDC (6 decimals)
  const payTo = env.X402_PAY_TO || '';
  const resource = env.X402_PREFLIGHT_RESOURCE_URL || 'https://api.paxiom.org/v1/x402/preflight';

  return {
    scheme: 'exact',
    network,
    maxAmountRequired: priceAtomic,
    resource,
    description: 'SSRF-hardened pre-payment x402 seller readiness, canonical Base USDC asset check, and Paxiom receipt capability scan',
    mimeType: 'application/json',
    payTo,
    maxTimeoutSeconds: 60,
    asset: netCfg.usdcAddress,
    outputSchema: {
      input: {
        discoverable: true,
        type: 'http',
        method: 'POST',
        bodyType: 'json',
        bodyFields: {
          url: { type: 'string', required: true, description: 'Target https:// x402 endpoint URL to inspect before paying' },
          method: { type: 'string', required: false, description: 'HTTP method to probe (POST, GET, or HEAD; default POST)' },
          maxBudgetAtomic: { type: 'string', required: false, description: 'Optional caller budget cap in USDC atomic units' },
          expectedNetwork: { type: 'string', required: false, description: 'Optional expected network (base or base-sepolia)' }
        }
      },
      output: {
        ok: { type: 'boolean' },
        verdict: { type: 'string' },
        riskLevel: { type: 'string' },
        selectedQuote: { type: 'object' },
        checks: { type: 'object' },
        receiptSupport: { type: 'object' },
        findings: { type: 'array' }
      }
    },
    extra: { name: netCfg.eip712Name || 'USD Coin', version: '2' }
  };
}

export function buildX402PaymentRequirements(env = process.env, { route = 'verify-live' } = {}) {
  const accepts = route === 'discovery'
    ? [buildVerifyLiveAccept(env), buildPreflightAccept(env)]
    : route === 'preflight'
      ? [buildPreflightAccept(env)]
      : [buildVerifyLiveAccept(env)];

  if (route === 'discovery') {
    let baseUrl = 'https://api.paxiom.org';
    try {
      baseUrl = new URL(accepts[0].resource).origin;
    } catch {
      // keep default origin
    }
    return {
      x402Version: 1,
      service: 'Paxiom Receipt Verifier',
      baseUrl,
      resources: accepts.map((a) => ({
        url: a.resource,
        resource: a.resource,
        method: 'POST',
        description: a.description,
        network: a.network,
        asset: a.asset,
        payTo: a.payTo,
        maxAmountRequired: a.maxAmountRequired
      })),
      accepts
    };
  }

  return {
    x402Version: 1,
    error: 'Payment Required: supply an x402 payment header (PAYMENT-SIGNATURE or X-PAYMENT) or a valid Paxiom API key (X-API-Key).',
    accepts
  };
}

/**
 * Phase 1 of the monetized gate (`FERMI-PAX-R2-01` & `FERMI-PAX-R2-03`):
 * Verify SaaS API key OR x402 payment header (`POST /verify` only — no on-chain debit yet)
 * BEFORE running any outbound DNS lookup or precheck that could act as an unauthenticated oracle.
 */
export async function verifyMonetizedRequest(req, {
  env = process.env,
  fetchImpl = globalThis.fetch,
  route = 'verify-live'
} = {}) {
  // 1. Check B2B SaaS API key first (zero per-call settlement latency)
  const apiKeyCheck = checkApiKey(req, env);
  if (apiKeyCheck.authorized) {
    return { verified: true, authorized: true, mode: 'api_key', responseHeaders: {} };
  }

  const x402Enabled = env.X402_ENABLED === 'true' || env.X402_ENABLED === '1';
  if (!x402Enabled) {
    if (apiKeyCheck.configured) {
      return {
        verified: false,
        authorized: false,
        status: 401,
        headers: {},
        body: {
          valid: false,
          trustState: 'error',
          error: { code: 'unauthorized', message: 'Valid X-API-Key or Authorization: Bearer token required.' }
        }
      };
    }
    const allowBrowserFreeLive = env.ALLOW_BROWSER_FREE_LIVE === 'true' || env.ALLOW_BROWSER_FREE_LIVE === '1';
    const rawOrigin = String((req && req.headers && req.headers.origin) || '').trim().toLowerCase();
    const secFetchSite = String((req && req.headers && req.headers['sec-fetch-site']) || '').trim().toLowerCase();
    const isTrustedFirstPartyOrigin = rawOrigin === 'https://paxiom.org' || rawOrigin === 'https://www.paxiom.org';
    const isUntrustedBrowserCrossSite = (Boolean(rawOrigin) && !isTrustedFirstPartyOrigin) ||
      (secFetchSite === 'cross-site' && !isTrustedFirstPartyOrigin);
    if (isUntrustedBrowserCrossSite && !allowBrowserFreeLive) {
      return {
        verified: false,
        authorized: false,
        status: 403,
        headers: {},
        body: {
          valid: false,
          trustState: 'error',
          error: {
            code: 'cross_origin_unmetered_blocked',
            message: 'Cross-origin browser requests to unmetered live endpoints are blocked; call from your backend/agent or set ALLOW_BROWSER_FREE_LIVE=true on self-hosted instances.'
          }
        }
      };
    }
    return { verified: true, authorized: true, mode: 'free_unmetered', responseHeaders: {} };
  }

  if (!env.X402_PAY_TO) {
    return {
      verified: false,
      authorized: false,
      status: 503,
      headers: {},
      body: {
        valid: false,
        trustState: 'error',
        error: { code: 'x402_misconfigured', message: 'X402_ENABLED is true, but X402_PAY_TO is not configured.' }
      }
    };
  }

  const requirementsPayload = buildX402PaymentRequirements(env, { route });
  const paymentRequirements = requirementsPayload.accepts[0];
  const paymentHeader = String(
    (req.headers && (req.headers['payment-signature'] || req.headers['x-payment'])) || ''
  ).trim();

  if (!paymentHeader) {
    const encodedReq = Buffer.from(JSON.stringify(requirementsPayload), 'utf8').toString('base64');
    return {
      verified: false,
      authorized: false,
      status: 402,
      headers: {
        'PAYMENT-REQUIRED': encodedReq,
        'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Paxiom-Receipt'
      },
      body: requirementsPayload
    };
  }

  let decodedPaymentPayload;
  try {
    decodedPaymentPayload = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8'));
  } catch {
    decodedPaymentPayload = null;
  }
  if (!decodedPaymentPayload || typeof decodedPaymentPayload !== 'object' || Array.isArray(decodedPaymentPayload)) {
    return {
      verified: false,
      authorized: false,
      status: 400,
      headers: {},
      body: {
        valid: false,
        trustState: 'error',
        error: { code: 'invalid_payment_header', message: 'Payment header is not a valid base64 JSON object.' }
      }
    };
  }

  const facilitatorUrl = String(env.X402_FACILITATOR_URL || env.CDP_FACILITATOR_URL || DEFAULT_FACILITATOR_URL).replace(/\/+$/, '');
  const facHeaders = { 'content-type': 'application/json' };
  if (env.FACILITATOR_BEARER_TOKEN) {
    facHeaders.authorization = `Bearer ${env.FACILITATOR_BEARER_TOKEN}`;
  }

  const verifyTimeoutMs = Number(env.FACILITATOR_VERIFY_TIMEOUT_MS) || DEFAULT_FACILITATOR_VERIFY_TIMEOUT_MS;
  const settleTimeoutMs = Number(env.FACILITATOR_SETTLE_TIMEOUT_MS) || DEFAULT_FACILITATOR_SETTLE_TIMEOUT_MS;

  // Step 1: Facilitator /verify (read-only signature & balance check)
  const verifyRes = await fetchWithTimeout(fetchImpl, `${facilitatorUrl}/verify`, {
    method: 'POST',
    headers: facHeaders,
    body: JSON.stringify({
      x402Version: 1,
      paymentPayload: decodedPaymentPayload,
      paymentRequirements
    })
  }, verifyTimeoutMs);
  if (!verifyRes.ok) {
    return {
      verified: false,
      authorized: false,
      status: 502,
      headers: {},
      body: {
        valid: false,
        trustState: 'error',
        error: { code: 'facilitator_verify_http_error', message: `Facilitator /verify returned HTTP ${verifyRes.status}` }
      }
    };
  }
  const verifyJson = await verifyRes.json();
  if (!verifyJson || !verifyJson.isValid) {
    const encodedReq = Buffer.from(JSON.stringify(requirementsPayload), 'utf8').toString('base64');
    return {
      verified: false,
      authorized: false,
      status: 402,
      headers: { 'PAYMENT-REQUIRED': encodedReq },
      body: {
        ...requirementsPayload,
        error: `Payment verification failed: ${(verifyJson && verifyJson.invalidReason) || 'invalid payment'}`
      }
    };
  }

  return {
    verified: true,
    authorized: false,
    mode: 'x402',
    facilitatorUrl,
    facHeaders,
    settleTimeoutMs,
    paymentRequirements,
    paymentPayload: decodedPaymentPayload
  };
}

/**
 * Phase 2 of the monetized gate (`FERMI-PAX-R2-01`):
 * Settle an already-verified x402 payment (`POST /settle`) ONLY after target/input validation passes.
 */
export async function settleMonetizedRequest(verifiedCtx, {
  fetchImpl = globalThis.fetch
} = {}) {
  if (!verifiedCtx || !verifiedCtx.verified) {
    return verifiedCtx;
  }
  if (verifiedCtx.mode !== 'x402') {
    return {
      authorized: true,
      mode: verifiedCtx.mode,
      responseHeaders: verifiedCtx.responseHeaders || {}
    };
  }

  const {
    facilitatorUrl,
    facHeaders,
    settleTimeoutMs,
    paymentRequirements,
    paymentPayload: decodedPaymentPayload
  } = verifiedCtx;

  const settleRes = await fetchWithTimeout(fetchImpl, `${facilitatorUrl}/settle`, {
    method: 'POST',
    headers: facHeaders,
    body: JSON.stringify({
      x402Version: 1,
      paymentPayload: decodedPaymentPayload,
      paymentRequirements
    })
  }, settleTimeoutMs);
  if (!settleRes.ok) {
    return {
      authorized: false,
      status: 502,
      headers: {},
      body: {
        valid: false,
        trustState: 'error',
        error: { code: 'facilitator_settle_http_error', message: `Facilitator /settle returned HTTP ${settleRes.status}` }
      }
    };
  }
  const settleJson = await settleRes.json();
  if (!settleJson || !settleJson.success) {
    return {
      authorized: false,
      status: 402,
      headers: {},
      body: {
        valid: false,
        trustState: 'error',
        error: {
          code: 'payment_settlement_failed',
          message: `Payment settlement failed: ${(settleJson && settleJson.errorReason) || 'settlement rejected'}`
        }
      }
    };
  }

  const encodedPaymentResponse = Buffer.from(JSON.stringify(settleJson), 'utf8').toString('base64');
  return {
    authorized: true,
    mode: 'x402',
    settlement: settleJson,
    paymentRequirements,
    paymentPayload: decodedPaymentPayload,
    responseHeaders: {
      'PAYMENT-RESPONSE': encodedPaymentResponse,
      'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Paxiom-Receipt'
    }
  };
}

/**
 * Authorize a paid route via SaaS API key OR x402 facilitator verify+settle.
 */
export async function authorizeMonetizedRequest(req, {
  env = process.env,
  fetchImpl = globalThis.fetch,
  route = 'verify-live'
} = {}) {
  const verified = await verifyMonetizedRequest(req, { env, fetchImpl, route });
  if (!verified.verified) return verified;
  return settleMonetizedRequest(verified, { fetchImpl });
}
