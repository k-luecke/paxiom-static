import { verifyReceipt } from './verify.mjs';
import { decodeReceiptHeader } from './issue.mjs';
import { RECEIPT_HEADER_NAME } from './middleware.mjs';

export const DEFAULT_PAXIOM_API_URL = 'https://api.paxiom.org';
export const PAXIOM_LIVE_VERIFIER_PUBLIC_KEY = 'hsRfDKd2AWxv0KwTs3gsDLMY7nPtVGky1Tc6NWgSxIY=';
export const PAXIOM_TRUSTED_PUBLIC_KEYS = Object.freeze([PAXIOM_LIVE_VERIFIER_PUBLIC_KEY]);

const DEFAULT_CLIENT_TIMEOUT_MS = 15000;
const MAX_CLIENT_RESPONSE_BYTES = 1024 * 1024; // 1 MiB safety cap
const ALLOWED_PREFLIGHT_METHODS = new Set(['POST', 'GET', 'HEAD']);
const DEC_UINT_RE = /^[0-9]+$/;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function isLoopbackHttpHost(hostname) {
  const bare = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  return bare === '127.0.0.1' || bare === 'localhost' || bare === '::1';
}

export function resolveSafeApiOrigin(rawBaseUrl = DEFAULT_PAXIOM_API_URL) {
  if (typeof rawBaseUrl !== 'string' || !rawBaseUrl.trim()) {
    throw new TypeError('baseUrl must be a non-empty URL string');
  }
  let parsed;
  try {
    parsed = new URL(rawBaseUrl.trim());
  } catch {
    throw new TypeError(`Invalid baseUrl: ${rawBaseUrl}`);
  }
  if (parsed.username || parsed.password) {
    throw new TypeError('baseUrl must not contain embedded credentials');
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackHttpHost(parsed.hostname))) {
    throw new TypeError('baseUrl must use https:// (plaintext http:// is permitted only on loopback for local tests)');
  }
  return parsed.origin;
}

function extractHeaderValue(responseOrHeaders, headerName) {
  if (!responseOrHeaders || typeof responseOrHeaders !== 'object') return undefined;
  const targetHeaders = (
    Object.hasOwn(responseOrHeaders, 'headers') ||
    typeof responseOrHeaders.headers === 'object'
  ) && responseOrHeaders.headers
    ? responseOrHeaders.headers
    : responseOrHeaders;

  if (typeof targetHeaders.get === 'function') {
    const val = targetHeaders.get(headerName);
    return val === null || val === undefined ? undefined : String(val);
  }
  const lower = headerName.toLowerCase();
  for (const [k, v] of Object.entries(targetHeaders)) {
    if (k.toLowerCase() === lower && v !== undefined && v !== null) {
      return Array.isArray(v) ? String(v[0]) : String(v);
    }
  }
  return undefined;
}

function decodeBase64JsonObject(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  for (const enc of ['base64', 'base64url']) {
    try {
      const parsed = JSON.parse(Buffer.from(trimmed, enc).toString('utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // try next encoding
    }
  }
  return null;
}

async function readBoundedFetchResponse(fetchImpl, url, init, {
  timeoutMs = DEFAULT_CLIENT_TIMEOUT_MS,
  maxBytes = MAX_CLIENT_RESPONSE_BYTES
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('No fetch implementation available; pass options.fetch or run on Node >= 18');
  }
  const effectiveTimeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_CLIENT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), effectiveTimeout);
  try {
    const res = await fetchImpl(url, {
      ...init,
      redirect: 'manual',
      signal: controller.signal
    });

    if (res.status >= 300 && res.status < 400) {
      throw new Error(`Refusing HTTP ${res.status} redirect from Paxiom verifier endpoint`);
    }

    let bodyBuf = Buffer.alloc(0);
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const buf = Buffer.from(value);
        total += buf.length;
        if (total > maxBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          throw new Error(`Verifier response exceeded ${maxBytes} bytes`);
        }
        chunks.push(buf);
      }
      bodyBuf = Buffer.concat(chunks);
    } else if (typeof res.text === 'function') {
      const txt = await res.text();
      bodyBuf = Buffer.from(txt, 'utf8');
      if (bodyBuf.length > maxBytes) {
        throw new Error(`Verifier response exceeded ${maxBytes} bytes`);
      }
    }

    return {
      response: res,
      status: Number(res.status) || 0,
      bodyText: bodyBuf.toString('utf8')
    };
  } finally {
    clearTimeout(timer);
  }
}

function buildAuthHeaders({ apiKey, paymentHeader }) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/json'
  };
  if (apiKey !== undefined && apiKey !== null && String(apiKey).trim() !== '') {
    headers['x-api-key'] = String(apiKey).trim();
  }
  if (paymentHeader !== undefined && paymentHeader !== null && String(paymentHeader).trim() !== '') {
    headers['payment-signature'] = String(paymentHeader).trim();
  }
  return headers;
}

/**
 * Inspect a Fetch `Response`, Node `IncomingMessage`, or headers object for an
 * `X-Paxiom-Receipt` header and verify it deterministically offline. Never throws.
 */
export function verifyResponseReceipt(responseOrHeaders, options = {}) {
  const rawHeader = extractHeaderValue(responseOrHeaders, RECEIPT_HEADER_NAME);
  if (!rawHeader || !rawHeader.trim()) {
    return {
      present: false,
      valid: false,
      trustState: null,
      receipt: null,
      verdict: null
    };
  }

  let receipt;
  try {
    receipt = decodeReceiptHeader(rawHeader);
  } catch (err) {
    return {
      present: true,
      valid: false,
      trustState: 'malformed_header',
      receipt: null,
      verdict: null,
      error: String((err && err.message) || err)
    };
  }

  const verifyOpts = {};
  if (options && typeof options === 'object') {
    if (Object.hasOwn(options, 'output') && options.output !== undefined) {
      verifyOpts.output = options.output;
    }
    verifyOpts.trustedPaxiomPublicKeys = Array.isArray(options.trustedPaxiomPublicKeys)
      ? options.trustedPaxiomPublicKeys
      : PAXIOM_TRUSTED_PUBLIC_KEYS;
  } else {
    verifyOpts.trustedPaxiomPublicKeys = PAXIOM_TRUSTED_PUBLIC_KEYS;
  }

  const verdict = verifyReceipt(receipt, verifyOpts);
  return {
    present: true,
    valid: verdict.valid,
    trustState: verdict.trustState,
    receipt,
    verdict
  };
}

/**
 * Run a pre-payment x402 seller readiness & USDC safety scan (`POST /v1/x402/preflight`)
 * before an agent wallet signs an EIP-3009 payment authorization.
 */
export async function preflightX402(targetUrl, options = {}) {
  if (typeof targetUrl !== 'string' || !targetUrl.trim()) {
    throw new TypeError('targetUrl must be a non-empty https:// URL string');
  }
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl.trim());
  } catch {
    throw new TypeError(`Invalid targetUrl: ${targetUrl}`);
  }
  if (parsedTarget.protocol !== 'https:') {
    throw new TypeError('targetUrl must use https://');
  }

  const opts = options && typeof options === 'object' ? options : {};
  const origin = resolveSafeApiOrigin(opts.baseUrl ?? DEFAULT_PAXIOM_API_URL);
  const method = opts.method !== undefined ? String(opts.method).toUpperCase() : 'POST';
  if (!ALLOWED_PREFLIGHT_METHODS.has(method)) {
    throw new TypeError('options.method must be POST, GET, or HEAD');
  }

  const reqBody = { url: parsedTarget.toString(), method };
  if (opts.maxBudgetAtomic !== undefined && opts.maxBudgetAtomic !== null && opts.maxBudgetAtomic !== '') {
    const budgetStr = String(opts.maxBudgetAtomic);
    if (!DEC_UINT_RE.test(budgetStr)) {
      throw new TypeError('options.maxBudgetAtomic must be a non-negative base-10 integer string');
    }
    reqBody.maxBudgetAtomic = budgetStr;
  }
  if (opts.expectedNetwork !== undefined && opts.expectedNetwork !== null && opts.expectedNetwork !== '') {
    reqBody.expectedNetwork = String(opts.expectedNetwork);
  }

  const fetchImpl = opts.fetch || opts.fetchImpl || globalThis.fetch;
  const { response, status, bodyText } = await readBoundedFetchResponse(
    fetchImpl,
    `${origin}/v1/x402/preflight`,
    {
      method: 'POST',
      headers: buildAuthHeaders({ apiKey: opts.apiKey, paymentHeader: opts.paymentHeader }),
      body: JSON.stringify(reqBody)
    },
    { timeoutMs: opts.timeoutMs }
  );

  let bodyJson = null;
  try {
    bodyJson = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    bodyJson = null;
  }

  if (status === 402) {
    const headerChallenge = decodeBase64JsonObject(extractHeaderValue(response, 'payment-required'));
    return {
      ok: false,
      status: 402,
      paymentRequired: true,
      challenge: headerChallenge || bodyJson,
      report: null,
      receiptVerification: null,
      paymentResponse: null
    };
  }

  if (status < 200 || status >= 300 || !bodyJson || typeof bodyJson !== 'object') {
    return {
      ok: false,
      status,
      paymentRequired: false,
      error: (bodyJson && bodyJson.error) || { code: 'preflight_http_error', message: `HTTP ${status}` },
      report: null,
      receiptVerification: null,
      paymentResponse: null
    };
  }

  const trustedKeys = Array.isArray(opts.trustedPaxiomPublicKeys)
    ? opts.trustedPaxiomPublicKeys
    : PAXIOM_TRUSTED_PUBLIC_KEYS;
  const receiptVerification = verifyResponseReceipt(response, {
    output: bodyJson,
    trustedPaxiomPublicKeys: trustedKeys
  });
  const paymentResponse = decodeBase64JsonObject(
    extractHeaderValue(response, 'payment-response') || extractHeaderValue(response, 'x-payment-response')
  );

  return {
    ok: true,
    status,
    paymentRequired: false,
    verdict: bodyJson.verdict ?? null,
    riskLevel: bodyJson.riskLevel ?? null,
    report: bodyJson,
    receiptVerification,
    paymentResponse
  };
}

/**
 * Verify a `paxiom.receipt.v0` receipt's claimed Base / Base Sepolia USDC settlement
 * live on-chain (`POST /v1/receipt/verify-live`) and optionally obtain a portable
 * Paxiom Ed25519 counter-attested receipt (`expectedPayTo` required for counter-attestation).
 */
export async function verifyReceiptLive(receipt, options = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new TypeError('receipt must be a parsed paxiom.receipt.v0 JSON object');
  }

  const opts = options && typeof options === 'object' ? options : {};
  const origin = resolveSafeApiOrigin(opts.baseUrl ?? DEFAULT_PAXIOM_API_URL);

  const reqBody = { receipt };
  const hasOutput = Object.hasOwn(opts, 'output') && opts.output !== undefined;
  if (hasOutput) {
    reqBody.output = opts.output;
  }
  if (opts.expectedPayTo !== undefined && opts.expectedPayTo !== null && opts.expectedPayTo !== '') {
    const payToStr = String(opts.expectedPayTo);
    if (!EVM_ADDRESS_RE.test(payToStr)) {
      throw new TypeError('options.expectedPayTo must be a 0x-prefixed 20-byte EVM hex address');
    }
    reqBody.expectedPayTo = payToStr;
  }

  const fetchImpl = opts.fetch || opts.fetchImpl || globalThis.fetch;
  const { response, status, bodyText } = await readBoundedFetchResponse(
    fetchImpl,
    `${origin}/v1/receipt/verify-live`,
    {
      method: 'POST',
      headers: buildAuthHeaders({ apiKey: opts.apiKey, paymentHeader: opts.paymentHeader }),
      body: JSON.stringify(reqBody)
    },
    { timeoutMs: opts.timeoutMs }
  );

  let bodyJson = null;
  try {
    bodyJson = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    bodyJson = null;
  }

  if (status === 402) {
    const headerChallenge = decodeBase64JsonObject(extractHeaderValue(response, 'payment-required'));
    return {
      ok: false,
      status: 402,
      paymentRequired: true,
      challenge: headerChallenge || bodyJson,
      result: null,
      counterAttestedReceipt: null,
      counterAttestedVerification: null,
      paymentResponse: null
    };
  }

  if (status < 200 || status >= 300 || !bodyJson || typeof bodyJson !== 'object') {
    return {
      ok: false,
      status,
      paymentRequired: false,
      error: (bodyJson && bodyJson.error) || { code: 'verify_live_http_error', message: `HTTP ${status}` },
      result: null,
      counterAttestedReceipt: null,
      counterAttestedVerification: null,
      paymentResponse: null
    };
  }

  const trustedKeys = Array.isArray(opts.trustedPaxiomPublicKeys)
    ? opts.trustedPaxiomPublicKeys
    : PAXIOM_TRUSTED_PUBLIC_KEYS;
  const counterAttestedReceipt = bodyJson.counterAttestedReceipt || null;
  const counterAttestedVerification = counterAttestedReceipt
    ? verifyReceipt(counterAttestedReceipt, {
        ...(hasOutput ? { output: opts.output } : {}),
        trustedPaxiomPublicKeys: trustedKeys
      })
    : null;
  const paymentResponse = decodeBase64JsonObject(
    extractHeaderValue(response, 'payment-response') || extractHeaderValue(response, 'x-payment-response')
  );

  return {
    ok: true,
    status,
    paymentRequired: false,
    valid: Boolean(bodyJson.valid),
    trustState: bodyJson.trustState ?? null,
    result: bodyJson,
    counterAttestedReceipt,
    counterAttestedVerification,
    paymentResponse
  };
}
