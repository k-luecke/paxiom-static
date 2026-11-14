// Public runtime for the Paxiom Receipt Verifier:
//   - Free offline routes (`/health`, `/version`, `/v1/receipt/demo`, `POST /v1/receipt/verify`)
//     are always active with zero env vars and zero external calls.
//   - Live settlement + dual-monetization route (`POST /v1/receipt/verify-live`,
//     `GET /.well-known/paxiom-keys.json`, `GET /.well-known/x402.json`) activates
//     only when `LIVE_VERIFY_ENABLED=true` or `X402_ENABLED=true`.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyReceipt, RECEIPT_VERSION } from '../../standards/receipts/v0/src/verify.mjs';
import { issueReceipt, publicKeyFromPrivateKey } from '../../standards/receipts/v0/src/issue.mjs';
import { verifyOnchainUsdcSettlement } from './onchain-settlement.mjs';
import { authorizeMonetizedRequest, buildX402PaymentRequirements } from './x402-gate.mjs';

const MAX_BODY_BYTES = 256 * 1024; // 256 KiB
const EX = new URL('../../standards/receipts/v0/examples/', import.meta.url);
const demoReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const demoOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

const RENDER_PRODUCTION_DEFAULTS = Object.freeze({
  LIVE_VERIFY_ENABLED: 'true',
  BASE_RPC_URL: 'https://base-rpc.publicnode.com,https://mainnet.base.org,https://1rpc.io/base',
  BASE_SEPOLIA_RPC_URL: 'https://base-sepolia-rpc.publicnode.com,https://sepolia.base.org',
  X402_ENABLED: 'true',
  X402_NETWORK: 'base',
  X402_PRICE_ATOMIC: '2000',
  X402_PAY_TO: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
  X402_FACILITATOR_URL: 'https://facilitator.payai.network',
  X402_RESOURCE_URL: 'https://api.paxiom.org/v1/receipt/verify-live'
});

export function resolveRuntimeEnv(rawEnv = process.env) {
  if (rawEnv && (rawEnv.RENDER === 'true' || rawEnv.PAXIOM_PRODUCTION_DEFAULTS === 'true')) {
    const merged = { ...RENDER_PRODUCTION_DEFAULTS };
    for (const [k, v] of Object.entries(rawEnv)) {
      if (v !== undefined && v !== '') merged[k] = v;
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
    receiptVersion: RECEIPT_VERSION,
    runtime: liveEnabled ? 'live-settlement-enabled' : 'developer-preview',
    checks: [
      'schema',
      'signature',
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
      liveSettlementVerification: liveEnabled,
      x402PaymentGating: x402Enabled,
      counterAttestation: Boolean(getConfiguredPaxiomKey(env))
    },
    endpoints: {
      freeOfflineVerify: 'POST /v1/receipt/verify',
      ...(liveEnabled ? { liveOnchainVerify: 'POST /v1/receipt/verify-live' } : {})
    },
    x402Enabled,
    note: liveEnabled
      ? 'POST /v1/receipt/verify remains free and offline. POST /v1/receipt/verify-live verifies claimed Base/Base-Sepolia USDC settlements via JSON-RPC.'
      : 'Developer-preview reference verifier for paxiom.receipt.v0. Verifies receipt schema, Ed25519 signature, and output binding. Reports settlement and proof-evidence states but does NOT independently verify onchain settlement, facilitator records, or proof-source evidence in v0. Free — no x402 gating.'
  };
}

function isFlagEnabled(val) {
  return val === 'true' || val === '1';
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type, authorization, x-api-key, payment-signature, x-payment'
};

function send(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...CORS, ...extraHeaders });
  res.end(JSON.stringify(body));
}

const errBody = (code, message) => ({ valid: false, trustState: 'error', error: { code, message } });

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', (c) => {
      if (tooLarge) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
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
      send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`));
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

async function handleOfflineVerify(req, res, env) {
  const parsed = await parseVerifyPayload(req, res);
  if (!parsed) return;
  try {
    const opts = Object.prototype.hasOwnProperty.call(parsed, 'output') ? { output: parsed.output } : {};
    const paxiomKey = getConfiguredPaxiomKey(env);
    if (paxiomKey) {
      opts.trustedPaxiomPublicKeys = [paxiomKey.publicKey];
    }
    return send(res, 200, verifyReceipt(parsed.receipt, opts));
  } catch (err) {
    return send(res, 500, errBody('verifier_error', String((err && err.message) || err)));
  }
}

async function handleLiveVerify(req, res, { env, fetchImpl }) {
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

  // If x402 gating is enabled and caller sent an unpaid discovery probe (GET or empty/{} POST),
  // return the 402 PaymentRequirements challenge immediately for x402 clients & Bazaar indexers.
  let rawBodyText = '';
  if (req.method === 'GET' && !hasPaymentOrAuthHeader && isFlagEnabled(env.X402_ENABLED) && env.X402_PAY_TO) {
    const auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
    return send(res, auth.status, auth.body, auth.headers);
  }
  try {
    rawBodyText = await readBody(req);
  } catch (err) {
    if (err.code === 'body_too_large') {
      return send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`));
    }
    return send(res, 400, errBody('read_error', 'Failed to read request body'));
  }

  let parsed;
  try {
    parsed = JSON.parse(rawBodyText || '{}');
  } catch {
    // Malformed JSON is ALWAYS rejected 400 before touching facilitator /settle.
    return send(res, 400, errBody('invalid_json', 'Request body is not valid JSON'));
  }

  if ((!parsed || typeof parsed !== 'object' || !parsed.receipt) &&
      !hasPaymentOrAuthHeader &&
      isFlagEnabled(env.X402_ENABLED) &&
      env.X402_PAY_TO) {
    const auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
    return send(res, auth.status, auth.body, auth.headers);
  }

  if (typeof parsed !== 'object' || parsed === null || !parsed.receipt) {
    return send(res, 400, errBody('missing_receipt', 'Request must be a JSON object with a "receipt" field'));
  }

  let auth;
  try {
    auth = await authorizeMonetizedRequest(req, { env, fetchImpl });
  } catch (err) {
    return send(res, 502, errBody('payment_gate_error', String((err && err.message) || err)));
  }
  if (!auth.authorized) {
    return send(res, auth.status, auth.body, auth.headers);
  }

  const hasOutput = Object.prototype.hasOwnProperty.call(parsed, 'output') && parsed.output !== undefined;
  const paxiomKey = getConfiguredPaxiomKey(env);
  const verifyOpts = {
    ...(hasOutput ? { output: parsed.output } : {}),
    ...(paxiomKey ? { trustedPaxiomPublicKeys: [paxiomKey.publicKey] } : {})
  };

  let baseResult;
  try {
    baseResult = verifyReceipt(parsed.receipt, verifyOpts);
  } catch (err) {
    return send(res, 500, errBody('verifier_error', String((err && err.message) || err)), auth.responseHeaders);
  }

  // If offline check already failed on structure, signature, expiry, or output mismatch,
  // return immediately without making unnecessary RPC calls.
  if (baseResult.trustState !== 'settlement_claimed_not_checked' && baseResult.trustState !== 'verified') {
    return send(res, 200, {
      ...baseResult,
      onchainSettlement: { checked: false, settled: false, reason: 'offline_verification_not_eligible' }
    }, auth.responseHeaders);
  }

  let onchain;
  try {
    onchain = await verifyOnchainUsdcSettlement(parsed.receipt, {
      env,
      fetchImpl,
      expectedPayTo: parsed.expectedPayTo || null,
      minConfirmations: Number(env.MIN_CONFIRMATIONS) || 1
    });
  } catch (err) {
    return send(res, 502, errBody(
      'onchain_rpc_error',
      `Failed to query chain RPC for settlement verification: ${(err && err.message) || err}`
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

  const finalTrustState = hasOutput ? 'verified' : 'valid_signature_only';
  const extraHeaders = { ...auth.responseHeaders };
  let counterAttestedReceipt = null;

  if (paxiomKey) {
    const orig = parsed.receipt.payload;
    const issued = issueReceipt({
      privateKey: paxiomKey.privateKeyPem,
      issuer: {
        name: env.PAXIOM_ISSUER_NAME || 'Paxiom Receipt Verifier',
        uri: env.PAXIOM_ISSUER_URI || 'https://paxiom.org',
        keyId: paxiomKey.keyId
      },
      service: orig.service,
      request: orig.request,
      payment: {
        ...orig.payment,
        settlement: {
          status: 'verified_settled',
          transactionHash: onchain.transactionHash,
          checkedByPaxiom: true
        }
      },
      outputHash: orig.delivery.outputHash,
      mimeType: orig.delivery.mimeType,
      evidence: [
        {
          type: 'attestation',
          status: 'verified',
          hash: baseResult.receiptHash,
          uri: orig.issuer.uri || null
        }
      ]
    });
    counterAttestedReceipt = issued.receipt;
    extraHeaders['X-Paxiom-Receipt'] = issued.receiptHeader;
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
    summary: finalTrustState === 'verified'
      ? `Receipt and on-chain USDC settlement (${onchain.transactionHash} on ${onchain.network}) verified.`
      : `Signature and on-chain USDC settlement (${onchain.transactionHash}) verified; supply output to verify outputHash binding.`
  }, extraHeaders);
}

export function createHandler({ env: rawEnv = process.env, fetchImpl = globalThis.fetch } = {}) {
  const env = resolveRuntimeEnv(rawEnv);
  return async function handleRequest(req, res) {
    const { method } = req;
    const path = (req.url || '').split('?')[0];

    if (method === 'OPTIONS') {
      res.writeHead(204, CORS);
      return res.end();
    }
    if (method === 'GET' && path === '/health') {
      return send(res, 200, { ok: true, service: 'paxiom-receipt-verifier', version: 'v0' });
    }
    if (method === 'GET' && path === '/version') {
      return send(res, 200, buildVersionPayload(env));
    }
    if (method === 'GET' && path === '/v1/receipt/demo') {
      return send(res, 200, {
        receiptVersion: RECEIPT_VERSION,
        output: demoOutput,
        receipt: demoReceipt,
        verify: { method: 'POST', path: '/v1/receipt/verify', body: { receipt: '<receipt>', output: '<output?>' } }
      });
    }
    if (method === 'GET' && path === '/.well-known/paxiom-keys.json') {
      const paxiomKey = getConfiguredPaxiomKey(env);
      return send(res, 200, {
        issuer: env.PAXIOM_ISSUER_NAME || 'Paxiom Receipt Verifier',
        keys: paxiomKey
          ? [{ keyId: paxiomKey.keyId, algorithm: 'ed25519', publicKey: paxiomKey.publicKey }]
          : []
      });
    }
    if (method === 'GET' && path === '/.well-known/x402.json') {
      if (!isFlagEnabled(env.X402_ENABLED) || !env.X402_PAY_TO) {
        return send(res, 404, errBody('x402_disabled', 'x402 payment discovery is not enabled on this instance.'));
      }
      return send(res, 200, buildX402PaymentRequirements(env));
    }
    if (method === 'POST' && path === '/v1/receipt/verify') {
      return handleOfflineVerify(req, res, env);
    }
    if ((method === 'POST' || method === 'GET') && path === '/v1/receipt/verify-live') {
      return handleLiveVerify(req, res, { env, fetchImpl });
    }
    return send(res, 404, errBody('not_found', `No route for ${method} ${path}`));
  };
}

// Default (req,res) handler for serverless platforms (Vercel).
export const handle = createHandler();

export function createServer(options = {}) {
  return http.createServer(createHandler(options));
}

export default handle;

// Run directly: node runtime/receipt-verifier/server.mjs
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const port = Number(process.env.PORT) || 8787;
  createServer().listen(port, () => {
    process.stdout.write(`paxiom-receipt-verifier (v0) on http://localhost:${port}\n`);
    process.stdout.write(`  GET  /health\n  GET  /version\n  GET  /v1/receipt/demo\n  POST /v1/receipt/verify\n  POST /v1/receipt/verify-live\n`);
  });
}
