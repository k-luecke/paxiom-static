// Public runtime for the FREE Paxiom Receipt Verifier (developer preview).
//
// Offline semantics: verifies local receipt structure, Ed25519 signature, output
// binding, and honest settlement/proof status. It makes NO chain calls, NO
// facilitator calls, requires NO secrets, writes NO files, and has NO x402 gating.
//
// The verification logic is the single source of truth in the spec repo; this file
// is only the deployable HTTP surface. Works as a long-running server (Render, Fly,
// bare node) and exports a default (req,res) handler for serverless (Vercel).
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { verifyReceipt, RECEIPT_VERSION } from '../../standards/receipts/v0/src/verify.mjs';

const MAX_BODY_BYTES = 256 * 1024; // 256 KiB
const EX = new URL('../../standards/receipts/v0/examples/', import.meta.url);
const demoReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const demoOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

const VERSION = {
  service: 'paxiom-receipt-verifier',
  receiptVersion: RECEIPT_VERSION,
  runtime: 'developer-preview',
  checks: ['schema', 'signature', 'outputHash', 'bindingFields', 'settlementStatusVocabulary', 'evidenceStatusVocabulary'],
  notChecked: ['onchainSettlement', 'facilitatorRecords', 'proofSourceEvidence', 'archiveAvailability'],
  note: 'Developer-preview reference verifier for paxiom.receipt.v0. Verifies receipt schema, Ed25519 signature, and output binding. Reports settlement and proof-evidence states but does NOT independently verify onchain settlement, facilitator records, or proof-source evidence in v0. Free — no x402 gating.'
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type'
};

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', ...CORS });
  res.end(JSON.stringify(body));
}
const errBody = (code, message) => ({ valid: false, trustState: 'error', error: { code, message } });

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0, tooLarge = false;
    const chunks = [];
    req.on('data', (c) => {
      if (tooLarge) return; // drain-and-discard so the socket closes cleanly
      size += c.length;
      if (size > MAX_BODY_BYTES) { tooLarge = true; reject(Object.assign(new Error('body too large'), { code: 'body_too_large' })); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!tooLarge) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

async function handleVerify(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch (err) {
    if (err.code === 'body_too_large') return send(res, 413, errBody('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`));
    return send(res, 400, errBody('read_error', 'Failed to read request body'));
  }
  let parsed;
  try {
    parsed = JSON.parse(raw || '{}');
  } catch {
    return send(res, 400, errBody('invalid_json', 'Request body is not valid JSON'));
  }
  if (typeof parsed !== 'object' || parsed === null || !parsed.receipt) {
    return send(res, 400, errBody('missing_receipt', 'Request must be a JSON object with a "receipt" field'));
  }
  try {
    const opts = Object.prototype.hasOwnProperty.call(parsed, 'output') ? { output: parsed.output } : {};
    return send(res, 200, verifyReceipt(parsed.receipt, opts)); // 200 for any verification result
  } catch (err) {
    // NB: do not log the receipt payload.
    return send(res, 500, errBody('verifier_error', String((err && err.message) || err)));
  }
}

// The core (req,res) handler. Exported so serverless platforms can wrap it.
export async function handle(req, res) {
  const { method } = req;
  const path = (req.url || '').split('?')[0];

  if (method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  if (method === 'GET' && path === '/health') return send(res, 200, { ok: true, service: 'paxiom-receipt-verifier', version: 'v0' });
  if (method === 'GET' && path === '/version') return send(res, 200, VERSION);
  if (method === 'GET' && path === '/v1/receipt/demo') {
    return send(res, 200, {
      receiptVersion: RECEIPT_VERSION,
      output: demoOutput,
      receipt: demoReceipt,
      verify: { method: 'POST', path: '/v1/receipt/verify', body: { receipt: '<receipt>', output: '<output?>' } }
    });
  }
  if (method === 'POST' && path === '/v1/receipt/verify') return handleVerify(req, res);
  return send(res, 404, errBody('not_found', `No route for ${method} ${path}`));
}

export function createServer() {
  return http.createServer(handle);
}

export default handle; // for serverless (e.g. Vercel catch-all function)

// Run directly: node runtime/receipt-verifier/server.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 8787;
  createServer().listen(port, () => {
    process.stdout.write(`paxiom-receipt-verifier (v0, free/offline) on http://localhost:${port}\n`);
    process.stdout.write(`  GET  /health\n  GET  /version\n  GET  /v1/receipt/demo\n  POST /v1/receipt/verify\n`);
  });
}
