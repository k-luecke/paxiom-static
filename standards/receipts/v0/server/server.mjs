// Minimal HTTP wrapper around the offline paxiom.receipt.v0 verifier.
// Node built-ins only. Free developer-preview endpoint — NO x402 gating, NO chain
// or facilitator calls. It is a thin transport over verifyReceipt().
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { verifyReceipt, RECEIPT_VERSION } from '../src/verify.mjs';

const MAX_BODY_BYTES = 256 * 1024; // 256 KiB — receipts are small; hash big outputs locally.
const EX = new URL('../examples/', import.meta.url);
const demoReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const demoOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type'
};

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', ...CORS });
  res.end(json);
}

function errorResult(code, message, status) {
  return { status, body: { valid: false, trustState: 'error', error: { code, message } } };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', (c) => {
      if (tooLarge) return; // keep draining but discard, so the socket closes cleanly
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        reject(Object.assign(new Error('body too large'), { code: 'body_too_large' }));
        return;
      }
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
    if (err.code === 'body_too_large') {
      const e = errorResult('body_too_large', `Request body exceeds ${MAX_BODY_BYTES / 1024} KiB`, 413);
      return send(res, e.status, e.body);
    }
    const e = errorResult('read_error', 'Failed to read request body', 400);
    return send(res, e.status, e.body);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw || '{}');
  } catch {
    const e = errorResult('invalid_json', 'Request body is not valid JSON', 400);
    return send(res, e.status, e.body);
  }
  if (typeof parsed !== 'object' || parsed === null || !parsed.receipt) {
    const e = errorResult('missing_receipt', 'Request must be a JSON object with a "receipt" field', 400);
    return send(res, e.status, e.body);
  }

  try {
    const opts = Object.prototype.hasOwnProperty.call(parsed, 'output') ? { output: parsed.output } : {};
    const result = verifyReceipt(parsed.receipt, opts);
    // 200 for any normal verification result, including non-verified receipts.
    return send(res, 200, result);
  } catch (err) {
    const e = errorResult('verifier_error', String((err && err.message) || err), 500);
    return send(res, e.status, e.body);
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const { method } = req;
    const path = (req.url || '').split('?')[0];

    if (method === 'OPTIONS') {
      res.writeHead(204, CORS);
      return res.end();
    }

    if (method === 'GET' && path === '/health') {
      return send(res, 200, { ok: true, service: 'paxiom-receipt-verifier', version: 'v0' });
    }

    if (method === 'GET' && path === '/v1/receipt/demo') {
      return send(res, 200, {
        receiptVersion: RECEIPT_VERSION,
        output: demoOutput,
        receipt: demoReceipt,
        verify: { method: 'POST', path: '/v1/receipt/verify', body: { receipt: '<receipt>', output: '<output?>' } }
      });
    }

    if (method === 'POST' && path === '/v1/receipt/verify') {
      return handleVerify(req, res);
    }

    const e = errorResult('not_found', `No route for ${method} ${path}`, 404);
    return send(res, e.status, e.body);
  });
}

// Run directly: node standards/receipts/v0/server/server.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 8787;
  createServer().listen(port, () => {
    process.stdout.write(`paxiom-receipt-verifier (v0, offline) listening on http://localhost:${port}\n`);
    process.stdout.write(`  GET  /health\n  GET  /v1/receipt/demo\n  POST /v1/receipt/verify\n`);
  });
}
