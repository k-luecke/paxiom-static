import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from './server.mjs';

const EX = new URL('../examples/', import.meta.url);
const load = (name) => JSON.parse(readFileSync(new URL(name, EX), 'utf8'));
const validReceipt = load('valid.receipt.json');
const validOutput = load('valid.output.json');
const mismatchOutput = load('output-mismatch.output.json');

let server, base;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const post = (path, bodyStr, headers = {}) =>
  fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: bodyStr });

test('GET /health -> ok', async () => {
  const res = await fetch(base + '/health');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  const j = await res.json();
  assert.deepEqual(j, { ok: true, service: 'paxiom-receipt-verifier', version: 'v0' });
});

test('GET /v1/receipt/demo -> returns fixtures', async () => {
  const res = await fetch(base + '/v1/receipt/demo');
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.receipt.receiptVersion, 'paxiom.receipt.v0');
  assert.ok(j.output);
  assert.equal(j.verify.path, '/v1/receipt/verify');
});

test('POST valid receipt + output -> 200 verified', async () => {
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, output: validOutput }));
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.valid, true);
  assert.equal(j.trustState, 'verified');
});

test('POST output mismatch -> 200 output_hash_mismatch', async () => {
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, output: mismatchOutput }));
  assert.equal(res.status, 200); // non-verified is still a normal result
  const j = await res.json();
  assert.equal(j.valid, false);
  assert.equal(j.trustState, 'output_hash_mismatch');
});

test('POST invalid JSON -> 400', async () => {
  const res = await post('/v1/receipt/verify', '{not json');
  assert.equal(res.status, 400);
  const j = await res.json();
  assert.equal(j.trustState, 'error');
  assert.equal(j.error.code, 'invalid_json');
});

test('POST missing receipt field -> 400', async () => {
  const res = await post('/v1/receipt/verify', JSON.stringify({ output: validOutput }));
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'missing_receipt');
});

test('POST body too large -> 413', async () => {
  const big = 'x'.repeat(256 * 1024 + 10);
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, blob: big }));
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error.code, 'body_too_large');
});

test('unknown path -> 404', async () => {
  const res = await fetch(base + '/nope');
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error.code, 'not_found');
});
