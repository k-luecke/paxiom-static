import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from '../server.mjs';

const EX = new URL('../../../standards/receipts/v0/examples/', import.meta.url);
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

const post = (path, body) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body });

test('GET /health', async () => {
  const res = await fetch(base + '/health');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).ok, true);
});

test('GET /version states v0 claim boundaries', async () => {
  const res = await fetch(base + '/version');
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.receiptVersion, 'paxiom.receipt.v0');
  assert.equal(j.runtime, 'developer-preview');
  assert.ok(j.checks.includes('signature'));
  assert.ok(j.notChecked.includes('onchainSettlement'));
  assert.ok(j.notChecked.includes('proofSourceEvidence'));
});

test('GET /v1/receipt/demo returns fixtures', async () => {
  const res = await fetch(base + '/v1/receipt/demo');
  assert.equal(res.status, 200);
  assert.equal((await res.json()).receipt.receiptVersion, 'paxiom.receipt.v0');
});

test('POST /v1/receipt/verify valid -> 200 verified', async () => {
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, output: validOutput }));
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.valid, true);
  assert.equal(j.trustState, 'verified');
});

test('POST mismatch -> 200 output_hash_mismatch', async () => {
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, output: mismatchOutput }));
  assert.equal(res.status, 200);
  assert.equal((await res.json()).trustState, 'output_hash_mismatch');
});

test('POST invalid JSON -> 400', async () => {
  const res = await post('/v1/receipt/verify', '{nope');
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'invalid_json');
});

test('POST oversized body -> 413', async () => {
  const big = 'x'.repeat(256 * 1024 + 10);
  const res = await post('/v1/receipt/verify', JSON.stringify({ receipt: validReceipt, blob: big }));
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error.code, 'body_too_large');
});

test('unknown path -> 404', async () => {
  const res = await fetch(base + '/nope');
  assert.equal(res.status, 404);
});
