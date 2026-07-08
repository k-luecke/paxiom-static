import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceipt, verifyFromFiles } from '../src/verify.mjs';

const EX = new URL('../examples/', import.meta.url);
const load = (name) => JSON.parse(readFileSync(new URL(name, EX), 'utf8'));
const path = (name) => new URL(name, EX).pathname;

const validReceipt = load('valid.receipt.json');
const validOutput = load('valid.output.json');
const mismatchOutput = load('output-mismatch.output.json');
const claimedReceipt = load('settlement-claimed-not-checked.receipt.json');

test('valid receipt + matching output -> verified', () => {
  const r = verifyReceipt(validReceipt, { output: validOutput });
  assert.equal(r.trustState, 'verified');
  assert.equal(r.valid, true);
  assert.equal(r.checks.signature, 'pass');
  assert.equal(r.checks.outputHash, 'pass');
  assert.match(r.receiptHash, /^0x[0-9a-f]{64}$/);
});

test('valid receipt + mismatched output -> output_hash_mismatch', () => {
  const r = verifyReceipt(validReceipt, { output: mismatchOutput });
  assert.equal(r.trustState, 'output_hash_mismatch');
  assert.equal(r.valid, false);
  assert.equal(r.checks.signature, 'pass');
  assert.equal(r.checks.outputHash, 'fail');
});

test('valid receipt with no output -> valid_signature_only', () => {
  const r = verifyReceipt(validReceipt);
  assert.equal(r.trustState, 'valid_signature_only');
  assert.equal(r.valid, false);
  assert.equal(r.checks.signature, 'pass');
  assert.equal(r.checks.outputHash, 'not_provided');
});

test('tampered signed field -> invalid_signature', () => {
  const tampered = structuredClone(validReceipt);
  tampered.payload.delivery.mimeType = 'text/plain';
  const r = verifyReceipt(tampered, { output: validOutput });
  assert.equal(r.trustState, 'invalid_signature');
  assert.equal(r.checks.signature, 'fail');
});

test('unknown receiptVersion -> unsupported_format', () => {
  const r = verifyReceipt({ ...validReceipt, receiptVersion: 'paxiom.receipt.v9' }, { output: validOutput });
  assert.equal(r.trustState, 'unsupported_format');
});

test('malformed receipt (missing payment) -> schema_invalid', () => {
  const bad = structuredClone(validReceipt);
  delete bad.payload.payment;
  const r = verifyReceipt(bad, { output: validOutput });
  assert.equal(r.trustState, 'schema_invalid');
  assert.equal(r.checks.schema, 'fail');
});

test('claimed-not-checked settlement -> settlement_claimed_not_checked (not verified)', () => {
  const r = verifyReceipt(claimedReceipt, { output: validOutput });
  assert.equal(r.trustState, 'settlement_claimed_not_checked');
  assert.equal(r.valid, false);
  assert.equal(r.checks.signature, 'pass');
  assert.equal(r.checks.outputHash, 'pass');
  assert.equal(r.checks.settlement, 'claimed_not_checked');
});

test('settlement_failed short-circuits before verified', () => {
  const failed = structuredClone(validReceipt);
  failed.payload.payment.settlement.status = 'failed';
  // note: mutating payload invalidates the signature, so this asserts ordering:
  // signature is checked before settlement, so we expect invalid_signature here.
  const r = verifyReceipt(failed, { output: validOutput });
  assert.equal(r.trustState, 'invalid_signature');
});

test('verifyFromFiles matches in-memory verify', () => {
  const r = verifyFromFiles(path('valid.receipt.json'), path('valid.output.json'));
  assert.equal(r.trustState, 'verified');
});

// --- hardening regressions (Findings A & B) ---

test('Finding A: { output: undefined } does not throw; behaves as no output', () => {
  let r;
  assert.doesNotThrow(() => { r = verifyReceipt(validReceipt, { output: undefined }); });
  assert.equal(r.trustState, 'valid_signature_only');
  assert.equal(r.valid, false);
  assert.equal(r.checks.signature, 'pass');
  assert.equal(r.checks.outputHash, 'not_provided'); // identical to omitting output
});

test('Finding B: pathologically deep output does not throw; returns error', () => {
  let deep = {};
  let cur = deep;
  for (let i = 0; i < 1000; i++) { cur.a = {}; cur = cur.a; } // depth 1000 > MAX_DEPTH
  let r;
  assert.doesNotThrow(() => { r = verifyReceipt(validReceipt, { output: deep }); });
  assert.equal(r.trustState, 'error');
  assert.equal(r.valid, false);
  assert.equal(r.checks.outputHash, 'error');
});
