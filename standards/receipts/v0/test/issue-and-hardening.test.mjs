import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  verifyReceipt,
  generateReceiptKeyPair,
  issueReceipt,
  decodeReceiptHeader,
  withPaxiomReceipt,
  createReceiptMiddleware
} from '../src/index.mjs';

test('non-ISO expiresAt is rejected by schema validator (never bypasses Date.parse via NaN)', () => {
  const kp = generateReceiptKeyPair({ keyId: 'seller-k1' });
  const output = { ok: true, answer: 7 };
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    expiresAt: 'not-a-valid-iso-date',
    issuer: { name: 'Seller', keyId: kp.keyId },
    service: { name: 'Seller API', resource: 'https://example.com/v1/q', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });
  const res = verifyReceipt(receipt, { output });
  assert.equal(res.trustState, 'schema_invalid');
  assert.equal(res.valid, false);
});

test('expired ISO expiresAt returns expired', () => {
  const kp = generateReceiptKeyPair({ keyId: 'seller-k1' });
  const output = { ok: true };
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-02T00:00:00.000Z',
    issuer: { name: 'Seller', keyId: kp.keyId },
    service: { name: 'Seller API', resource: 'https://example.com/v1/q', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });
  const res = verifyReceipt(receipt, { output });
  assert.equal(res.trustState, 'expired');
  assert.equal(res.valid, false);
});

test('payload.issuer.keyId != signature.keyId returns invalid_signature', () => {
  const kp = generateReceiptKeyPair({ keyId: 'seller-k1' });
  const output = { ok: true };
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller', keyId: kp.keyId },
    service: { name: 'Seller API', resource: 'https://example.com/v1/q', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });
  receipt.signature.keyId = 'different-key-id';
  const res = verifyReceipt(receipt, { output });
  assert.equal(res.trustState, 'invalid_signature');
});

test('untrusted signer setting checkedByPaxiom=true cannot reach verified; trusted Paxiom key can', () => {
  const kp = generateReceiptKeyPair({ keyId: 'paxiom-live-001' });
  const output = { result: 'paid-data' };
  const txHash = '0x' + 'ab'.repeat(32);
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Paxiom', keyId: kp.keyId },
    service: { name: 'Data API', resource: 'https://api.example.com/data', method: 'POST' },
    payment: {
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'verified_settled', transactionHash: txHash, checkedByPaxiom: true }
    },
    output
  });

  // Without pinning Paxiom's public key, offline verifier treats checkedByPaxiom=true as unverified claim
  const untrusted = verifyReceipt(receipt, { output });
  assert.equal(untrusted.trustState, 'settlement_claimed_not_checked');
  assert.equal(untrusted.valid, false);

  // With Paxiom's public key pinned in trustedPaxiomPublicKeys, counter-attested receipt reaches verified
  const trusted = verifyReceipt(receipt, {
    output,
    trustedPaxiomPublicKeys: [kp.publicKey]
  });
  assert.equal(trusted.trustState, 'verified');
  assert.equal(trusted.valid, true);
});

test('withPaxiomReceipt wraps Web Fetch handler and emits verifiable X-Paxiom-Receipt header', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'fetch-seller-01' });
  const app = withPaxiomReceipt(
    async (req) => {
      const body = await req.json();
      return new Response(JSON.stringify({ echoed: body.query, score: 99 }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    },
    {
      privateKey: kp.privateKeyPem,
      issuer: { name: 'Fetch Seller', keyId: kp.keyId },
      paymentDefaults: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } }
    }
  );

  const req = new Request('https://seller.example/v1/score', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'agent-trust' })
  });
  const res = await app(req);
  assert.equal(res.status, 200);
  const hdr = res.headers.get('x-paxiom-receipt');
  assert.ok(hdr, 'expected X-Paxiom-Receipt header');

  const output = await res.json();
  const receipt = decodeReceiptHeader(hdr);
  const verified = verifyReceipt(receipt, { output });
  assert.equal(verified.trustState, 'verified');
});

test('createReceiptMiddleware attaches X-Paxiom-Receipt on Node HTTP responses and binds x402 settlement tx', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'node-mw-01' });
  const mw = createReceiptMiddleware({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Node Seller', keyId: kp.keyId }
  });

  const txHash = '0x' + 'cd'.repeat(32);
  const paymentResB64 = Buffer.from(JSON.stringify({ success: true, transaction: txHash }), 'utf8').toString('base64');

  const srv = http.createServer((req, res) => {
    mw(req, res, () => {
      res.setHeader('content-type', 'application/json');
      res.setHeader('payment-response', paymentResB64);
      res.end(JSON.stringify({ delivered: 'alpha-feed' }));
    });
  });

  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const { port } = srv.address();
    const res = await fetch(`http://127.0.0.1:${port}/v1/feed`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': 'demo-sig' },
      body: JSON.stringify({ symbol: 'ETH' })
    });
    const output = await res.json();
    const receipt = decodeReceiptHeader(res.headers.get('x-paxiom-receipt'));
    assert.equal(receipt.payload.payment.settlement.transactionHash, txHash);
    assert.equal(receipt.payload.payment.settlement.status, 'claimed_not_checked');

    const verified = verifyReceipt(receipt, { output });
    assert.equal(verified.trustState, 'settlement_claimed_not_checked');
    assert.equal(verified.checks.outputHash, 'pass');
  } finally {
    await new Promise((r) => srv.close(r));
  }
});

test('CLI keygen -> issue -> verify round-trip works end-to-end', () => {
  const dir = mkdtempSync(join(tmpdir(), 'paxiom-cli-test-'));
  try {
    const cli = new URL('../bin/paxiom-receipt.mjs', import.meta.url).pathname;
    const keyPath = join(dir, 'issuer.pem');
    const outPath = join(dir, 'output.json');
    const rcptPath = join(dir, 'receipt.json');

    writeFileSync(outPath, JSON.stringify({ status: 'ok', items: [1, 2, 3] }));
    const keyMeta = JSON.parse(execFileSync(process.execPath, [cli, 'keygen', '--key-id', 'cli-k1', '--out', keyPath], { encoding: 'utf8' }));
    assert.equal(keyMeta.keyId, 'cli-k1');

    execFileSync(process.execPath, [
      cli, 'issue',
      '--key', keyPath,
      '--issuer-name', 'CLI Test',
      '--key-id', 'cli-k1',
      '--resource', 'https://api.example.com/items',
      '--output', outPath,
      '--out', rcptPath
    ], { encoding: 'utf8' });

    const verifyJson = JSON.parse(execFileSync(process.execPath, [
      cli, 'verify', rcptPath, '--output', outPath, '--json'
    ], { encoding: 'utf8' }));
    assert.equal(verifyJson.trustState, 'verified');
    assert.equal(verifyJson.valid, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
