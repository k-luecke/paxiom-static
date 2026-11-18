import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const pkgDir = fileURLToPath(new URL('..', import.meta.url)).replace(/\/+$/, '');

test('CommonJS exports match ESM exports 1:1 across index, guard, and web', async () => {
  const esmIndex = await import('../src/index.mjs');
  const esmGuard = await import('../src/guard.mjs');
  const esmWeb = await import('../src/web.mjs');

  const cjsIndex = require('../cjs/index.cjs');
  const cjsGuard = require('../cjs/guard.cjs');
  const cjsWeb = require('../cjs/web.cjs');

  assert.deepEqual(Object.keys(cjsIndex).sort(), Object.keys(esmIndex).sort());
  assert.deepEqual(Object.keys(cjsGuard).sort(), Object.keys(esmGuard).sort());
  assert.deepEqual(Object.keys(cjsWeb).sort(), Object.keys(esmWeb).sort());
});

test('CommonJS circular load order works both guard-first and web-first in fresh Node processes', () => {
  const guardFirst = execFileSync(
    process.execPath,
    [
      '-e',
      `const g = require('./cjs/guard.cjs');
       const w = require('./cjs/web.cjs');
       if (typeof g.evaluatePreSignPolicy !== 'function' || typeof w.verifyReceipt !== 'function' || typeof w.evaluateDeliveryArbiter !== 'function') process.exit(1);`
    ],
    { cwd: pkgDir, encoding: 'utf8' }
  );
  assert.equal(guardFirst, '');

  const webFirst = execFileSync(
    process.execPath,
    [
      '-e',
      `const w = require('./cjs/web.cjs');
       const g = require('./cjs/guard.cjs');
       if (typeof w.evaluatePreSignPolicy !== 'function' || typeof g.evaluateDeliveryArbiter !== 'function' || typeof w.verifyReceipt !== 'function') process.exit(1);`
    ],
    { cwd: pkgDir, encoding: 'utf8' }
  );
  assert.equal(webFirst, '');
});

test('CommonJS end-to-end Gate 1 pre-sign firewall + Gate 2 receipt delivery arbiter round-trip', async () => {
  const { generateReceiptKeyPair, issueReceipt } = require('../cjs/index.cjs');
  const {
    createMemorySpendLedger,
    evaluatePreSignPolicy,
    evaluateDeliveryArbiter
  } = require('../cjs/guard.cjs');

  const kp = generateReceiptKeyPair({ keyId: 'seller-k1' });
  const ledger = createMemorySpendLedger();
  const url = 'https://seller.example/v1/alpha';
  const payTo = '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4';
  const usdc = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

  const pre = evaluatePreSignPolicy(
    {
      url,
      challenge: {
        accepts: [
          {
            scheme: 'exact',
            network: 'eip155:8453',
            asset: usdc,
            payTo,
            amount: '10000'
          }
        ]
      }
    },
    {
      maxPerCallAtomic: '50000',
      maxSessionAtomic: '100000',
      allowedNetworks: ['eip155:8453'],
      allowedAssets: [usdc],
      allowedPayTo: [payTo]
    },
    ledger
  );
  assert.equal(pre.allow, true);
  assert.ok(pre.reservationId);

  const bodyObj = { ok: true, signal: 42 };
  const { receiptHeader } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller', keyId: 'seller-k1', payTo },
    service: { name: 'Alpha', resource: '/v1/alpha', method: 'GET' },
    request: { method: 'GET', resource: '/v1/alpha', body: '' },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: usdc,
      amountAtomic: '10000',
      amountDisplay: '$0.01 USDC',
      payTo,
      settlement: { status: 'verify_only', transactionHash: null }
    },
    output: bodyObj
  });

  const arb = await evaluateDeliveryArbiter(
    {
      origin: 'https://seller.example',
      reservationId: pre.reservationId,
      challenge: pre.challenge,
      request: { url, method: 'GET', body: '' },
      response: { status: 200, headers: { 'payment-receipt': receiptHeader } },
      body: JSON.stringify(bodyObj)
    },
    {
      ledger,
      expectedIssuerPublicKeys: [kp.publicKey]
    }
  );
  assert.equal(arb.action, 'CAPTURE', `${arb.reasonCode}: ${arb.reason}`);
  assert.equal(arb.ok, true);
  assert.equal(ledger.snapshot().committedSessionAtomic, 10000n);
});
