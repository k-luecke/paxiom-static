import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_PAXIOM_API_URL,
  PAXIOM_LIVE_VERIFIER_PUBLIC_KEY,
  PAXIOM_TRUSTED_PUBLIC_KEYS,
  resolveSafeApiOrigin,
  verifyResponseReceipt,
  preflightX402,
  verifyReceiptLive,
  generateReceiptKeyPair,
  issueReceipt
} from '../src/index.mjs';

test('resolveSafeApiOrigin enforces https:// except loopback http:// and blocks embedded credentials', () => {
  assert.equal(resolveSafeApiOrigin(), DEFAULT_PAXIOM_API_URL);
  assert.equal(resolveSafeApiOrigin('https://api.paxiom.org/v1/extra'), 'https://api.paxiom.org');
  assert.equal(resolveSafeApiOrigin('http://127.0.0.1:8787'), 'http://127.0.0.1:8787');
  assert.equal(resolveSafeApiOrigin('http://localhost:8787'), 'http://localhost:8787');

  assert.throws(() => resolveSafeApiOrigin('http://api.paxiom.org'), /https:\/\//);
  assert.throws(() => resolveSafeApiOrigin('https://user:pass@api.paxiom.org'), /credentials/);
  assert.equal(PAXIOM_TRUSTED_PUBLIC_KEYS.includes(PAXIOM_LIVE_VERIFIER_PUBLIC_KEY), true);
});

test('verifyResponseReceipt handles absent, malformed, valid, and mismatched X-Paxiom-Receipt headers without throwing', () => {
  const noHdr = verifyResponseReceipt(new Response('{}', { status: 200 }));
  assert.equal(noHdr.present, false);
  assert.equal(noHdr.valid, false);
  assert.equal(noHdr.trustState, null);

  const badHdr = verifyResponseReceipt(
    new Response('{}', { status: 200, headers: { 'x-paxiom-receipt': '!!!not-base64-json!!!' } })
  );
  assert.equal(badHdr.present, true);
  assert.equal(badHdr.valid, false);
  assert.equal(badHdr.trustState, 'malformed_header');

  const kp = generateReceiptKeyPair({ keyId: 'seller-client-01' });
  const output = { alpha: 42 };
  const { receiptHeader } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller', keyId: kp.keyId },
    service: { name: 'API', resource: 'https://seller.example/v1', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });

  const okRes = verifyResponseReceipt(
    new Response(JSON.stringify(output), {
      status: 200,
      headers: { 'X-Paxiom-Receipt': receiptHeader }
    }),
    { output }
  );
  assert.equal(okRes.present, true);
  assert.equal(okRes.valid, true);
  assert.equal(okRes.trustState, 'verified');

  // Node IncomingMessage-style plain headers object with tampered output
  const mismatch = verifyResponseReceipt(
    { headers: { 'x-paxiom-receipt': receiptHeader } },
    { output: { alpha: 999 } }
  );
  assert.equal(mismatch.present, true);
  assert.equal(mismatch.valid, false);
  assert.equal(mismatch.trustState, 'output_hash_mismatch');
});

test('preflightX402 handles unpaid 402 challenges, paid 200 + signed X-Paxiom-Receipt, redirects, and input bounds', async () => {
  await assert.rejects(() => preflightX402('http://insecure.seller.example/v1'), /https:\/\//);
  await assert.rejects(() => preflightX402('https://seller.example/v1', { method: 'DELETE' }), /POST, GET, or HEAD/);
  await assert.rejects(() => preflightX402('https://seller.example/v1', { maxBudgetAtomic: '-5' }), /non-negative/);

  // 1. Unpaid 402 challenge decoding
  const challengePayload = {
    x402Version: 1,
    accepts: [{ scheme: 'exact', network: 'base', maxAmountRequired: '10000' }]
  };
  const unpaidFetch = async () => new Response(JSON.stringify(challengePayload), {
    status: 402,
    headers: {
      'content-type': 'application/json',
      'payment-required': Buffer.from(JSON.stringify(challengePayload), 'utf8').toString('base64')
    }
  });
  const unpaid = await preflightX402('https://seller.example/v1', { fetch: unpaidFetch });
  assert.equal(unpaid.ok, false);
  assert.equal(unpaid.status, 402);
  assert.equal(unpaid.paymentRequired, true);
  assert.equal(unpaid.challenge.accepts[0].maxAmountRequired, '10000');

  // 2. Paid 200 response with signed X-Paxiom-Receipt + PAYMENT-RESPONSE
  const paxiomKp = generateReceiptKeyPair({ keyId: 'paxiom-test-01' });
  const reportBody = {
    ok: true,
    targetUrl: 'https://seller.example/v1',
    probedMethod: 'POST',
    verdict: 'proceed',
    riskLevel: 'low',
    httpStatus: 402,
    selectedQuote: {
      scheme: 'exact',
      network: 'eip155:8453',
      rawNetwork: 'base',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      canonicalUsdc: true,
      payTo: '0x1111111111111111111111111111111111111111',
      amountAtomic: '5000',
      maxTimeoutSeconds: 60
    },
    recommendedMaxPaymentAtomic: '5000',
    checks: { canonicalUsdcAsset: 'pass' },
    receiptSupport: { paxiomHeaderExposed: true, paxiomWellKnownKeys: 1 },
    findings: []
  };
  const { receiptHeader } = issueReceipt({
    privateKey: paxiomKp.privateKeyPem,
    issuer: { name: 'Paxiom Receipt Verifier', keyId: paxiomKp.keyId },
    service: { name: 'Preflight', resource: 'https://api.paxiom.org/v1/x402/preflight', method: 'POST' },
    payment: { settlement: { status: 'not_required', transactionHash: null, checkedByPaxiom: false } },
    output: reportBody
  });
  const settleJson = { success: true, transaction: '0x' + 'aa'.repeat(32) };

  const paidFetch = async (_url, init) => {
    assert.equal(init.redirect, 'manual');
    assert.equal(init.headers['x-api-key'], 'pax_test_key');
    return new Response(JSON.stringify(reportBody), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-paxiom-receipt': receiptHeader,
        'payment-response': Buffer.from(JSON.stringify(settleJson), 'utf8').toString('base64')
      }
    });
  };

  const paid = await preflightX402('https://seller.example/v1', {
    apiKey: 'pax_test_key',
    fetch: paidFetch,
    trustedPaxiomPublicKeys: [paxiomKp.publicKey]
  });
  assert.equal(paid.ok, true);
  assert.equal(paid.verdict, 'proceed');
  assert.equal(paid.receiptVerification.valid, true);
  assert.equal(paid.receiptVerification.trustState, 'verified');
  assert.equal(paid.paymentResponse.success, true);

  // 3. Refuses 3xx redirects so credentials never leak
  const redirectFetch = async () => new Response('', { status: 302, headers: { location: 'https://evil.example' } });
  await assert.rejects(() => preflightX402('https://seller.example/v1', { fetch: redirectFetch }), /redirect/);
});

test('verifyReceiptLive validates expectedPayTo and verifies returned counterAttestedReceipt offline', async () => {
  const sellerKp = generateReceiptKeyPair({ keyId: 'seller-01' });
  const paxiomKp = generateReceiptKeyPair({ keyId: 'paxiom-root-01' });
  const output = { result: 'ok' };
  const txHash = '0x' + 'bb'.repeat(32);

  const { receipt: claimed } = issueReceipt({
    privateKey: sellerKp.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKp.keyId },
    service: { name: 'API', resource: 'https://seller.example/v1', method: 'POST' },
    payment: {
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  await assert.rejects(
    () => verifyReceiptLive(claimed, { expectedPayTo: 'not-an-evm-address' }),
    /expectedPayTo/
  );

  const { receipt: counterReceipt } = issueReceipt({
    privateKey: paxiomKp.privateKeyPem,
    issuer: { name: 'Paxiom Receipt Verifier', keyId: paxiomKp.keyId },
    service: { name: 'API', resource: 'https://seller.example/v1', method: 'POST' },
    payment: {
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      settlement: { status: 'verified_settled', transactionHash: txHash, checkedByPaxiom: true }
    },
    output
  });

  const liveFetch = async () => new Response(JSON.stringify({
    valid: true,
    trustState: 'verified',
    onchainSettlement: { checked: true, settled: true, transactionHash: txHash },
    counterAttestedReceipt: counterReceipt
  }), { status: 200, headers: { 'content-type': 'application/json' } });

  const live = await verifyReceiptLive(claimed, {
    output,
    expectedPayTo: '0x1111111111111111111111111111111111111111',
    fetch: liveFetch,
    trustedPaxiomPublicKeys: [paxiomKp.publicKey]
  });
  assert.equal(live.ok, true);
  assert.equal(live.valid, true);
  assert.equal(live.trustState, 'verified');
  assert.ok(live.counterAttestedReceipt);
  assert.equal(live.counterAttestedVerification.valid, true);
  assert.equal(live.counterAttestedVerification.trustState, 'verified');
});
