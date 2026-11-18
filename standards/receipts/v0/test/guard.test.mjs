import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}

import {
  generateReceiptKeyPair,
  issueReceipt,
  withPaxiomReceipt
} from '../src/index.mjs';
import {
  createMemorySpendLedger,
  evaluatePreSignPolicy,
  evaluateDeliveryArbiter,
  createGuardedFetch,
  extractPaymentChallenges
} from '../src/guard.mjs';
import * as webSdk from '../src/web.mjs';

const TRUSTED_OPERATOR = '0x1111111111111111111111111111111111111111';
const SELLER_PAY_TO = '0x2222222222222222222222222222222222222222';
const ATTACKER_PAY_TO = '0x9999999999999999999999999999999999999999';
const PAYMENT_INFO_HASH = '0x' + 'ab'.repeat(32);

function encodeChallengeHeader(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

test('v0.3.0 @paxiom/receipts/guard has ZERO node:* imports, ZERO Buffer tokens, and is re-exported on web & node', () => {
  for (const rel of ['../src/guard.mjs', '../src/guard.d.ts']) {
    const raw = readFileSync(new URL(rel, import.meta.url), 'utf8');
    const codeOnly = raw
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    assert.equal(/\bnode:[A-Za-z0-9_-]+/.test(codeOnly), false, `${rel} must not import node:*`);
    assert.equal(/\bBuffer\b/.test(codeOnly), false, `${rel} must not reference Buffer`);
  }
  assert.equal(typeof webSdk.evaluatePreSignPolicy, 'function');
  assert.equal(typeof webSdk.evaluateDeliveryArbiter, 'function');
  assert.equal(typeof webSdk.createGuardedFetch, 'function');
  assert.equal(typeof webSdk.createMemorySpendLedger, 'function');
});

test('Gate 1 (evaluatePreSignPolicy): enforces HTTPS, origin allow/deny, per-call caps, payTo pinning, and escrow thresholds', () => {
  const nowMs = 1_800_000_000_000;
  const nowSec = Math.floor(nowMs / 1000);
  const basePolicy = {
    maxPerCallAtomic: 500_000n, // $0.50 USDC
    maxPerOriginWindowAtomic: 1_000_000n, // $1.00 USDC
    maxSessionAtomic: 2_000_000n, // $2.00 USDC
    maxUnescrowedExactAtomic: 10_000n, // $0.01 microcap for irreversible exact
    allowedNetworks: ['eip155:8453'],
    pinnedPayToByOrigin: {
      'https://api.seller.example': SELLER_PAY_TO.toUpperCase().replace('0X', '0x')
    },
    trustedOperators: [TRUSTED_OPERATOR],
    maxAllowedFeeBps: 250 // 2.5%
  };

  // 1. Plaintext HTTP rejected
  const httpDeny = evaluatePreSignPolicy(
    { url: 'http://api.seller.example/v1/query', challenge: { scheme: 'exact', network: 'base', amount: '5000', payTo: SELLER_PAY_TO } },
    basePolicy
  );
  assert.equal(httpDeny.allow, false);
  assert.equal(httpDeny.code, 'insecure_transport');

  // 2. Embedded credentials rejected
  const credDeny = evaluatePreSignPolicy(
    { url: 'https://user:pass@api.seller.example/v1/query', challenge: { scheme: 'exact', network: 'base', amount: '5000', payTo: SELLER_PAY_TO } },
    basePolicy
  );
  assert.equal(credDeny.allow, false);
  assert.equal(credDeny.code, 'invalid_origin');

  // 3. Dynamic 402 price escalation ($25.00 > $0.50 cap)
  const priceSpike = evaluatePreSignPolicy(
    { url: 'https://api.seller.example/v1/query', challenge: { scheme: 'auth-capture', network: 'base', amount: '25000000', payTo: SELLER_PAY_TO }, nowMs },
    basePolicy
  );
  assert.equal(priceSpike.allow, false);
  assert.equal(priceSpike.code, 'per_call_cap_exceeded');

  // 4. Unpinned payTo substitution rejected
  const hijackedPayTo = evaluatePreSignPolicy(
    { url: 'https://api.seller.example/v1/query', challenge: { scheme: 'exact', network: 'base', amount: '5000', payTo: ATTACKER_PAY_TO }, nowMs },
    basePolicy
  );
  assert.equal(hijackedPayTo.allow, false);
  assert.equal(hijackedPayTo.code, 'untrusted_pay_to');

  // 5. Scheme downgrade: $0.25 `exact` rejected when maxUnescrowedExactAtomic == $0.01
  const exactAboveCap = evaluatePreSignPolicy(
    { url: 'https://api.seller.example/v1/query', challenge: { scheme: 'exact', network: 'base', amount: '250000', payTo: SELLER_PAY_TO }, nowMs },
    basePolicy
  );
  assert.equal(exactAboveCap.allow, false);
  assert.equal(exactAboveCap.code, 'escrow_required_above_microcap');

  // 6. AuthCaptureEscrow operator, fee bps, and expiry checks
  const badOperator = evaluatePreSignPolicy(
    {
      url: 'https://api.seller.example/v1/query',
      nowMs,
      challenge: {
        scheme: 'auth-capture',
        network: 'base',
        amount: '250000',
        payTo: SELLER_PAY_TO,
        extra: {
          operator: ATTACKER_PAY_TO,
          minFeeBps: 0,
          maxFeeBps: 100,
          authorizationExpiry: nowSec + 600
        }
      }
    },
    basePolicy
  );
  assert.equal(badOperator.allow, false);
  assert.equal(badOperator.code, 'untrusted_escrow_operator');

  const highFee = evaluatePreSignPolicy(
    {
      url: 'https://api.seller.example/v1/query',
      nowMs,
      challenge: {
        scheme: 'auth-capture',
        network: 'base',
        amount: '250000',
        payTo: SELLER_PAY_TO,
        extra: {
          operator: TRUSTED_OPERATOR,
          minFeeBps: 0,
          maxFeeBps: 500, // 5% > 2.5%
          authorizationExpiry: nowSec + 600
        }
      }
    },
    basePolicy
  );
  assert.equal(highFee.allow, false);
  assert.equal(highFee.code, 'escrow_fee_cap_exceeded');

  const shortExpiry = evaluatePreSignPolicy(
    {
      url: 'https://api.seller.example/v1/query',
      nowMs,
      challenge: {
        scheme: 'auth-capture',
        network: 'base',
        amount: '250000',
        payTo: SELLER_PAY_TO,
        extra: {
          operator: TRUSTED_OPERATOR,
          minFeeBps: 0,
          maxFeeBps: 100,
          authorizationExpiry: nowSec + 5 // < 30s minAuthWindowSec
        }
      }
    },
    basePolicy
  );
  assert.equal(shortExpiry.allow, false);
  assert.equal(shortExpiry.code, 'escrow_expiry_out_of_bounds');

  // 7. Multi-scheme `accepts`: automatically upgrades from `exact` to compliant `auth-capture`
  const ledger = createMemorySpendLedger();
  const multiAccept = evaluatePreSignPolicy(
    {
      url: 'https://api.seller.example/v1/query',
      nowMs,
      challenge: {
        accepts: [
          { scheme: 'exact', network: 'base', amount: '250000', payTo: SELLER_PAY_TO },
          {
            scheme: 'auth-capture',
            network: 'base',
            amount: '250000',
            payTo: SELLER_PAY_TO,
            extra: {
              operator: TRUSTED_OPERATOR,
              minFeeBps: 0,
              maxFeeBps: 100,
              authorizationExpiry: nowSec + 600,
              paymentInfoHash: PAYMENT_INFO_HASH
            }
          }
        ]
      }
    },
    basePolicy,
    ledger
  );
  assert.equal(multiAccept.allow, true);
  assert.equal(multiAccept.challenge.scheme, 'auth-capture');
  assert.equal(multiAccept.challenge.authCapture.paymentInfoHash, PAYMENT_INFO_HASH);
  assert.equal(multiAccept.reservedAtomic, 250_000n);
});

test('Gate 1 + Ledger: atomic reservations prevent concurrent calls from overshooting origin or session caps', () => {
  const nowMs = 1_800_000_000_000;
  const ledger = createMemorySpendLedger({ windowMs: 60_000 });
  const policy = {
    maxPerCallAtomic: 400_000n,
    maxPerOriginWindowAtomic: 700_000n,
    maxSessionAtomic: 900_000n
  };

  const makeReq = (origin, amt) => evaluatePreSignPolicy(
    { url: `${origin}/v1/tool`, nowMs, challenge: { scheme: 'exact', network: 'eip155:8453', amount: String(amt), payTo: SELLER_PAY_TO } },
    policy,
    ledger
  );

  const r1 = makeReq('https://a.example', 400_000);
  const r2 = makeReq('https://a.example', 400_000); // 400k + 400k > 700k origin cap even before r1 commits!
  assert.equal(r1.allow, true);
  assert.equal(r2.allow, false);
  assert.equal(r2.code, 'origin_window_cap_exceeded');

  const r3 = makeReq('https://b.example', 400_000); // 400k + 400k = 800k <= 900k session cap
  const r4 = makeReq('https://c.example', 200_000); // 800k + 200k = 1000k > 900k session cap
  assert.equal(r3.allow, true);
  assert.equal(r4.allow, false);
  assert.equal(r4.code, 'session_budget_exceeded');
});

test('Gate 2 (evaluateDeliveryArbiter): captures valid delivery, voids bogus signed content with non-repudiable fraud evidence, and blocks replay & cross-query substitution', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'seller-key-1' });
  const ledger = createMemorySpendLedger();
  const nowMs = Date.now();
  const challenge = extractPaymentChallenges({
    scheme: 'auth-capture',
    network: 'eip155:8453',
    amount: '250000',
    payTo: SELLER_PAY_TO,
    extra: {
      operator: TRUSTED_OPERATOR,
      minFeeBps: 0,
      maxFeeBps: 100,
      authorizationExpiry: Math.floor(nowMs / 1000) + 600,
      paymentInfoHash: PAYMENT_INFO_HASH
    }
  })[0];

  // Valid delivery -> CAPTURE
  const rsv1 = ledger.reserve({ origin: 'https://api.seller.example', amountAtomic: 250_000n, scheme: 'auth-capture', nowMs });
  const goodPayload = { results: [{ id: 1, score: 0.98 }] };
  const { receiptHeader: goodHeader } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller API', keyId: kp.keyId, payTo: SELLER_PAY_TO },
    service: { name: 'Seller API', resource: 'https://api.seller.example/v1/search?q=alpha', method: 'GET' },
    request: { method: 'GET', resource: 'https://api.seller.example/v1/search?q=alpha', body: '' },
    payment: {
      scheme: 'auth-capture',
      network: 'eip155:8453',
      asset: 'USDC',
      amountAtomic: '250000',
      payTo: SELLER_PAY_TO,
      settlement: { status: 'verify_only', transactionHash: null }
    },
    output: goodPayload
  });

  const dec1 = await evaluateDeliveryArbiter(
    {
      origin: 'https://api.seller.example',
      reservationId: rsv1,
      challenge,
      request: { url: 'https://api.seller.example/v1/search?q=alpha', method: 'GET' },
      response: { status: 200, headers: { 'payment-receipt': goodHeader } },
      body: JSON.stringify(goodPayload)
    },
    {
      ledger,
      expectedIssuerPublicKeys: [kp.publicKey],
      validateContent: (body) => Array.isArray(body.results) && body.results.length > 0
    }
  );
  assert.equal(dec1.action, 'CAPTURE');
  assert.equal(dec1.ok, true);
  assert.equal(dec1.captureAmountAtomic, 250_000n);
  assert.equal(dec1.paymentInfoHash, PAYMENT_INFO_HASH);
  assert.equal(ledger.snapshot(nowMs).committedSessionAtomic, 250_000n);

  // Replay of exact same receipt on a second call -> VOID (`replayed_receipt`)
  const rsvReplay = ledger.reserve({ origin: 'https://api.seller.example', amountAtomic: 250_000n, scheme: 'auth-capture', nowMs });
  const decReplay = await evaluateDeliveryArbiter(
    {
      origin: 'https://api.seller.example',
      reservationId: rsvReplay,
      challenge,
      request: { url: 'https://api.seller.example/v1/search?q=alpha', method: 'GET' },
      response: { status: 200, headers: { 'payment-receipt': goodHeader } },
      body: JSON.stringify(goodPayload)
    },
    { ledger, expectedIssuerPublicKeys: [kp.publicKey] }
  );
  assert.equal(decReplay.action, 'VOID');
  assert.equal(decReplay.reasonCode, 'replayed_receipt');
  // Escrow hold was released — committedSessionAtomic stays 250_000n!
  assert.equal(ledger.snapshot(nowMs).committedSessionAtomic, 250_000n);

  // Cross-query substitution: fresh receipt signed for `?q=cheap` returned to buyer asking `?q=expensive` -> VOID (`request_binding_mismatch`)
  const { receiptHeader: wrongQueryHeader } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller API', keyId: kp.keyId, payTo: SELLER_PAY_TO },
    service: { name: 'Seller API', resource: 'https://api.seller.example/v1/search?q=cheap', method: 'GET' },
    request: { method: 'GET', resource: 'https://api.seller.example/v1/search?q=cheap', body: '' },
    payment: {
      scheme: 'auth-capture',
      network: 'eip155:8453',
      asset: 'USDC',
      amountAtomic: '250000',
      payTo: SELLER_PAY_TO,
      settlement: { status: 'verify_only', transactionHash: null }
    },
    output: goodPayload
  });
  const decWrongReq = await evaluateDeliveryArbiter(
    {
      origin: 'https://api.seller.example',
      challenge,
      request: { url: 'https://api.seller.example/v1/search?q=expensive', method: 'GET' },
      response: { status: 200, headers: { 'payment-receipt': wrongQueryHeader } },
      body: JSON.stringify(goodPayload)
    },
    { ledger, expectedIssuerPublicKeys: [kp.publicKey] }
  );
  assert.equal(decWrongReq.action, 'VOID');
  assert.equal(decWrongReq.reasonCode, 'request_binding_mismatch');

  // Signed bogus delivery (`{"results": [], "warning": "upstream_degraded"}`) -> VOID + nonRepudiable FraudEvidenceRecord!
  const bogusPayload = { results: [], warning: 'upstream_degraded' };
  const { receiptHeader: bogusHeader } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Seller API', keyId: kp.keyId, payTo: SELLER_PAY_TO },
    service: { name: 'Seller API', resource: 'https://api.seller.example/v1/search?q=beta', method: 'GET' },
    request: { method: 'GET', resource: 'https://api.seller.example/v1/search?q=beta', body: '' },
    payment: {
      scheme: 'auth-capture',
      network: 'eip155:8453',
      asset: 'USDC',
      amountAtomic: '250000',
      payTo: SELLER_PAY_TO,
      settlement: { status: 'verify_only', transactionHash: null }
    },
    output: bogusPayload
  });

  const decBogus = await evaluateDeliveryArbiter(
    {
      origin: 'https://api.seller.example',
      challenge,
      request: { url: 'https://api.seller.example/v1/search?q=beta', method: 'GET' },
      response: { status: 200, headers: { 'payment-receipt': bogusHeader } },
      body: JSON.stringify(bogusPayload)
    },
    {
      ledger,
      expectedIssuerPublicKeys: [kp.publicKey],
      validateContent: (body) => (Array.isArray(body.results) && body.results.length > 0)
        ? { ok: true }
        : { ok: false, reason: 'Empty results envelope' }
    }
  );
  assert.equal(decBogus.action, 'VOID');
  assert.equal(decBogus.reasonCode, 'content_rejected');
  assert.equal(decBogus.fraudEvidence.nonRepudiable, true);
  assert.equal(decBogus.fraudEvidence.issuerKeyId, kp.keyId);
  assert.equal(decBogus.fraudEvidence.issuerPublicKey, kp.publicKey);
});

test('createGuardedFetch: end-to-end 402 -> Gate 1 -> sign -> withPaxiomReceipt -> Gate 2 CAPTURE, irreversible exact budget conservation, and circuit breaker', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'edge-seller-01' });
  const ledger = createMemorySpendLedger();
  const captured = [];
  const voided = [];
  let signCalls = 0;
  let serveBogus = false;

  const sellerHandler = withPaxiomReceipt(
    async (req) => {
      const sig = req.headers.get('payment-signature');
      if (!sig) {
        const challenge = {
          accepts: [
            {
              scheme: 'auth-capture',
              network: 'eip155:8453',
              asset: 'USDC',
              amount: '100000',
              payTo: SELLER_PAY_TO,
              extra: {
                operator: TRUSTED_OPERATOR,
                minFeeBps: 0,
                maxFeeBps: 100,
                authorizationExpiry: Math.floor(Date.now() / 1000) + 900,
                paymentInfoHash: PAYMENT_INFO_HASH
              }
            }
          ]
        };
        return new Response(JSON.stringify(challenge), {
          status: 402,
          headers: {
            'content-type': 'application/json',
            'payment-required': encodeChallengeHeader(challenge)
          }
        });
      }
      const body = serveBogus ? { answer: null } : { answer: 42 };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    },
    {
      privateKey: kp.privateKeyPem,
      issuer: { name: 'Edge Compute', keyId: kp.keyId, payTo: SELLER_PAY_TO },
      paymentDefaults: {
        scheme: 'auth-capture',
        network: 'eip155:8453',
        asset: 'USDC',
        amountAtomic: '100000',
        payTo: SELLER_PAY_TO
      }
    }
  );

  const guardedFetch = createGuardedFetch({
    policy: {
      maxPerCallAtomic: 200_000n,
      maxSessionAtomic: 500_000n,
      maxUnescrowedExactAtomic: 10_000n,
      trustedOperators: [TRUSTED_OPERATOR],
      pinnedPayToByOrigin: { 'https://compute.example': SELLER_PAY_TO },
      maxConsecutiveFailures: 2,
      cooldownMs: 60_000
    },
    ledger,
    expectedIssuerPublicKeys: [kp.publicKey],
    validateContent: (body) => typeof body.answer === 'number',
    signPayment: async ({ challenge }) => {
      signCalls += 1;
      return Buffer.from(JSON.stringify({
        scheme: challenge.scheme,
        network: challenge.network,
        accepted: {
          scheme: challenge.scheme,
          network: challenge.network,
          amount: challenge.amountAtomicString,
          payTo: challenge.payTo
        }
      })).toString('base64');
    },
    fetchImpl: (url, init) => sellerHandler(new Request(url, init)),
    onCapture: (d) => captured.push(d),
    onVoid: (d) => voided.push(d)
  });

  // 1. Honest response -> CAPTURE
  const res1 = await guardedFetch('https://compute.example/v1/infer', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt: '6*7' })
  });
  assert.equal(res1.ok, true);
  assert.equal(res1.arbiter.action, 'CAPTURE');
  assert.deepEqual(res1.data, { answer: 42 });
  assert.equal(captured.length, 1);
  assert.equal(signCalls, 1);
  assert.equal(ledger.snapshot().committedSessionAtomic, 100_000n);

  // 2. Two consecutive bogus deliveries -> VOID + circuit breaker trips on 2nd failure!
  serveBogus = true;
  const res2 = await guardedFetch('https://compute.example/v1/infer', { method: 'POST', body: '{}' });
  const res3 = await guardedFetch('https://compute.example/v1/infer', { method: 'POST', body: '{}' });
  assert.equal(res2.ok, false);
  assert.equal(res2.arbiter.action, 'VOID');
  assert.equal(res3.ok, false);
  assert.equal(res3.arbiter.action, 'VOID');
  assert.equal(voided.length, 2);
  assert.equal(signCalls, 3);
  // Because scheme was auth-capture, the 2 voided holds were NOT charged against committedSessionAtomic!
  assert.equal(ledger.snapshot().committedSessionAtomic, 100_000n);

  // 3. 4th attempt is blocked BEFORE network or wallet signing by open circuit breaker!
  const res4 = await guardedFetch('https://compute.example/v1/infer', { method: 'POST', body: '{}' });
  assert.equal(res4.ok, false);
  assert.equal(res4.stage, 'pre_request');
  assert.equal(res4.preSign.code, 'circuit_breaker_open');
  assert.equal(signCalls, 3); // Zero additional wallet signatures!
});
