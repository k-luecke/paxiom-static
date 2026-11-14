import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../server.mjs';
import { NETWORK_CONFIGS } from '../onchain-settlement.mjs';
import { isPublicGlobalIp, validatePublicHttpsTarget } from '../x402-preflight.mjs';
import { generateReceiptKeyPair, decodeReceiptHeader } from '../../../standards/receipts/v0/src/issue.mjs';
import { verifyReceipt } from '../../../standards/receipts/v0/src/verify.mjs';

async function withServer(options, fn) {
  const srv = createServer(options);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => srv.close(r));
  }
}

test('SSRF IP & URL validator blocks all private, loopback, metadata, NAT64/6to4, and rebinding targets', async () => {
  const blockedIps = [
    '0.0.0.0',
    '127.0.0.1',
    '10.0.0.1',
    '100.64.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:169.254.169.254',
    '64:ff9b::169.254.169.254',
    '2002:7f00:0001::1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
    '2001:db8::1'
  ];
  for (const ip of blockedIps) {
    assert.equal(isPublicGlobalIp(ip), false, `expected ${ip} to be blocked`);
  }

  assert.equal(isPublicGlobalIp('93.184.216.34'), true);
  assert.equal(isPublicGlobalIp('2606:2800:220:1:248:1893:25c8:1946'), true);

  // Plaintext HTTP, credentials, non-443 ports, hex IPv4 loopback, and rebinding domains
  assert.equal((await validatePublicHttpsTarget('http://seller.example/v1/pay')).ok, false);
  assert.equal((await validatePublicHttpsTarget('https://user:secret@seller.example/v1/pay')).ok, false);
  assert.equal((await validatePublicHttpsTarget('https://seller.example:8443/v1/pay')).ok, false);
  assert.equal((await validatePublicHttpsTarget('https://0x7f000001/admin')).code, 'ssrf_blocked');
  assert.equal((await validatePublicHttpsTarget('https://169.254.169.254/latest/meta-data/')).code, 'ssrf_blocked');
  assert.equal((await validatePublicHttpsTarget('https://[::1]/')).code, 'ssrf_blocked');
  assert.equal((await validatePublicHttpsTarget('https://127.0.0.1.nip.io/v1')).code, 'ssrf_blocked');
  assert.equal((await validatePublicHttpsTarget('https://metadata/v1')).code, 'ssrf_blocked');

  // DNS multi-record poisoning (one public IP + one private RFC1918 IP -> blocked!)
  const mixedDns = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '10.0.0.9', family: 4 }
  ];
  const mixedRes = await validatePublicHttpsTarget('https://dual.seller.example/v1', { lookupImpl: mixedDns });
  assert.equal(mixedRes.ok, false);
  assert.equal(mixedRes.code, 'ssrf_blocked');
});

test('x402 discovery exposes $0.002 verify-live + $0.01 preflight, and SSRF targets never debit facilitator', async () => {
  let facilitatorHits = 0;
  const env = {
    RENDER: 'true',
    CDP_FACILITATOR_URL: 'https://facilitator.mock'
  };
  const publicDns = async (host) => {
    if (host === 'internal-rebind.example') return [{ address: '169.254.169.254', family: 4 }];
    return [{ address: '93.184.216.34', family: 4 }];
  };
  const mockFetch = async (url) => {
    if (url.startsWith('https://facilitator.mock')) {
      facilitatorHits++;
      return new Response(JSON.stringify({ isValid: true, success: true }), { status: 200 });
    }
    throw new Error(`Unexpected outbound fetch to ${url}`);
  };

  await withServer({ env, fetchImpl: mockFetch, lookupImpl: publicDns }, async (base) => {
    const disc = await fetch(`${base}/.well-known/x402.json`).then((r) => r.json());
    assert.equal(disc.accepts.length, 2);
    assert.equal(disc.accepts[0].maxAmountRequired, '2000');
    assert.equal(disc.accepts[1].maxAmountRequired, '10000');
    assert.match(disc.accepts[1].resource, /\/v1\/x402\/preflight$/);

    // Unpaid probe returns 402 quoting 10000 atomic ($0.01 USDC)
    const unpaid = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}'
    });
    assert.equal(unpaid.status, 402);
    const unpaidJson = await unpaid.json();
    assert.equal(unpaidJson.accepts[0].maxAmountRequired, '10000');

    // Paid call with SSRF / private DNS target returns 400 BEFORE calling facilitator /verify or /settle
    const paymentHeader = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact', payload: {} }), 'utf8').toString('base64');
    for (const badUrl of [
      'http://seller.example/v1/data',
      'https://127.0.0.1/v1/data',
      'https://169.254.169.254/latest/meta-data/',
      'https://internal-rebind.example/v1/data'
    ]) {
      const r = await fetch(`${base}/v1/x402/preflight`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
        body: JSON.stringify({ url: badUrl })
      });
      assert.equal(r.status, 400, `expected 400 for ${badUrl}`);
      assert.equal(facilitatorHits, 0, `must not touch facilitator for ${badUrl}`);
    }
  });
});

test('POST /v1/x402/preflight flags spoofed USDC, payTo bait-and-switch, and redirects; approves canonical Base USDC + signs X-Paxiom-Receipt', async () => {
  const paxiomKey = generateReceiptKeyPair({ keyId: 'paxiom-preflight-01' });
  const sellerKey = generateReceiptKeyPair({ keyId: 'good-seller-01' });
  const goodPayTo = '0x1111111111111111111111111111111111111111';
  const hijackedPayTo = '0x2222222222222222222222222222222222222222';
  const fakeUsdc = '0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead';

  const env = {
    LIVE_VERIFY_ENABLED: 'true',
    X402_ENABLED: 'true',
    X402_PAY_TO: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
    PAXIOM_API_KEYS: 'pax_preflight_key',
    PAXIOM_SIGNING_PRIVATE_KEY_PEM: paxiomKey.privateKeyPem,
    PAXIOM_SIGNING_KEY_ID: paxiomKey.keyId
  };

  const publicDns = async () => [{ address: '93.184.216.34', family: 4 }];

  const mockFetch = async (url) => {
    // 1. Good seller with canonical Base USDC + matching .well-known/x402.json + Paxiom keys
    if (url === 'https://good.seller.example/v1/alpha') {
      const challenge = {
        x402Version: 1,
        accepts: [{
          scheme: 'exact',
          network: 'base',
          maxAmountRequired: '5000',
          resource: 'https://good.seller.example/v1/alpha',
          payTo: goodPayTo,
          maxTimeoutSeconds: 60,
          asset: NETWORK_CONFIGS.base.usdcAddress,
          outputSchema: { input: { discoverable: true }, output: {} },
          extra: { name: 'USD Coin', version: '2' }
        }]
      };
      return new Response(JSON.stringify(challenge), {
        status: 402,
        headers: {
          'content-type': 'application/json',
          'payment-required': Buffer.from(JSON.stringify(challenge), 'utf8').toString('base64'),
          'access-control-expose-headers': 'PAYMENT-REQUIRED, X-Paxiom-Receipt'
        }
      });
    }
    if (url === 'https://good.seller.example/.well-known/x402.json') {
      return new Response(JSON.stringify({
        x402Version: 1,
        accepts: [{ resource: 'https://good.seller.example/v1/alpha', payTo: goodPayTo }]
      }), { status: 200 });
    }
    if (url === 'https://good.seller.example/.well-known/paxiom-keys.json') {
      return new Response(JSON.stringify({
        issuer: 'Good Seller',
        keys: [{ keyId: sellerKey.keyId, algorithm: 'ed25519', publicKey: sellerKey.publicKey }]
      }), { status: 200 });
    }

    // 2. Spoofed token + payTo bait-and-switch seller
    if (url === 'https://scam.seller.example/v1/trap') {
      return new Response(JSON.stringify({
        x402Version: 1,
        accepts: [{
          scheme: 'exact',
          network: 'base',
          maxAmountRequired: '5000',
          resource: 'https://scam.seller.example/v1/trap',
          payTo: hijackedPayTo,
          asset: fakeUsdc,
          extra: { name: 'Fake Coin', version: '2' }
        }]
      }), { status: 402 });
    }
    if (url === 'https://scam.seller.example/.well-known/x402.json') {
      return new Response(JSON.stringify({
        x402Version: 1,
        accepts: [{ resource: 'https://scam.seller.example/v1/trap', payTo: goodPayTo }]
      }), { status: 200 });
    }

    // 3. Redirecting seller (302 to internal host — must NOT be followed!)
    if (url === 'https://redirect.seller.example/v1/hop') {
      return new Response('', {
        status: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data/' }
      });
    }

    return new Response('not found', { status: 404 });
  };

  await withServer({ env, fetchImpl: mockFetch, lookupImpl: publicDns }, async (base) => {
    // A. Healthy canonical Base USDC seller -> verdict: "proceed", riskLevel: "low", signed X-Paxiom-Receipt!
    const okRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'pax_preflight_key' },
      body: JSON.stringify({
        url: 'https://good.seller.example/v1/alpha',
        maxBudgetAtomic: '10000',
        expectedNetwork: 'base'
      })
    });
    assert.equal(okRes.status, 200);
    const receiptHdr = okRes.headers.get('x-paxiom-receipt');
    assert.ok(receiptHdr, 'expected signed X-Paxiom-Receipt header');
    const okBody = await okRes.json();
    assert.equal(okBody.verdict, 'proceed');
    assert.equal(okBody.riskLevel, 'low');
    assert.equal(okBody.checks.canonicalUsdcAsset, 'pass');
    assert.equal(okBody.checks.eip712Domain, 'pass');
    assert.equal(okBody.checks.manifestConsistency, 'pass');
    assert.equal(okBody.checks.budgetCap, 'pass');
    assert.equal(okBody.checks.paxiomReceipts, 'ready');
    assert.equal(okBody.receiptSupport.paxiomWellKnownKeys, 1);

    // Verify X-Paxiom-Receipt binds the exact preflight report output offline!
    const decodedReceipt = decodeReceiptHeader(receiptHdr);
    const verified = verifyReceipt(decodedReceipt, { output: okBody });
    assert.equal(verified.valid, true);
    assert.equal(verified.trustState, 'verified');

    // B. Spoofed token + payTo hijack -> verdict: "block", riskLevel: "high"
    const scamRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'pax_preflight_key' },
      body: JSON.stringify({ url: 'https://scam.seller.example/v1/trap' })
    });
    assert.equal(scamRes.status, 200);
    const scamBody = await scamRes.json();
    assert.equal(scamBody.verdict, 'block');
    assert.equal(scamBody.riskLevel, 'high');
    const scamCodes = scamBody.findings.map((f) => f.code);
    assert.ok(scamCodes.includes('non_canonical_usdc_asset'));
    assert.ok(scamCodes.includes('eip712_domain_mismatch'));
    assert.ok(scamCodes.includes('payto_manifest_mismatch'));

    // C. Redirecting seller -> verdict: "block", redirect NOT followed
    const redirRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'pax_preflight_key' },
      body: JSON.stringify({ url: 'https://redirect.seller.example/v1/hop' })
    });
    assert.equal(redirRes.status, 200);
    const redirBody = await redirRes.json();
    assert.equal(redirBody.verdict, 'block');
    assert.equal(redirBody.findings[0].code, 'redirect_not_allowed');
  });
});
