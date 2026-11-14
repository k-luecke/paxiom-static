import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../server.mjs';
import { NETWORK_CONFIGS } from '../onchain-settlement.mjs';
import {
  isPublicGlobalIp,
  validatePublicHttpsTarget,
  buildPinnedHttpsRequestOptions
} from '../x402-preflight.mjs';
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
    '64:ff9b:1::1',
    '64:ff9b:1::93.184.216.34',
    '64:ff9b:0:1::93.184.216.34',
    '2002:7f00:0001::1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
    '2001::1',
    '2001:2::1',
    '2001:10::1',
    '2001:20::1',
    '2001:db8::1',
    '3fff::1',
    '3fff:100:8fe::1',
    '2620:4f:8000::1'
  ];
  for (const ip of blockedIps) {
    assert.equal(isPublicGlobalIp(ip), false, `expected ${ip} to be blocked`);
  }

  assert.equal(isPublicGlobalIp('93.184.216.34'), true);
  assert.equal(isPublicGlobalIp('64:ff9b::93.184.216.34'), true);
  assert.equal(isPublicGlobalIp('2001:4860:4860::8888'), true);
  assert.equal(isPublicGlobalIp('2606:2800:220:1:248:1893:25c8:1946'), true);

  // FERMI-PAX-R2-02: RFC 6066 TLS SNI omission for IP literals & RFC 3986 bracketed IPv6 Host header
  const domainOpts = buildPinnedHttpsRequestOptions(
    { hostname: 'good.seller.example', pinnedIp: '93.184.216.34', pinnedFamily: 4 },
    'https://good.seller.example/v1/pay',
    { method: 'POST', headers: { accept: 'application/json' }, body: '{}' }
  );
  assert.equal(domainOpts.servername, 'good.seller.example');
  assert.equal(domainOpts.headers.host, 'good.seller.example');

  const v4Opts = buildPinnedHttpsRequestOptions(
    { hostname: '93.184.216.34', pinnedIp: '93.184.216.34', pinnedFamily: 4 },
    'https://93.184.216.34/v1/pay',
    { method: 'GET', headers: {} }
  );
  assert.equal(Object.hasOwn(v4Opts, 'servername'), false);
  assert.equal(v4Opts.headers.host, '93.184.216.34');

  const v6Opts = buildPinnedHttpsRequestOptions(
    { hostname: '2606:2800:220:1:248:1893:25c8:1946', pinnedIp: '2606:2800:220:1:248:1893:25c8:1946', pinnedFamily: 6 },
    'https://[2606:2800:220:1:248:1893:25c8:1946]/v1/pay',
    { method: 'GET', headers: {} }
  );
  assert.equal(Object.hasOwn(v6Opts, 'servername'), false);
  assert.equal(v6Opts.headers.host, '[2606:2800:220:1:248:1893:25c8:1946]');

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

test('x402 discovery exposes $0.002 verify-live + $0.01 preflight, closes pre-verify DNS oracle, and never debits facilitator on SSRF targets', async () => {
  let verifyHits = 0;
  let settleHits = 0;
  let dnsHits = 0;
  let facilitatorVerifyValid = true;
  const env = {
    RENDER: 'true',
    CDP_FACILITATOR_URL: 'https://facilitator.mock'
  };
  const publicDns = async (host) => {
    dnsHits++;
    if (host === 'internal-rebind.example') return [{ address: '169.254.169.254', family: 4 }];
    return [{ address: '93.184.216.34', family: 4 }];
  };
  const mockFetch = async (url) => {
    if (url === 'https://facilitator.mock/verify') {
      verifyHits++;
      return new Response(JSON.stringify({ isValid: facilitatorVerifyValid, invalidReason: facilitatorVerifyValid ? undefined : 'bad_sig' }), { status: 200 });
    }
    if (url === 'https://facilitator.mock/settle') {
      settleHits++;
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    }
    throw new Error(`Unexpected outbound fetch to ${url}`);
  };

  await withServer({ env, fetchImpl: mockFetch, lookupImpl: publicDns }, async (base) => {
    const disc = await fetch(`${base}/.well-known/x402.json`).then((r) => r.json());
    assert.equal(disc.accepts.length, 2);
    assert.equal(disc.accepts[0].maxAmountRequired, '2000');
    assert.equal(disc.accepts[1].maxAmountRequired, '10000');
    assert.match(disc.accepts[1].resource, /\/v1\/x402\/preflight$/);

    // Unpaid probe returns 402 quoting 10000 atomic ($0.01 USDC) with 0 DNS lookups
    const unpaid = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}'
    });
    assert.equal(unpaid.status, 402);
    assert.equal(dnsHits, 0);
    const unpaidJson = await unpaid.json();
    assert.equal(unpaidJson.accepts[0].maxAmountRequired, '10000');

    // FERMI-PAX-R2-01: Dummy X-PAYMENT header is rejected 400 BEFORE dns.lookup or facilitator /verify
    const dummyHdrRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-payment': 'dummy' },
      body: JSON.stringify({ url: 'https://internal-rebind.example/v1/data' })
    });
    assert.equal(dummyHdrRes.status, 400);
    assert.equal((await dummyHdrRes.json()).error.code, 'invalid_payment_header');
    assert.equal(dnsHits, 0, 'dummy X-PAYMENT must not trigger dns.lookup');
    assert.equal(verifyHits, 0);
    assert.equal(settleHits, 0);

    const paymentHeader = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact', payload: {} }), 'utf8').toString('base64');

    // FERMI-PAX-R2-01: Forged payment header failing facilitator /verify returns 402 BEFORE dns.lookup
    facilitatorVerifyValid = false;
    const invalidSigRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ url: 'https://internal-rebind.example/v1/data' })
    });
    assert.equal(invalidSigRes.status, 402);
    assert.equal(verifyHits, 1);
    assert.equal(dnsHits, 0, 'unverified payment must not trigger dns.lookup');
    assert.equal(settleHits, 0);

    // Lexical SSRF targets return 400 offline BEFORE touching facilitator /verify, /settle, or DNS
    facilitatorVerifyValid = true;
    verifyHits = 0;
    for (const lexicalBadUrl of [
      'http://seller.example/v1/data',
      'https://127.0.0.1/v1/data',
      'https://169.254.169.254/latest/meta-data/',
      'https://[3fff:100:8fe::1]/v1/data'
    ]) {
      const r = await fetch(`${base}/v1/x402/preflight`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
        body: JSON.stringify({ url: lexicalBadUrl })
      });
      assert.equal(r.status, 400, `expected 400 for ${lexicalBadUrl}`);
      assert.equal(verifyHits, 0, `must not call /verify for lexical SSRF ${lexicalBadUrl}`);
      assert.equal(settleHits, 0, `must not debit /settle for ${lexicalBadUrl}`);
      assert.equal(dnsHits, 0, `must not call DNS for ${lexicalBadUrl}`);
    }

    // Verified payment with private-DNS rebinding target runs /verify -> DNS -> 400 WITHOUT calling /settle!
    const rebindRes = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ url: 'https://internal-rebind.example/v1/data' })
    });
    assert.equal(rebindRes.status, 400);
    assert.equal(verifyHits, 1);
    assert.equal(dnsHits, 1);
    assert.equal(settleHits, 0, 'must NEVER call /settle when DNS resolves to private/metadata IP');
  });

  // FERMI-PAX-R2-03: Self-hosted localhost free_unmetered blocks cross-origin browser Origin headers (403)
  let freeDnsHits = 0;
  await withServer({
    env: { LIVE_VERIFY_ENABLED: 'true' },
    lookupImpl: async () => {
      freeDnsHits++;
      return [{ address: '93.184.216.34', family: 4 }];
    }
  }, async (base) => {
    const csrfPreflight = await fetch(`${base}/v1/x402/preflight`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ url: 'https://good.seller.example/v1/alpha' })
    });
    assert.equal(csrfPreflight.status, 403);
    assert.equal((await csrfPreflight.json()).error.code, 'cross_origin_unmetered_blocked');
    assert.equal(freeDnsHits, 0);
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
