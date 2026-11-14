import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../server.mjs';
import { ERC20_TRANSFER_TOPIC0, NETWORK_CONFIGS } from '../onchain-settlement.mjs';
import { generateReceiptKeyPair, issueReceipt } from '../../../standards/receipts/v0/src/issue.mjs';
import { verifyReceipt } from '../../../standards/receipts/v0/src/verify.mjs';

function padAddressTopic(addr) {
  return '0x' + addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

function padUint256Hex(num) {
  return '0x' + BigInt(num).toString(16).padStart(64, '0');
}

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

test('default preview mode keeps verify-live disabled (503) and x402 discovery off (404)', async () => {
  await withServer({ env: {} }, async (base) => {
    const r1 = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt: {} })
    });
    assert.equal(r1.status, 503);
    const b1 = await r1.json();
    assert.equal(b1.error.code, 'live_verify_disabled');

    const r2 = await fetch(`${base}/.well-known/x402.json`);
    assert.equal(r2.status, 404);
  });
});

test('SaaS API key + live Base USDC settlement check upgrades claimed receipt to verified + counter-attests', async () => {
  const sellerKey = generateReceiptKeyPair({ keyId: 'seller-live-01' });
  const paxiomKey = generateReceiptKeyPair({ keyId: 'paxiom-live-verifier-001' });
  const sellerPayTo = '0x1111111111111111111111111111111111111111';
  const buyerAddr = '0x2222222222222222222222222222222222222222';
  const txHash = '0x' + 'aa'.repeat(32);
  const output = { weather: 'sunny', tempF: 72 };

  const { receipt: claimedReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Weather Seller', uri: 'https://weather.example', keyId: sellerKey.keyId },
    service: { name: 'Weather API', resource: 'https://weather.example/v1/now', method: 'POST' },
    payment: {
      scheme: 'x402',
      network: 'base',
      asset: 'USDC',
      amountAtomic: '5000',
      amountDisplay: '0.005',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  const env = {
    LIVE_VERIFY_ENABLED: 'true',
    X402_ENABLED: 'true',
    X402_PAY_TO: '0x9999999999999999999999999999999999999999',
    PAXIOM_API_KEYS: 'pax_live_secret_key_123',
    BASE_RPC_URL: 'https://rpc.base.mock',
    PAXIOM_SIGNING_PRIVATE_KEY_PEM: paxiomKey.privateKeyPem,
    PAXIOM_SIGNING_KEY_ID: paxiomKey.keyId
  };

  const mockFetch = async (url, init) => {
    assert.equal(url, 'https://rpc.base.mock');
    const req = JSON.parse(init.body);
    if (req.method === 'eth_blockNumber') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x1005' }), { status: 200 });
    }
    if (req.method === 'eth_getTransactionReceipt') {
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          status: '0x1',
          blockNumber: '0x1000',
          logs: [
            {
              address: NETWORK_CONFIGS.base.usdcAddress,
              topics: [ERC20_TRANSFER_TOPIC0, padAddressTopic(buyerAddr), padAddressTopic(sellerPayTo)],
              data: padUint256Hex(5000)
            }
          ]
        }
      }), { status: 200 });
    }
    throw new Error(`Unexpected RPC method ${req.method}`);
  };

  await withServer({ env, fetchImpl: mockFetch }, async (base) => {
    // 1. Unpaid / unauthenticated call receives 402 with PAYMENT-REQUIRED + Bazaar outputSchema
    const unpaid = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt: claimedReceipt, output })
    });
    assert.equal(unpaid.status, 402);
    assert.ok(unpaid.headers.get('payment-required'));
    const unpaidBody = await unpaid.json();
    assert.ok(unpaidBody.accepts[0].outputSchema);

    // 2. Valid SaaS X-API-Key bypasses x402, checks Base RPC, and returns verified + counterAttestedReceipt
    const paidApi = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': 'pax_live_secret_key_123'
      },
      body: JSON.stringify({ receipt: claimedReceipt, output, expectedPayTo: sellerPayTo })
    });
    assert.equal(paidApi.status, 200);
    assert.ok(paidApi.headers.get('x-paxiom-receipt'));
    const body = await paidApi.json();
    assert.equal(body.valid, true);
    assert.equal(body.trustState, 'verified');
    assert.equal(body.checks.settlement, 'verified_settled');
    assert.equal(body.onchainSettlement.settled, true);
    assert.ok(body.counterAttestedReceipt);

    // 3. Downstream agent fetches /.well-known/paxiom-keys.json and verifies counterAttestedReceipt 100% offline!
    const keysRes = await fetch(`${base}/.well-known/paxiom-keys.json`);
    const keysJson = await keysRes.json();
    assert.equal(keysJson.keys.length, 1);

    const offlineCounterCheck = verifyReceipt(body.counterAttestedReceipt, {
      output,
      trustedPaxiomPublicKeys: keysJson.keys.map((k) => k.publicKey)
    });
    assert.equal(offlineCounterCheck.trustState, 'verified');
    assert.equal(offlineCounterCheck.valid, true);
  });
});

test('x402 facilitator verify -> settle -> serve flow + never charges malformed JSON', async () => {
  const sellerKey = generateReceiptKeyPair({ keyId: 'seller-x402-01' });
  const txHash = '0x' + 'bb'.repeat(32);
  const output = { ok: true };
  const { receipt: claimedReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKey.keyId },
    service: { name: 'Seller', resource: 'https://s.example/api', method: 'POST' },
    payment: {
      network: 'base-sepolia',
      asset: 'USDC',
      amountAtomic: '1000',
      amountDisplay: '0.001',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  let facilitatorCalls = 0;
  const env = {
    X402_ENABLED: 'true',
    X402_NETWORK: 'base-sepolia',
    X402_PAY_TO: '0x9999999999999999999999999999999999999999',
    CDP_FACILITATOR_URL: 'https://facilitator.mock',
    BASE_SEPOLIA_RPC_URL: 'https://sepolia.base.mock'
  };

  const mockFetch = async (url, init) => {
    if (url === 'https://facilitator.mock/verify') {
      facilitatorCalls++;
      return new Response(JSON.stringify({ isValid: true }), { status: 200 });
    }
    if (url === 'https://facilitator.mock/settle') {
      facilitatorCalls++;
      return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ff'.repeat(32), network: 'base-sepolia' }), { status: 200 });
    }
    if (url === 'https://sepolia.base.mock') {
      const req = JSON.parse(init.body);
      if (req.method === 'eth_blockNumber') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x20' }), { status: 200 });
      }
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          status: '0x1',
          blockNumber: '0x1f',
          logs: [
            {
              address: NETWORK_CONFIGS['base-sepolia'].usdcAddress,
              topics: [
                ERC20_TRANSFER_TOPIC0,
                padAddressTopic('0x3333333333333333333333333333333333333333'),
                padAddressTopic('0x4444444444444444444444444444444444444444')
              ],
              data: padUint256Hex(1000)
            }
          ]
        }
      }), { status: 200 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };

  await withServer({ env, fetchImpl: mockFetch }, async (base) => {
    const paymentHeader = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact', payload: { sig: '0x123' } }), 'utf8').toString('base64');

    // Malformed body returns 400 BEFORE touching facilitator
    const badReq = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: '{bad json'
    });
    assert.equal(badReq.status, 400);
    assert.equal(facilitatorCalls, 0);

    // Valid x402 paid request runs /verify -> /settle -> RPC check -> 200 + PAYMENT-RESPONSE
    const goodReq = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: claimedReceipt, output })
    });
    assert.equal(goodReq.status, 200);
    assert.equal(facilitatorCalls, 2);
    assert.ok(goodReq.headers.get('payment-response'));
    const body = await goodReq.json();
    assert.equal(body.trustState, 'verified');
    assert.equal(body.valid, true);
  });
});

test('RENDER=true auto-enables live x402 discovery, capabilities, and unpaid 402 probe response', async (t) => {
  const srv = createServer({ env: { RENDER: 'true' } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  const { port } = srv.address();
  const base = `http://127.0.0.1:${port}`;

  const ver = await fetch(`${base}/version`).then((r) => r.json());
  assert.equal(ver.x402Enabled, true);
  assert.equal(ver.capabilities.liveSettlementVerification, true);

  const discRes = await fetch(`${base}/.well-known/x402.json`);
  assert.equal(discRes.status, 200);
  const disc = await discRes.json();
  assert.equal(disc.accepts[0].payTo, '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4');
  assert.equal(disc.accepts[0].outputSchema.input.discoverable, true);

  const probe = await fetch(`${base}/v1/receipt/verify-live`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  });
  assert.equal(probe.status, 402);
  assert.ok(probe.headers.get('payment-required'));
});

test('comma-separated BASE_RPC_URL automatically fails over when primary RPC rate-limits (-32011)', async () => {
  const sellerKey = generateReceiptKeyPair({ keyId: 'seller-failover-01' });
  const txHash = '0x' + 'cc'.repeat(32);
  const output = { failover: true };
  const { receipt: claimedReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKey.keyId },
    service: { name: 'Seller', resource: 'https://s.example/api', method: 'POST' },
    payment: {
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  const env = {
    LIVE_VERIFY_ENABLED: 'true',
    PAXIOM_API_KEYS: 'pax_key_failover',
    BASE_RPC_URL: 'https://rate-limited.base.mock, https://healthy.base.mock'
  };

  let rateLimitedHits = 0;
  let healthyHits = 0;
  const mockFetch = async (url, init) => {
    if (url === 'https://rate-limited.base.mock') {
      rateLimitedHits++;
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        error: { code: -32011, message: 'request limit reached' }
      }), { status: 200 });
    }
    if (url === 'https://healthy.base.mock') {
      healthyHits++;
      const req = JSON.parse(init.body);
      if (req.method === 'eth_blockNumber') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x105' }), { status: 200 });
      }
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          status: '0x1',
          blockNumber: '0x100',
          logs: [
            {
              address: NETWORK_CONFIGS.base.usdcAddress,
              topics: [
                ERC20_TRANSFER_TOPIC0,
                padAddressTopic('0x1111111111111111111111111111111111111111'),
                padAddressTopic('0x2222222222222222222222222222222222222222')
              ],
              data: padUint256Hex(2000)
            }
          ]
        }
      }), { status: 200 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };

  await withServer({ env, fetchImpl: mockFetch }, async (base) => {
    const res = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'pax_key_failover' },
      body: JSON.stringify({ receipt: claimedReceipt, output })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, true);
    assert.equal(body.trustState, 'verified');
    assert.ok(rateLimitedHits >= 2);
    assert.equal(healthyHits, 2);
  });
});

test('FERMI-PAX-01 & FERMI-PAX-02: never settles x402 payment for prototype network keys or ineligible receipts, and requires expectedPayTo + provenance URI for counter-attestation', async () => {
  const sellerKey = generateReceiptKeyPair({ keyId: 'seller-fermi-01' });
  const paxiomKey = generateReceiptKeyPair({ keyId: 'paxiom-fermi-root-01' });
  const sellerPayTo = '0x1111111111111111111111111111111111111111';
  const buyerAddr = '0x2222222222222222222222222222222222222222';
  const txHash = '0x' + 'dd'.repeat(32);
  const output = { ok: true };

  // Receipt with payment.network = "constructor" (Object.prototype key)
  const { receipt: protoNetReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKey.keyId },
    service: { name: 'API', resource: 'https://s.example/api', method: 'POST' },
    payment: {
      network: 'constructor',
      asset: 'USDC',
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  const { receipt: validClaimedReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Seller', uri: 'https://s.example', keyId: sellerKey.keyId },
    service: { name: 'API', resource: 'https://s.example/api', method: 'POST' },
    payment: {
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  let facilitatorHits = 0;
  const env = {
    LIVE_VERIFY_ENABLED: 'true',
    X402_ENABLED: 'true',
    X402_PAY_TO: '0x9999999999999999999999999999999999999999',
    CDP_FACILITATOR_URL: 'https://facilitator.mock',
    BASE_RPC_URL: 'https://rpc.base.mock',
    PAXIOM_SIGNING_PRIVATE_KEY_PEM: paxiomKey.privateKeyPem,
    PAXIOM_SIGNING_KEY_ID: paxiomKey.keyId
  };

  const mockFetch = async (url, init) => {
    if (url === 'https://facilitator.mock/verify') {
      facilitatorHits++;
      return new Response(JSON.stringify({ isValid: true }), { status: 200 });
    }
    if (url === 'https://facilitator.mock/settle') {
      facilitatorHits++;
      return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ee'.repeat(32), network: 'base' }), { status: 200 });
    }
    if (url === 'https://rpc.base.mock') {
      const req = JSON.parse(init.body);
      if (req.method === 'eth_blockNumber') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x200' }), { status: 200 });
      }
      return new Response(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          status: '0x1',
          blockNumber: '0x1ff',
          logs: [
            {
              address: NETWORK_CONFIGS.base.usdcAddress,
              topics: [ERC20_TRANSFER_TOPIC0, padAddressTopic(buyerAddr), padAddressTopic(sellerPayTo)],
              data: padUint256Hex(2000)
            }
          ]
        }
      }), { status: 200 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };

  const paymentHeader = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact', payload: {} }), 'utf8').toString('base64');

  await withServer({ env, fetchImpl: mockFetch }, async (base) => {
    // 1. Prototype network "constructor" returns clean unsupported_network BEFORE charging x402 facilitator!
    const rProto = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: protoNetReceipt, output, expectedPayTo: sellerPayTo })
    });
    assert.equal(rProto.status, 200);
    assert.equal(facilitatorHits, 0, 'must not settle caller x402 payment for unsupported network');
    const bProto = await rProto.json();
    assert.equal(bProto.onchainSettlement.reason, 'unsupported_network');

    // 2. Invalid expectedPayTo format is rejected 400 BEFORE charging x402 facilitator!
    const rBadAddr = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: validClaimedReceipt, output, expectedPayTo: 'not-an-evm-address' })
    });
    assert.equal(rBadAddr.status, 400);
    assert.equal(facilitatorHits, 0);

    // 3. Omitting expectedPayTo verifies RPC JSON but refuses to mint portable root counterAttestedReceipt
    const rNoPayTo = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: validClaimedReceipt, output })
    });
    assert.equal(rNoPayTo.status, 200);
    assert.equal(facilitatorHits, 2);
    const bNoPayTo = await rNoPayTo.json();
    assert.equal(bNoPayTo.onchainSettlement.recipientChecked, false);
    assert.equal(bNoPayTo.counterAttestedReceipt, undefined);
    assert.equal(bNoPayTo.counterAttestationSkippedReason, 'expectedPayTo_required_for_counter_attestation');

    // 4. Supplying matching expectedPayTo mints counterAttestedReceipt binding from, to, and original seller publicKey!
    const rWithPayTo = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: validClaimedReceipt, output, expectedPayTo: sellerPayTo })
    });
    assert.equal(rWithPayTo.status, 200);
    const bWithPayTo = await rWithPayTo.json();
    assert.ok(bWithPayTo.counterAttestedReceipt);
    const evUri = bWithPayTo.counterAttestedReceipt.payload.evidence[0].uri;
    assert.match(evUri, /^urn:paxiom:settlement-attestation:v0:eip155:8453:/);
    assert.ok(evUri.includes(`to=${sellerPayTo.toLowerCase()}`));
    assert.ok(evUri.includes(`origPubKey=${encodeURIComponent(sellerKey.publicKey)}`));

    // 5. Re-submitting an already counter-attested receipt does not re-wrap or charge facilitator
    facilitatorHits = 0;
    const rRewrap = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: bWithPayTo.counterAttestedReceipt, output, expectedPayTo: sellerPayTo })
    });
    assert.equal(rRewrap.status, 200);
    assert.equal(facilitatorHits, 0);
    const bRewrap = await rRewrap.json();
    assert.equal(bRewrap.counterAttestedReceipt, undefined);
  });
});

test('FERMI-PAX-06: pending RPC receipt (blockNumber: null) returns structured tx_pending (no 502 BigInt crash) and facilitator timeout aborts cleanly', async () => {
  const sellerKey = generateReceiptKeyPair({ keyId: 'seller-pending-01' });
  const txHash = '0x' + '99'.repeat(32);
  const output = { ok: true };
  const { receipt: claimedReceipt } = issueReceipt({
    privateKey: sellerKey.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKey.keyId },
    service: { name: 'API', resource: 'https://s.example/api', method: 'POST' },
    payment: {
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'claimed_not_checked', transactionHash: txHash, checkedByPaxiom: false }
    },
    output
  });

  const envPending = {
    LIVE_VERIFY_ENABLED: 'true',
    PAXIOM_API_KEYS: 'pax_pending_key',
    BASE_RPC_URL: 'https://rpc.pending.mock'
  };

  const mockPendingRpc = async (_url, init) => {
    const req = JSON.parse(init.body);
    if (req.method === 'eth_blockNumber') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x100' }), { status: 200 });
    }
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { status: null, blockNumber: null, logs: [] }
    }), { status: 200 });
  };

  await withServer({ env: envPending, fetchImpl: mockPendingRpc }, async (base) => {
    const res = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'pax_pending_key' },
      body: JSON.stringify({ receipt: claimedReceipt, output })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, false);
    assert.equal(body.trustState, 'settlement_failed');
    assert.equal(body.onchainSettlement.reason, 'tx_pending');
  });

  // Stalled facilitator aborts cleanly via FACILITATOR_VERIFY_TIMEOUT_MS -> 502 payment_gate_error
  const envTimeout = {
    X402_ENABLED: 'true',
    X402_PAY_TO: '0x9999999999999999999999999999999999999999',
    CDP_FACILITATOR_URL: 'https://stalled.facilitator.mock',
    FACILITATOR_VERIFY_TIMEOUT_MS: '40',
    BASE_RPC_URL: 'https://rpc.pending.mock'
  };
  const stalledFetch = (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('Aborted')));
  });
  const paymentHeader = Buffer.from(JSON.stringify({ x402Version: 1 }), 'utf8').toString('base64');

  await withServer({ env: envTimeout, fetchImpl: stalledFetch }, async (base) => {
    const res = await fetch(`${base}/v1/receipt/verify-live`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': paymentHeader },
      body: JSON.stringify({ receipt: claimedReceipt, output })
    });
    assert.equal(res.status, 502);
    const body = await res.json();
    assert.equal(body.error.code, 'payment_gate_error');
  });
});
