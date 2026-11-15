import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  STANDARD_RECEIPT_HEADER_NAME,
  RECEIPT_HEADER_NAME,
  generateReceiptKeyPair,
  issueReceipt,
  verifyReceipt,
  withPaxiomReceipt,
  createReceiptMiddleware,
  parseX402Headers,
  verifyResponseReceipt,
  discoverIssuerKeys
} from '../src/index.mjs';
import { handleJsonRpcMessage } from '../mcp/server.mjs';

test('v0.2.0 signer authorization enforces expectedIssuerPublicKeys and expectedPayTo (EVM & Solana)', () => {
  const sellerKp = generateReceiptKeyPair({ keyId: 'seller-01' });
  const attackerKp = generateReceiptKeyPair({ keyId: 'attacker-01' });
  const evmPayTo = '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4';
  const solPayTo = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';

  const { receipt } = issueReceipt({
    privateKey: sellerKp.privateKeyPem,
    issuer: { name: 'Seller', keyId: sellerKp.keyId, payTo: evmPayTo },
    service: { name: 'Inference', resource: 'https://seller.example/v1/infer', method: 'POST' },
    payment: { payTo: evmPayTo },
    output: { answer: 42 }
  });

  // Unpinned -> verified with issuerAuthorization = 'unpinned'
  const unpinned = verifyReceipt(receipt, { output: { answer: 42 } });
  assert.equal(unpinned.valid, true);
  assert.equal(unpinned.checks.issuerAuthorization, 'unpinned');

  // Matching key + case-insensitive EVM payTo -> verified with issuerAuthorization = 'pass'
  const pinnedOk = verifyReceipt(receipt, {
    output: { answer: 42 },
    expectedIssuerPublicKeys: [sellerKp.publicKey],
    expectedPayTo: evmPayTo.toLowerCase()
  });
  assert.equal(pinnedOk.valid, true);
  assert.equal(pinnedOk.trustState, 'verified');
  assert.equal(pinnedOk.checks.issuerAuthorization, 'pass');

  // Spoofed key -> unauthorized_issuer
  const wrongKey = verifyReceipt(receipt, {
    output: { answer: 42 },
    expectedIssuerPublicKeys: [attackerKp.publicKey]
  });
  assert.equal(wrongKey.valid, false);
  assert.equal(wrongKey.trustState, 'unauthorized_issuer');
  assert.equal(wrongKey.checks.issuerAuthorization, 'fail');

  // Wrong payTo -> unauthorized_issuer
  const wrongPayTo = verifyReceipt(receipt, {
    output: { answer: 42 },
    expectedPayTo: '0x1111111111111111111111111111111111111111'
  });
  assert.equal(wrongPayTo.valid, false);
  assert.equal(wrongPayTo.trustState, 'unauthorized_issuer');

  // Solana base58 payTo is case-sensitive
  const solIssued = issueReceipt({
    privateKey: sellerKp.privateKeyPem,
    issuer: { name: 'SolSeller', keyId: sellerKp.keyId, payTo: solPayTo },
    service: { name: 'SolAPI', resource: 'https://sol.example/v1/infer', method: 'POST' },
    payment: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', payTo: solPayTo },
    output: { slot: 123 }
  });
  assert.equal(
    verifyReceipt(solIssued.receipt, { output: { slot: 123 }, expectedPayTo: solPayTo }).trustState,
    'verified'
  );
  assert.equal(
    verifyReceipt(solIssued.receipt, { output: { slot: 123 }, expectedPayTo: solPayTo.toLowerCase() }).trustState,
    'unauthorized_issuer'
  );
});

test('v0.2.0 discoverIssuerKeys resolves /.well-known/x402-keys.json with fallback to paxiom-keys.json', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'disc-01' });

  // Primary /.well-known/x402-keys.json
  const resPrimary = await discoverIssuerKeys('https://seller.example/v1/resource', {
    fetchImpl: async (url) => {
      assert.equal(url, 'https://seller.example/.well-known/x402-keys.json');
      return new Response(JSON.stringify({
        keys: [{ keyId: kp.keyId, algorithm: 'ed25519', publicKey: kp.publicKey }]
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  assert.equal(resPrimary.ok, true);
  assert.deepEqual(resPrimary.publicKeys, [kp.publicKey]);

  // Fallback to /.well-known/paxiom-keys.json on 404
  const seen = [];
  const resFallback = await discoverIssuerKeys('https://legacy.example/api', {
    fetchImpl: async (url) => {
      seen.push(url);
      if (url.endsWith('/x402-keys.json')) return new Response('not found', { status: 404 });
      return new Response(JSON.stringify({
        keys: [{ keyId: kp.keyId, algorithm: 'ed25519', publicKey: kp.publicKey }]
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  assert.equal(resFallback.ok, true);
  assert.equal(seen.length, 2);
  assert.deepEqual(resFallback.publicKeys, [kp.publicKey]);
});

test('v0.2.0 raw-sha256 signs Markdown & binary responses and emits dual Payment-Receipt + X-Paxiom-Receipt headers', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'raw-01' });
  const mdText = '# Paid Report\n\nDeterministic raw-sha256 body.\n';

  const wrapped = withPaxiomReceipt(
    async () => new Response(mdText, {
      status: 201,
      headers: { 'content-type': 'text/markdown; charset=utf-8' }
    }),
    {
      privateKey: kp.privateKeyPem,
      issuer: { name: 'MarkdownSeller', keyId: kp.keyId, payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4' }
    }
  );

  const resp = await wrapped(new Request('https://seller.example/v1/report', {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: 'generate report'
  }));

  assert.equal(resp.status, 201);
  const stdHdr = resp.headers.get(STANDARD_RECEIPT_HEADER_NAME);
  const legHdr = resp.headers.get(RECEIPT_HEADER_NAME);
  assert.ok(stdHdr);
  assert.equal(stdHdr, legHdr);

  const checkOk = verifyResponseReceipt(resp, {
    output: mdText,
    expectedIssuerPublicKeys: [kp.publicKey],
    expectedPayTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4'
  });
  assert.equal(checkOk.valid, true);
  assert.equal(checkOk.receipt.payload.delivery.canonicalization, 'raw-sha256');
  assert.equal(checkOk.receipt.payload.delivery.statusCode, 201);
  assert.equal(checkOk.receipt.payload.delivery.mimeType, 'text/markdown');

  // Tampered single byte fails output_hash_mismatch
  const checkTampered = verifyResponseReceipt(resp, { output: mdText + ' ' });
  assert.equal(checkTampered.valid, false);
  assert.equal(checkTampered.trustState, 'output_hash_mismatch');

  // Header smuggling: differing Payment-Receipt and X-Paxiom-Receipt MUST reject
  const smuggledHeaders = new Headers({
    'payment-receipt': stdHdr,
    'x-paxiom-receipt': stdHdr.slice(0, -2) + 'AA'
  });
  const smuggled = verifyResponseReceipt({ headers: smuggledHeaders }, { output: mdText });
  assert.equal(smuggled.valid, false);
  assert.equal(smuggled.trustState, 'malformed_header');
});

test('v0.2.0 parseX402Headers and createReceiptMiddleware bind CAIP-2 EVM & Solana base58 transactions', async () => {
  const solSig = '5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW';
  const paymentSigObj = {
    x402Version: 2,
    accepted: {
      scheme: 'exact',
      network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
      asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      amount: '25000',
      payTo: '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin'
    },
    payload: { signature: 'demo' }
  };
  const settleRespObj = {
    success: true,
    transaction: solSig,
    network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    payer: '4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T'
  };
  const b64PaySig = Buffer.from(JSON.stringify(paymentSigObj), 'utf8').toString('base64');
  const b64Settle = Buffer.from(JSON.stringify(settleRespObj), 'utf8').toString('base64');

  const parsed = parseX402Headers(
    { 'payment-signature': b64PaySig },
    { 'payment-response': b64Settle }
  );
  assert.equal(parsed.network, 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
  assert.equal(parsed.amountAtomic, '25000');
  assert.equal(parsed.amountDisplay, '0.025');
  assert.equal(parsed.txHash, solSig);
  assert.equal(parsed.payTo, '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin');
  assert.equal(parsed.payer, '4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T');

  // Verify Node HTTP middleware emits Payment-Receipt with binary PNG payload & Solana tx
  const kp = generateReceiptKeyPair({ keyId: 'sol-mw-01' });
  const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const mw = createReceiptMiddleware({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'SolanaBinarySeller', keyId: kp.keyId }
  });

  const server = http.createServer((req, res) => {
    mw(req, res, () => {
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Payment-Response', b64Settle);
      res.statusCode = 200;
      res.end(pngBytes);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/chart.png`, {
      method: 'GET',
      headers: { 'Payment-Signature': b64PaySig }
    });
    const outBytes = new Uint8Array(await res.arrayBuffer());
    const v = verifyResponseReceipt(res, {
      output: outBytes,
      expectedIssuerPublicKeys: [kp.publicKey],
      expectedPayTo: '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin'
    });
    assert.equal(v.trustState, 'settlement_claimed_not_checked');
    assert.equal(v.checks.outputHash, 'pass');
    assert.equal(v.checks.issuerAuthorization, 'pass');
    assert.equal(v.receipt.payload.payment.settlement.transactionHash, solSig);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('v0.2.0 vendor-neutral checkedByVerifier + trustedVerifierPublicKeys and MCP v0.2.0 args', () => {
  const verifierKp = generateReceiptKeyPair({ keyId: 'verifier-root-01' });
  const { receipt } = issueReceipt({
    privateKey: verifierKp.privateKeyPem,
    issuer: { name: 'Reference Verifier', keyId: verifierKp.keyId },
    service: { name: 'CounterAttest', resource: 'https://seller.example/v1/infer', method: 'POST' },
    payment: {
      settlement: {
        status: 'verified_settled',
        transactionHash: '0x' + 'ab'.repeat(32),
        checkedByVerifier: true,
        verifier: 'https://api.paxiom.org'
      }
    },
    output: { ok: true }
  });
  assert.equal(Object.hasOwn(receipt.payload.payment.settlement, 'checkedByPaxiom'), false);
  assert.equal(receipt.payload.payment.settlement.checkedByVerifier, true);

  const untrusted = verifyReceipt(receipt, { output: { ok: true } });
  assert.equal(untrusted.trustState, 'settlement_claimed_not_checked');

  const trusted = verifyReceipt(receipt, {
    output: { ok: true },
    trustedVerifierPublicKeys: [verifierKp.publicKey]
  });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.trustState, 'verified');

  // MCP verify_receipt supports expectedIssuerPublicKeys -> unauthorized_issuer
  const mcpResp = handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 77,
    method: 'tools/call',
    params: {
      name: 'verify_receipt',
      arguments: {
        receipt,
        output: { ok: true },
        expectedIssuerPublicKeys: [generateReceiptKeyPair().publicKey]
      }
    }
  });
  assert.equal(mcpResp.result.isError, false);
  assert.equal(mcpResp.result.structuredContent.trustState, 'unauthorized_issuer');
});

test('v0.2.0 discoverIssuerKeys resolves W3C did:web (/.well-known/did.json) OKP Ed25519 keys', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'did-seller-01' });
  const xB64Url = Buffer.from(kp.publicKey, 'base64').toString('base64url');
  const didDoc = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: 'did:web:seller.example',
    verificationMethod: [
      {
        id: 'did:web:seller.example#did-seller-01',
        type: 'JsonWebKey2020',
        controller: 'did:web:seller.example',
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: xB64Url
        }
      }
    ]
  };
  const disc = await discoverIssuerKeys('https://seller.example/v1/infer', {
    fetch: async (url) => {
      if (url.endsWith('/.well-known/x402-keys.json')) {
        return new Response('not found', { status: 404 });
      }
      if (url.endsWith('/.well-known/did.json')) {
        return new Response(JSON.stringify(didDoc), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      }
      return new Response('not found', { status: 404 });
    }
  });
  assert.equal(disc.ok, true);
  assert.equal(disc.issuer, 'did:web:seller.example');
  assert.deepEqual(disc.publicKeys, [kp.publicKey]);
  assert.equal(disc.keys[0].keyId, 'did-seller-01');
});
