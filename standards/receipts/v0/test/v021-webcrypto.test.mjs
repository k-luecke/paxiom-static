import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

// On Node 18 ESM (before Node 19 exposed globalThis.crypto by default), bind crypto.webcrypto
// so `npm test` runs the full WebCrypto suite across Node 18, 20, 22, and 24+.
if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}

import * as nodeSdk from '../src/index.mjs';
import * as webSdk from '../src/web.mjs';

const EX = new URL('../examples/', import.meta.url);
const validReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const validOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

test('v0.2.1 @paxiom/receipts/web module graph has ZERO node:* imports and ZERO Buffer tokens', () => {
  const webGraphFiles = [
    '../src/web.mjs',
    '../src/web.d.ts',
    '../src/bytes.mjs',
    '../src/schema.mjs',
    '../src/canonicalize.mjs',
    '../src/explain.mjs',
    '../src/guard.mjs',
    '../src/guard.d.ts',
    '../src/proofs.mjs',
    '../src/proofs.d.ts'
  ];

  for (const rel of webGraphFiles) {
    const raw = readFileSync(new URL(rel, import.meta.url), 'utf8');
    // Strip single-line and multi-line comments before token check
    const codeOnly = raw
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    assert.equal(
      /\bnode:[A-Za-z0-9_-]+/.test(codeOnly),
      false,
      `${rel} must not import any node:* built-in module`
    );
    assert.equal(
      /\bBuffer\b/.test(codeOnly),
      false,
      `${rel} must not reference Node Buffer`
    );
  }
});

test('v0.2.1 WebCrypto verifies official valid.receipt.json conformance vector and cross-verifies with Node SDK', async () => {
  const webOfficial = await webSdk.verifyReceipt(validReceipt, { output: validOutput });
  const nodeOfficial = nodeSdk.verifyReceipt(validReceipt, { output: validOutput });
  assert.deepEqual(webOfficial, nodeOfficial);
  assert.equal(webOfficial.valid, true);
  assert.equal(webOfficial.trustState, 'verified');

  // Node-generated PEM -> WebCrypto issueReceipt -> Node verifyReceipt & WebCrypto verifyReceipt
  const nodeKp = nodeSdk.generateReceiptKeyPair({ keyId: 'cross-node-01' });
  const singleLinePem = nodeKp.privateKeyPem.trim().replace(/\n/g, '\\n');
  assert.equal(await webSdk.publicKeyFromPrivateKey(singleLinePem), nodeKp.publicKey);

  const webIssued = await webSdk.issueReceipt({
    privateKey: singleLinePem,
    receiptId: 'rcpt_cross_deterministic_01',
    issuedAt: '2026-11-16T12:00:00.000Z',
    issuer: {
      name: 'Edge Worker Seller',
      keyId: nodeKp.keyId,
      payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4'
    },
    service: {
      name: 'ToolSnap HTTP Door',
      resource: 'https://mcp.toolsnap.app/x402/tools/screenshot_url',
      method: 'POST'
    },
    request: {
      method: 'POST',
      resource: 'https://mcp.toolsnap.app/x402/tools/screenshot_url',
      body: JSON.stringify({ url: 'https://example.com' })
    },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amountAtomic: '40000',
      amountDisplay: '0.04',
      payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
      settlement: { status: 'verify_only', transactionHash: null, checkedByVerifier: false }
    },
    output: { imageUrl: 'https://cdn.example.com/shot.png' },
    statusCode: 200
  });

  // Deterministic Ed25519: Node issueReceipt with identical inputs produces byte-identical signature!
  const nodeIssued = nodeSdk.issueReceipt({
    privateKey: nodeKp.privateKeyPem,
    receiptId: 'rcpt_cross_deterministic_01',
    issuedAt: '2026-11-16T12:00:00.000Z',
    issuer: {
      name: 'Edge Worker Seller',
      keyId: nodeKp.keyId,
      payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4'
    },
    service: {
      name: 'ToolSnap HTTP Door',
      resource: 'https://mcp.toolsnap.app/x402/tools/screenshot_url',
      method: 'POST'
    },
    request: {
      method: 'POST',
      resource: 'https://mcp.toolsnap.app/x402/tools/screenshot_url',
      body: JSON.stringify({ url: 'https://example.com' })
    },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amountAtomic: '40000',
      amountDisplay: '0.04',
      payTo: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
      settlement: { status: 'verify_only', transactionHash: null, checkedByVerifier: false }
    },
    output: { imageUrl: 'https://cdn.example.com/shot.png' },
    statusCode: 200
  });

  assert.equal(webIssued.receipt.signature.value, nodeIssued.receipt.signature.value);
  assert.equal(webIssued.receiptHeader, nodeIssued.receiptHeader);

  const vNode = nodeSdk.verifyReceipt(webIssued.receipt, {
    output: { imageUrl: 'https://cdn.example.com/shot.png' },
    expectedIssuerPublicKeys: [nodeKp.publicKey],
    expectedPayTo: '0x9786f5532ab7d7556cda53e3f6c2d937c9b87bc4'
  });
  assert.equal(vNode.valid, true);
  assert.equal(vNode.trustState, 'verified');

  // WebCrypto generateReceiptKeyPair -> Node issueReceipt -> WebCrypto verifyReceipt
  const webKp = await webSdk.generateReceiptKeyPair({ keyId: 'web-gen-01' });
  const fromWebKey = nodeSdk.issueReceipt({
    privateKey: webKp.privateKeyPem,
    issuer: { name: 'WebKey Seller', keyId: webKp.keyId },
    service: { name: 'Svc', resource: 'https://edge.example/run', method: 'POST' },
    output: new Uint8Array([1, 2, 3, 4]),
    mimeType: 'application/octet-stream'
  });
  const vWebBin = await webSdk.verifyReceipt(fromWebKey.receipt, {
    output: new Uint8Array([1, 2, 3, 4]),
    expectedIssuerPublicKeys: [webKp.publicKey]
  });
  assert.equal(vWebBin.valid, true);
  assert.equal(vWebBin.trustState, 'verified');
});

test('v0.2.1 WebCrypto supports 32-byte raw seeds, hex seeds, JWKs, and non-extractable CryptoKey bundles', async () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 1;
  const hexSeed = '0x' + webSdk.bytesToHex(seed);

  const pubFromBytes = await webSdk.publicKeyFromPrivateKey(seed);
  const pubFromHex = await webSdk.publicKeyFromPrivateKey(hexSeed);
  assert.equal(pubFromBytes, pubFromHex);

  const jwkDOnly = { kty: 'OKP', crv: 'Ed25519', d: webSdk.bytesToBase64Url(seed) };
  assert.equal(await webSdk.publicKeyFromPrivateKey(jwkDOnly), pubFromBytes);

  // Mismatched x in JWK must throw
  await assert.rejects(
    () => webSdk.publicKeyFromPrivateKey({ ...jwkDOnly, x: webSdk.bytesToBase64Url(new Uint8Array(32)) }),
    /does not match/
  );

  // Non-extractable CryptoKey bundle
  const ckPair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  await assert.rejects(() => webSdk.publicKeyFromPrivateKey(ckPair.privateKey), /Non-extractable/);

  const nonExtractableIssued = await webSdk.issueReceipt({
    privateKey: { privateKey: ckPair.privateKey, publicKey: ckPair.publicKey },
    issuer: { name: 'HSM Worker', keyId: 'hsm-01' },
    service: { name: 'HSM API', resource: 'https://hsm.example/sign', method: 'POST' },
    output: { protected: true }
  });
  const v = await webSdk.verifyReceipt(nonExtractableIssued.receipt, { output: { protected: true } });
  assert.equal(v.valid, true);
});

test('v0.2.1 WebCrypto enforces RFC 8032 S < L scalar malleability and canonical base64 padding bits', async () => {
  const kp = await webSdk.generateReceiptKeyPair({ keyId: 'malleability-01' });
  const output = { amount: '100' };
  const { receipt } = await webSdk.issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Strict Edge', keyId: kp.keyId },
    service: { name: 'API', resource: 'https://edge.example/v1', method: 'POST' },
    output
  });

  // 1. Add Ed25519 group order L to S (little-endian bytes 32..63) -> S' = S + L >= L
  const ED25519_L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
  const sigBytes = webSdk.base64ToBytes(receipt.signature.value);
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sigBytes[i]);
  const sPlusL = s + ED25519_L;
  const malleableBytes = new Uint8Array(sigBytes);
  let tmp = sPlusL;
  for (let i = 32; i < 64; i++) {
    malleableBytes[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  const highScalarReceipt = structuredClone(receipt);
  highScalarReceipt.signature.value = webSdk.bytesToBase64(malleableBytes);
  const resHighScalar = await webSdk.verifyReceipt(highScalarReceipt, { output });
  assert.equal(resHighScalar.valid, false);
  assert.equal(resHighScalar.trustState, 'invalid_signature');

  // 2. Flip unused low base64 padding bit in 86th char preceding '=='
  const b64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const origSig = receipt.signature.value;
  const idx85 = b64Alphabet.indexOf(origSig[85]);
  const badPadReceipt = structuredClone(receipt);
  badPadReceipt.signature.value = origSig.slice(0, 85) + b64Alphabet[idx85 ^ 1] + origSig.slice(86);
  const resBadPad = await webSdk.verifyReceipt(badPadReceipt, { output });
  assert.equal(resBadPad.valid, false);
  assert.equal(resBadPad.trustState, 'invalid_signature');
});

test('v0.2.1 WebCrypto withPaxiomReceipt, verifyResponseReceipt, and discoverIssuerKeys (did:web + x402-keys)', async () => {
  const kp = await webSdk.generateReceiptKeyPair({ keyId: 'worker-door-01' });
  const payTo = '0xd5F96b537A05f196091502bCde038C572f88efba';
  const txHash = '0x' + 'ef'.repeat(32);

  const paySigJson = {
    x402Version: 2,
    accepted: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amount: '40000',
      payTo
    }
  };
  const payResJson = {
    success: true,
    transaction: txHash,
    network: 'eip155:8453',
    payer: '0x1111111111111111111111111111111111111111'
  };

  const workerFetch = webSdk.withPaxiomReceipt(
    async (req) => {
      const body = await req.json();
      return new Response(JSON.stringify({ capturedUrl: body.url, ok: true }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'payment-response': webSdk.bytesToBase64(webSdk.utf8ToBytes(JSON.stringify(payResJson)))
        }
      });
    },
    {
      privateKey: kp.privateKeyPem,
      issuer: { name: 'ToolSnap Worker', keyId: kp.keyId, payTo }
    }
  );

  const response = await workerFetch(
    new Request('https://mcp.toolsnap.app/x402/tools/screenshot_url', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'payment-signature': webSdk.bytesToBase64(webSdk.utf8ToBytes(JSON.stringify(paySigJson)))
      },
      body: JSON.stringify({ url: 'https://paxiom.org' })
    })
  );

  assert.equal(response.status, 200);
  assert.ok(response.headers.get('payment-receipt'));
  assert.equal(response.headers.get('payment-receipt'), response.headers.get('x-paxiom-receipt'));

  const delivered = await response.clone().json();
  const verified = await webSdk.verifyResponseReceipt(response, {
    output: delivered,
    expectedIssuerPublicKeys: [kp.publicKey],
    expectedPayTo: payTo
  });
  assert.equal(verified.present, true);
  assert.equal(verified.trustState, 'settlement_claimed_not_checked');
  assert.equal(verified.checks.signature, 'pass');
  assert.equal(verified.checks.issuerAuthorization, 'pass');
  assert.equal(verified.checks.outputHash, 'pass');
  assert.equal(verified.receipt.payload.payment.settlement.transactionHash, txHash);

  // W3C did:web discovery via WebCrypto discoverIssuerKeys
  const disc = await webSdk.discoverIssuerKeys('https://mcp.toolsnap.app/x402/tools/screenshot_url', {
    fetch: async (url) => {
      if (url.endsWith('/.well-known/did.json')) {
        return new Response(JSON.stringify({
          id: 'did:web:mcp.toolsnap.app',
          verificationMethod: [{
            id: 'did:web:mcp.toolsnap.app#worker-door-01',
            type: 'JsonWebKey2020',
            controller: 'did:web:mcp.toolsnap.app',
            publicKeyJwk: kp.publicKeyJwk
          }]
        }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }
  });
  assert.equal(disc.ok, true);
  assert.deepEqual(disc.publicKeys, [kp.publicKey]);
});
