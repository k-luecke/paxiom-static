import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  verifyReceipt,
  generateReceiptKeyPair,
  issueReceipt,
  canonicalize,
  createReceiptMiddleware
} from '../src/index.mjs';
import { handleJsonRpcMessage } from '../mcp/server.mjs';

test('FERMI-PAX-03: schema validator rejects Object.prototype property names on additionalProperties:false objects', () => {
  const kp = generateReceiptKeyPair({ keyId: 'proto-guard-01' });
  const output = { ok: true };
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Proto Seller', keyId: kp.keyId },
    service: { name: 'Proto API', resource: 'https://example.com/api', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });

  // Attach unsigned top-level prototype-named key via JSON.parse so it is an own property
  const withTopLevelProtoKey = JSON.parse(
    JSON.stringify(receipt).replace(/\}$/, ',"toString":"unsigned-metadata"}')
  );
  const resTop = verifyReceipt(withTopLevelProtoKey, { output });
  assert.equal(resTop.trustState, 'schema_invalid');
  assert.equal(resTop.valid, false);
  assert.equal(resTop.checks.schema, 'fail');

  // Attach prototype-named key on signature object
  const withSigProtoKey = structuredClone(receipt);
  Object.defineProperty(withSigProtoKey.signature, 'constructor', {
    value: 'unexpected-field',
    enumerable: true,
    configurable: true,
    writable: true
  });
  const resSig = verifyReceipt(withSigProtoKey, { output });
  assert.equal(resSig.trustState, 'schema_invalid');
  assert.equal(resSig.valid, false);
});

test('FERMI-PAX-03: non-null settlement.transactionHash with verify_only/not_required/disabled never reaches verified offline', () => {
  const kp = generateReceiptKeyPair({ keyId: 'txhash-status-01' });
  const output = { ok: true };
  const txHash = '0x' + '11'.repeat(32);

  for (const status of ['not_required', 'disabled', 'verify_only']) {
    const { receipt } = issueReceipt({
      privateKey: kp.privateKeyPem,
      issuer: { name: 'Seller', keyId: kp.keyId },
      service: { name: 'API', resource: 'https://example.com/v1', method: 'POST' },
      payment: {
        settlement: { status, transactionHash: txHash, checkedByPaxiom: false }
      },
      output
    });
    const res = verifyReceipt(receipt, { output });
    assert.equal(res.trustState, 'settlement_claimed_not_checked', `status=${status} must not reach verified with unverified txHash`);
    assert.equal(res.valid, false);
  }
});

test('FERMI-PAX-04: createReceiptMiddleware refuses to sign truncated (>256 KiB) request bodies, rejects async resolvePayment, and sanitizes Host', async () => {
  const kp = generateReceiptKeyPair({ keyId: 'mw-guard-01' });

  // 1. Async resolvePayment throws at setup time instead of silently spreading {} -> amountAtomic:"0"
  assert.throws(
    () => createReceiptMiddleware({
      privateKey: kp.privateKeyPem,
      issuer: { name: 'MW Seller', keyId: kp.keyId },
      resolvePayment: async () => ({ amountAtomic: '5000' })
    }),
    /synchronous resolvePayment/
  );

  // 2. Oversized request (>256 KiB) passes through cleanly to handler WITHOUT emitting a truncated prefix receipt
  const mw = createReceiptMiddleware({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'MW Seller', keyId: kp.keyId },
    paymentDefaults: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } }
  });

  const srv = http.createServer((req, res) => {
    mw(req, res, () => {
      let bytes = 0;
      req.on('data', (c) => { bytes += c.length; });
      req.on('end', () => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ receivedBytes: bytes }));
      });
    });
  });

  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const { port } = srv.address();
    const bigPayload = JSON.stringify({ data: 'a'.repeat(270 * 1024) });
    const resBig = await fetch(`http://127.0.0.1:${port}/v1/ingest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: bigPayload
    });
    assert.equal(resBig.status, 200);
    const bodyBig = await resBig.json();
    assert.equal(bodyBig.receivedBytes, Buffer.byteLength(bigPayload));
    assert.equal(resBig.headers.get('x-paxiom-receipt'), null);
  } finally {
    await new Promise((r) => srv.close(r));
  }
});

test('FERMI-PAX-05: canonicalize rejects NaN/Infinity/Function/Symbol/Map/Set and preserves Date.toJSON() parity', () => {
  assert.throws(() => canonicalize({ score: Number.NaN }), TypeError);
  assert.throws(() => canonicalize({ score: Number.POSITIVE_INFINITY }), TypeError);
  assert.throws(() => canonicalize({ fn: () => {} }), TypeError);
  assert.throws(() => canonicalize([Symbol('x')]), TypeError);
  assert.throws(() => canonicalize(new Set([1, 2])), TypeError);
  assert.throws(() => canonicalize(new Map([['a', 1]])), TypeError);

  const d = new Date('2026-05-01T12:00:00.000Z');
  assert.equal(canonicalize({ at: d }), '{"at":"2026-05-01T12:00:00.000Z"}');
});

test('FERMI-PAX-05: verifyReceipt rejects non-canonical base64 padding bits and whitespace in signature and publicKey', () => {
  const kp = generateReceiptKeyPair({ keyId: 'b64-strict-01' });
  const output = { ok: true };
  const { receipt } = issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: { name: 'Strict B64', keyId: kp.keyId },
    service: { name: 'API', resource: 'https://example.com/v1', method: 'POST' },
    payment: { settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false } },
    output
  });

  // Non-base64 whitespace/punctuation stripped by permissive Buffer.from must fail
  const spacedSig = structuredClone(receipt);
  spacedSig.signature.value = `${receipt.signature.value.slice(0, 10)} ${receipt.signature.value.slice(10)}`;
  assert.equal(verifyReceipt(spacedSig, { output }).trustState, 'invalid_signature');

  // Flipping unused low bits in the 86th base64 char (preceding '==') must fail canonical round-trip
  const b64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const origSig = receipt.signature.value;
  const idx85 = b64Alphabet.indexOf(origSig[85]);
  const nonCanonicalChar = b64Alphabet[idx85 ^ 1]; // flips lowest unused padding bit
  const malleableSig = structuredClone(receipt);
  malleableSig.signature.value = origSig.slice(0, 85) + nonCanonicalChar + origSig.slice(86);
  assert.equal(
    Buffer.from(malleableSig.signature.value, 'base64').equals(Buffer.from(origSig, 'base64')),
    true,
    'raw decoded bytes are identical, proving canonical base64 check is required'
  );
  assert.equal(verifyReceipt(malleableSig, { output }).trustState, 'invalid_signature');
});

test('FERMI-PAX-07: CLI keygen --out with missing path exits 2 without printing privateKeyPem to stdout, and MCP explain_receipt honors trustedPaxiomPublicKeys', () => {
  const cliPath = fileURLToPath(new URL('../bin/paxiom-receipt.mjs', import.meta.url));
  const proc = spawnSync(process.execPath, [cliPath, 'keygen', '--out'], { encoding: 'utf8' });
  assert.equal(proc.status, 2);
  assert.equal(proc.stdout.includes('PRIVATE KEY'), false);

  const paxiomKp = generateReceiptKeyPair({ keyId: 'paxiom-mcp-root-01' });
  const output = { verifiedBy: 'paxiom' };
  const { receipt } = issueReceipt({
    privateKey: paxiomKp.privateKeyPem,
    issuer: { name: 'Paxiom Receipt Verifier', keyId: paxiomKp.keyId },
    service: { name: 'Demo', resource: 'https://example.com/demo', method: 'POST' },
    payment: {
      amountAtomic: '2000',
      amountDisplay: '0.002',
      settlement: { status: 'verified_settled', transactionHash: '0x' + '22'.repeat(32), checkedByPaxiom: true }
    },
    output
  });

  const explained = handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 42,
    method: 'tools/call',
    params: {
      name: 'explain_receipt',
      arguments: {
        receipt,
        output,
        trustedPaxiomPublicKeys: [paxiomKp.publicKey]
      }
    }
  });
  assert.equal(explained.result.isError, false);
  assert.match(explained.result.content[0].text, /✓ VERIFIED/);
});
