import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}

const require = createRequire(import.meta.url);
const cjsProofs = require('../cjs/proofs.cjs');

import * as nodeSdk from '../src/index.mjs';
import * as webSdk from '../src/web.mjs';
import * as proofs from '../src/proofs.mjs';
import { utf8ToBytes, hexToBytes, bytesToHex, bytesToBase64Url } from '../src/bytes.mjs';

const FIXTURES_DIR = new URL('./fixtures/', import.meta.url);
const ethMainnetFixture = JSON.parse(
  readFileSync(new URL('eth-mainnet-usdc-eip1186.json', FIXTURES_DIR), 'utf8')
);
const baseMainnetFixture = JSON.parse(
  readFileSync(new URL('base-mainnet-usdc-receipt-proof.json', FIXTURES_DIR), 'utf8')
);

const ZERO_BLOOM = `0x${'00'.repeat(256)}`;

function makeTransferLog(tokenAddr, fromAddr, toAddr, amountBigInt) {
  const padTopic = (addr) => `0x000000000000000000000000${addr.replace(/^0x/i, '').toLowerCase()}`;
  const dataHex = `0x${BigInt(amountBigInt).toString(16).padStart(64, '0')}`;
  return {
    address: tokenAddr,
    topics: [proofs.ERC20_TRANSFER_TOPIC0, padTopic(fromAddr), padTopic(toAddr)],
    data: dataHex
  };
}

test('v0.4.0 Keccak-256 matches Ethereum vectors including 135/136/137-byte rate boundaries', () => {
  assert.equal(
    proofs.keccak256Hex(new Uint8Array(0)),
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  );
  assert.equal(
    proofs.keccak256Hex(utf8ToBytes('abc')),
    '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
  );
  assert.equal(
    proofs.keccak256Hex(utf8ToBytes('Transfer(address,address,uint256)')),
    proofs.ERC20_TRANSFER_TOPIC0
  );
  // Empty RLP byte string 0x80 -> EMPTY_TRIE_ROOT_HEX
  assert.equal(
    proofs.keccak256Hex(new Uint8Array([0x80])),
    proofs.EMPTY_TRIE_ROOT_HEX
  );

  // Critical Keccak rate=136 boundary tests (verified against ethereum-cryptography/keccak.js):
  // 135 bytes ('a'*135): pad[135] combines 0x01 ^ 0x80 = 0x81 in a single block!
  assert.equal(
    proofs.keccak256Hex(utf8ToBytes('a'.repeat(135))),
    '0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446'
  );
  // 136 bytes ('a'*136): exact full rate block followed by full padding block [0x01, 0..., 0x80]
  assert.equal(
    proofs.keccak256Hex(utf8ToBytes('a'.repeat(136))),
    '0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e'
  );
  // 137 bytes ('a'*137): multi-block spill
  assert.equal(
    proofs.keccak256Hex(utf8ToBytes('a'.repeat(137))),
    '0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39'
  );
  // CommonJS parity
  assert.equal(
    cjsProofs.keccak256Hex(utf8ToBytes('a'.repeat(135))),
    proofs.keccak256Hex(utf8ToBytes('a'.repeat(135)))
  );
});

test('v0.4.0 Canonical RLP round-trips Yellow Paper vectors and rejects non-canonical malleability', () => {
  assert.equal(bytesToHex(proofs.rlpEncode(0n)), '80');
  assert.equal(bytesToHex(proofs.rlpEncode(15)), '0f');
  assert.equal(bytesToHex(proofs.rlpEncode(1024n)), '820400');
  assert.equal(bytesToHex(proofs.rlpEncode([])), 'c0');
  // Yellow Paper "set theoretical representation of three": [ [], [[]], [ [], [[]] ] ]
  const setThree = [[], [[]], [[], [[]]]];
  assert.equal(bytesToHex(proofs.rlpEncode(setThree)), 'c7c0c1c0c3c0c1c0');
  assert.deepEqual(proofs.rlpDecode('0xc7c0c1c0c3c0c1c0'), setThree);

  // 56-byte long string boundary (> 55 bytes)
  const long56 = utf8ToBytes('x'.repeat(56));
  const enc56 = proofs.rlpEncode(long56);
  assert.equal(enc56[0], 0xb8);
  assert.equal(enc56[1], 56);
  assert.deepEqual(proofs.rlpDecode(enc56), long56);

  // Adversarial non-canonical RLP rejections:
  // 1. Single byte < 0x80 encoded with 0x81 prefix
  assert.throws(() => proofs.rlpDecode('0x817f'), /Non-canonical RLP/);
  assert.throws(() => proofs.rlpDecode('0x8100'), /Non-canonical RLP/);
  // 2. Short string (<=55 bytes) encoded with long prefix 0xb8
  assert.throws(() => proofs.rlpDecode('0xb803616263'), /length <= 55/);
  // 3. Leading zero in length prefix (0xb90038...)
  assert.throws(() => proofs.rlpDecode(`0xb90038${'61'.repeat(56)}`), /leading zero/);
  // 4. Trailing garbage byte
  assert.throws(() => proofs.rlpDecode('0x8000'), /Trailing/);
  // 5. Truncated payload
  assert.throws(() => proofs.rlpDecode('0x84dead'), /Truncated/);
  // 6. Excessive nesting depth (> 64)
  const deepHex = `0x${'c1'.repeat(66)}c0`;
  assert.throws(() => proofs.rlpDecode(deepHex), /maximum depth/);
});

test('v0.4.0 MPT builder & verifier handle Branch, Extension, Leaf, <32B Inline nodes, and Exclusion proofs', () => {
  // Construct keys with shared prefixes, branch splits, and tiny values (< 32B RLP -> inline child nodes!)
  const entries = [
    { key: '0x11223300', value: '0x01' }, // tiny leaf (< 32B RLP -> inlined in parent!)
    { key: '0x11223301', value: '0x02' }, // tiny sibling leaf -> forces Extension('1122330') + Branch + 2 inline leaves!
    { key: '0x11224400', value: `0x${'aa'.repeat(40)}` }, // >= 32B hashed leaf
    { key: '0x99887766', value: `0x${'bb'.repeat(48)}` }
  ];

  // Verify every included key
  for (const e of entries) {
    const built = proofs.buildMptProof(entries, e.key);
    const res = proofs.verifyMptProof({
      rootHash: built.rootHash,
      key: e.key,
      proof: built.proof,
      expectedValue: e.value
    });
    assert.equal(res.ok, true, res.reason);
    assert.equal(res.code, 'verified');
    assert.equal(`0x${bytesToHex(res.value)}`, e.value);
  }

  // Verify authenticated exclusion proofs across all 3 absence mechanisms:
  // (a) Empty branch slot ('0x55000000')
  // (b) Divergent extension prefix ('0x11230000')
  // (c) Divergent leaf suffix ('0x99887799')
  for (const absentKey of ['0x55000000', '0x11230000', '0x99887799']) {
    const built = proofs.buildMptProof(entries, absentKey);
    assert.equal(built.value, null);
    const res = proofs.verifyMptProof({
      rootHash: built.rootHash,
      key: absentKey,
      proof: built.proof,
      expectedValue: null
    });
    assert.equal(res.ok, true, res.reason);
    assert.equal(res.code, 'verified_absent');
    assert.equal(res.value, null);

    // Asking for an inclusion value on an absent key must fail
    const wrong = proofs.verifyMptProof({
      rootHash: built.rootHash,
      key: absentKey,
      proof: built.proof,
      expectedValue: '0x01'
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.code, 'key_absent');
  }

  // Empty trie root exclusion proof
  const emptyRes = proofs.verifyMptProof({
    rootHash: proofs.EMPTY_TRIE_ROOT_HEX,
    key: '0xdeadbeef',
    proof: [],
    expectedValue: null
  });
  assert.equal(emptyRes.ok, true);
  assert.equal(emptyRes.code, 'verified_absent');
});

test('v0.4.0 Real Ethereum Mainnet USDC EIP-1186 proof verifies offline & rejects tampering', () => {
  const res = proofs.verifyEip1186Proof({
    stateRoot: ethMainnetFixture.stateRoot,
    proof: ethMainnetFixture.proof,
    expectedStorage: [
      { slot: 0n, value: ethMainnetFixture.proof.storageProof[0].value },
      { slot: '0xdeadbeef', value: 0n }
    ]
  });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.exists, true);
  assert.equal(res.storage.length, 2);
  assert.equal(res.storage[1].code, 'verified_zero');
  assert.equal(res.storage[1].value, 0n);

  // Tamper storage value -> must reject
  const wrongExpect = proofs.verifyEip1186Proof({
    stateRoot: ethMainnetFixture.stateRoot,
    proof: ethMainnetFixture.proof,
    expectedStorage: [{ slot: '0xdeadbeef', value: 1n }]
  });
  assert.equal(wrongExpect.ok, false);
  assert.equal(wrongExpect.code, 'storage_value_mismatch');

  // Corrupt 1 byte in accountProof[2] -> must reject with incomplete_proof / proof_root_mismatch
  const corruptedNodes = [...ethMainnetFixture.proof.accountProof];
  const nodeBytes = hexToBytes(corruptedNodes[2]);
  nodeBytes[nodeBytes.length - 1] ^= 0xff;
  corruptedNodes[2] = `0x${bytesToHex(nodeBytes)}`;
  const corruptedRes = proofs.verifyEip1186Proof({
    stateRoot: ethMainnetFixture.stateRoot,
    proof: { ...ethMainnetFixture.proof, accountProof: corruptedNodes }
  });
  assert.equal(corruptedRes.ok, false);
  assert.equal(corruptedRes.code, 'incomplete_proof');

  // EIP-3009 authorizationState nested mapping slot helper
  const slotHex = proofs.computeEip3009AuthStateSlot(
    '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
    `0x${'ab'.repeat(32)}`,
    15n
  );
  assert.match(slotHex, /^0x[0-9a-f]{64}$/);
});

test('v0.4.0 Real Base Mainnet OP-Stack receipt-trie USDC proof + paxiom.root.v0 upgrades receipt to verified', async () => {
  const sellerKp = nodeSdk.generateReceiptKeyPair({ keyId: 'seller-base-01' });
  const rootWitnessKp = nodeSdk.generateReceiptKeyPair({ keyId: 'witness-root-01' });

  const deliveredPayload = { ok: true, dataset: 'base-l2-orderbook-snapshot', rows: 128 };
  const { receipt, receiptHeader } = nodeSdk.issueReceipt({
    privateKey: sellerKp.privateKeyPem,
    issuer: {
      name: 'Base Data Seller',
      keyId: sellerKp.keyId,
      payTo: baseMainnetFixture.payTo
    },
    service: {
      name: 'Orderbook Feed',
      resource: 'https://seller.example/v1/snapshot',
      method: 'GET'
    },
    request: { method: 'GET', resource: 'https://seller.example/v1/snapshot', body: '' },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: 'USDC',
      amountAtomic: baseMainnetFixture.amountAtomic,
      amountDisplay: '4329.679740',
      payer: baseMainnetFixture.payer,
      payTo: baseMainnetFixture.payTo,
      settlement: {
        status: 'claimed_not_checked',
        transactionHash: baseMainnetFixture.settlementProof.transactionHash
      }
    },
    output: deliveredPayload
  });

  // 1. Without offline proof, receipt stops at settlement_claimed_not_checked
  const baseline = nodeSdk.verifyReceipt(receipt, { output: deliveredPayload });
  assert.equal(baseline.valid, false);
  assert.equal(baseline.trustState, 'settlement_claimed_not_checked');

  // 2. With settlementProof but NO root anchor -> still settlement_claimed_not_checked (cannot forge root!)
  const unanchored = nodeSdk.verifyReceipt(receipt, {
    output: deliveredPayload,
    settlementProof: baseMainnetFixture.settlementProof
  });
  assert.equal(unanchored.valid, false);
  assert.equal(unanchored.trustState, 'settlement_claimed_not_checked');
  assert.equal(unanchored.checks.proof, 'provided');

  // 3. Issue signed paxiom.root.v0 attestation & verify in BOTH sync Node SDK and async WebCrypto SDK
  const rootAtt = await proofs.issueRootAttestation({
    privateKey: rootWitnessKp.privateKeyPem,
    network: 'base',
    blockNumber: baseMainnetFixture.blockNumber,
    blockHash: baseMainnetFixture.blockHash,
    stateRoot: baseMainnetFixture.stateRoot,
    receiptsRoot: baseMainnetFixture.receiptsRoot,
    finalityTier: 'l2-sequencer-attested',
    issuedAt: '2026-11-18T18:00:00.000Z',
    expiresAt: '2026-11-19T18:00:00.000Z',
    attester: { name: 'Paxiom Root Witness', keyId: rootWitnessKp.keyId }
  });

  const verifyOpts = {
    output: deliveredPayload,
    expectedIssuerPublicKeys: [sellerKp.publicKey],
    expectedPayTo: baseMainnetFixture.payTo,
    settlementProof: baseMainnetFixture.settlementProof,
    rootAttestation: rootAtt,
    trustedRootPublicKeys: [rootWitnessKp.publicKey],
    now: Date.parse('2026-11-18T19:00:00.000Z')
  };

  const nodeVerified = nodeSdk.verifyReceipt(receipt, verifyOpts);
  const webVerified = await webSdk.verifyReceipt(receipt, verifyOpts);
  assert.deepEqual(webVerified, nodeVerified);
  assert.equal(nodeVerified.valid, true, nodeVerified.summary);
  assert.equal(nodeVerified.trustState, 'verified');
  assert.equal(nodeVerified.checks.settlement, 'verified_settled');
  assert.equal(nodeVerified.checks.proof, 'verified');

  // 4. Gate 2 Delivery Arbiter with strict allowUncheckedSettlementClaim: false -> CAPTURE via Payment-Settlement-Proof header!
  const proofHeaderB64 = bytesToBase64Url(
    utf8ToBytes(JSON.stringify({ ...baseMainnetFixture.settlementProof, rootAttestation: rootAtt }))
  );
  const arbiter = await nodeSdk.evaluateDeliveryArbiter(
    {
      origin: 'https://seller.example',
      scheme: 'exact',
      request: { url: 'https://seller.example/v1/snapshot', method: 'GET', body: '' },
      response: {
        status: 200,
        headers: {
          'payment-receipt': receiptHeader,
          'payment-settlement-proof': proofHeaderB64
        }
      },
      body: JSON.stringify(deliveredPayload)
    },
    {
      expectedIssuerPublicKeys: [sellerKp.publicKey],
      expectedPayTo: baseMainnetFixture.payTo,
      trustedRootPublicKeys: [rootWitnessKp.publicKey],
      allowUncheckedSettlementClaim: false,
      nowMs: Date.parse('2026-11-18T19:00:00.000Z')
    }
  );
  assert.equal(arbiter.action, 'CAPTURE', `${arbiter.reasonCode}: ${arbiter.reason}`);
  assert.equal(arbiter.verification.trustState, 'verified');

  // 5. Expired rootAttestation -> falls back to settlement_claimed_not_checked -> VOID when allowUncheckedSettlementClaim: false
  const expiredArbiter = await nodeSdk.evaluateDeliveryArbiter(
    {
      origin: 'https://seller.example',
      scheme: 'exact',
      response: {
        status: 200,
        headers: {
          'payment-receipt': receiptHeader,
          'payment-settlement-proof': proofHeaderB64
        }
      },
      body: JSON.stringify(deliveredPayload)
    },
    {
      expectedIssuerPublicKeys: [sellerKp.publicKey],
      trustedRootPublicKeys: [rootWitnessKp.publicKey],
      allowUncheckedSettlementClaim: false,
      nowMs: Date.parse('2026-11-25T00:00:00.000Z')
    }
  );
  assert.equal(expiredArbiter.action, 'VOID');
  assert.equal(expiredArbiter.reasonCode, 'receipt_settlement_claimed_not_checked');
});

test('v0.4.0 Circle Arc (eip155:5042) & Adversarial Receipt-Trie Rejection (reverted tx, spoofed token, underpayment)', () => {
  const sellerKp = nodeSdk.generateReceiptKeyPair({ keyId: 'arc-seller-01' });
  const payer = '0x35a9dd3fae03ae16dd93a67d185569ec0aa3e6c3';
  const payTo = '0x9786f5532ab7d7556cda53e3f6c2d937c9b87bc4';
  const arcUsdc = proofs.CANONICAL_USDC_BY_NETWORK['eip155:5042']; // 0x3600...0000
  const fakeToken = '0x1111111111111111111111111111111111111111';

  const blockReceipts = [
    // tx 0: Valid Circle Arc USDC Transfer of 50_000 (0.05 USDC)
    {
      type: '0x2',
      status: '0x1',
      cumulativeGasUsed: '0x5208',
      logsBloom: ZERO_BLOOM,
      transactionIndex: '0x0',
      transactionHash: `0x${'10'.repeat(32)}`,
      blockNumber: '0x100',
      logs: [makeTransferLog(arcUsdc, payer, payTo, 50_000n)]
    },
    // tx 1: Reverted transaction (status = 0x0) even with log bytes
    {
      type: '0x2',
      status: '0x0',
      cumulativeGasUsed: '0xa410',
      logsBloom: ZERO_BLOOM,
      transactionIndex: '0x1',
      transactionHash: `0x${'20'.repeat(32)}`,
      blockNumber: '0x100',
      logs: [makeTransferLog(arcUsdc, payer, payTo, 50_000n)]
    },
    // tx 2: Spoofed non-USDC ERC-20 token emitting Transfer(payer, payTo, 50_000)
    {
      type: '0x2',
      status: '0x1',
      cumulativeGasUsed: '0xf618',
      logsBloom: ZERO_BLOOM,
      transactionIndex: '0x2',
      transactionHash: `0x${'30'.repeat(32)}`,
      blockNumber: '0x100',
      logs: [makeTransferLog(fakeToken, payer, payTo, 50_000n)]
    },
    // tx 3: Underpayment (49_999 < 50_000)
    {
      type: '0x2',
      status: '0x1',
      cumulativeGasUsed: '0x14820',
      logsBloom: ZERO_BLOOM,
      transactionIndex: '0x3',
      transactionHash: `0x${'40'.repeat(32)}`,
      blockNumber: '0x100',
      logs: [makeTransferLog(arcUsdc, payer, payTo, 49_999n)]
    }
  ];

  const proofValid = proofs.buildReceiptTrieProof(blockReceipts, 0, { network: 'arc' });
  const proofReverted = proofs.buildReceiptTrieProof(blockReceipts, 1, { network: 'arc' });
  const proofSpoofed = proofs.buildReceiptTrieProof(blockReceipts, 2, { network: 'arc' });
  const proofUnderpaid = proofs.buildReceiptTrieProof(blockReceipts, 3, { network: 'arc' });

  const trustedRoots = [{ network: 'eip155:5042', blockNumber: '256', receiptsRoot: proofValid.receiptsRoot }];
  const out = { arcFinalityMs: 320, ok: true };

  const mkReceipt = (txHashHex) =>
    nodeSdk.issueReceipt({
      privateKey: sellerKp.privateKeyPem,
      issuer: { name: 'Arc Gateway Seller', keyId: sellerKp.keyId, payTo },
      service: { name: 'Arc Inference', resource: '/v1/infer', method: 'POST' },
      request: { method: 'POST', resource: '/v1/infer', body: '{}' },
      payment: {
        scheme: 'batch-settlement',
        network: 'arc',
        asset: 'USDC',
        amountAtomic: '50000',
        amountDisplay: '0.05',
        payer,
        payTo,
        settlement: { status: 'claimed_not_checked', transactionHash: txHashHex }
      },
      output: out
    }).receipt;

  // Valid Arc USDC proof -> verified!
  const okRes = nodeSdk.verifyReceipt(mkReceipt(`0x${'10'.repeat(32)}`), {
    output: out,
    settlementProof: proofValid,
    trustedRoots
  });
  assert.equal(okRes.valid, true, okRes.summary);
  assert.equal(okRes.trustState, 'verified');
  assert.equal(okRes.checks.settlement, 'verified_settled');

  // Reverted tx -> settlement_failed!
  const revRes = nodeSdk.verifyReceipt(mkReceipt(`0x${'20'.repeat(32)}`), {
    output: out,
    settlementProof: proofReverted,
    trustedRoots
  });
  assert.equal(revRes.valid, false);
  assert.equal(revRes.trustState, 'settlement_failed');
  assert.equal(revRes.checks.settlement, 'failed');

  // Spoofed token contract -> proof_invalid!
  const spoofRes = nodeSdk.verifyReceipt(mkReceipt(`0x${'30'.repeat(32)}`), {
    output: out,
    settlementProof: proofSpoofed,
    trustedRoots
  });
  assert.equal(spoofRes.valid, false);
  assert.equal(spoofRes.trustState, 'proof_invalid');

  // Underpayment (49_999 < 50_000) -> proof_invalid!
  const underRes = nodeSdk.verifyReceipt(mkReceipt(`0x${'40'.repeat(32)}`), {
    output: out,
    settlementProof: proofUnderpaid,
    trustedRoots
  });
  assert.equal(underRes.valid, false);
  assert.equal(underRes.trustState, 'proof_invalid');
});
