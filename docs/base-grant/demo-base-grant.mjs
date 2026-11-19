#!/usr/bin/env node
// 90-Second Loom Walkthrough Script for Base Builder Grants (Track 4: Agents & x402)
// Usage: node docs/base-grant/demo-base-grant.mjs [bc_your_builder_code]

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;

import {
  generateReceiptKeyPair,
  issueReceipt,
  verifyReceipt,
  createMemorySpendLedger,
  evaluatePreSignPolicy,
  evaluateDeliveryArbiter,
  issueRootAttestation,
  appendErc8021Suffix,
  decodeErc8021Suffix,
  bytesToBase64Url,
  utf8ToBytes
} from '../../standards/receipts/v0/src/web.mjs';

const builderCode = process.argv[2] || 'bc_paxiom_demo';
const fixture = JSON.parse(
  readFileSync(
    new URL('../../standards/receipts/v0/test/fixtures/base-mainnet-usdc-receipt-proof.json', import.meta.url),
    'utf8'
  )
);

const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SPOOF_TOKEN = '0x1111111111111111111111111111111111111111';

console.log('========================================================================');
console.log(' PAXIOM (@paxiom/receipts v0.4.0) — BASE x402 AGENT SECURITY & PROOFS');
console.log('========================================================================\n');

// ─── BEAT 1: Pre-Sign Buyer Policy Firewall (Gate 1) ─────────────────────
console.log('[1/3] GATE 1 — Pre-Sign Buyer Policy Firewall (Before Wallet Signs)');
const ledger = createMemorySpendLedger();
const policy = {
  maxPerCallAtomic: '5000000000',
  maxSessionAtomic: '10000000000',
  allowedNetworks: ['eip155:8453'],
  allowedAssets: [BASE_USDC],
  pinnedPayToByOrigin: { 'https://seller.base.example': [fixture.payTo] }
};

const spoofAttempt = evaluatePreSignPolicy(
  {
    url: 'https://seller.base.example/v1/market-feed',
    challenge: {
      accepts: [{ scheme: 'exact', network: 'base', asset: SPOOF_TOKEN, payTo: fixture.payTo, amount: '50000' }]
    }
  },
  policy,
  ledger
);
console.log(`  ✗ Spoofed ERC-20 challenge -> allow=${spoofAttempt.allow} (${spoofAttempt.code})`);

const validPreSign = evaluatePreSignPolicy(
  {
    url: 'https://seller.base.example/v1/market-feed',
    challenge: {
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: BASE_USDC,
          payTo: fixture.payTo,
          amount: fixture.amountAtomic
        }
      ]
    }
  },
  policy,
  ledger
);
console.log(`  ✓ Canonical Base USDC challenge -> allow=${validPreSign.allow} (reservation=${validPreSign.reservationId})\n`);

// ─── BEAT 2: ERC-8021 Base Builder Code Attribution ──────────────────────
console.log('[2/3] ERC-8021 — Base Builder Code & x402 Calldata Attribution');
const annotatedCalldata = appendErc8021Suffix('0x3009e3be', {
  appCode: builderCode,
  walletCode: 'coinbase-agentkit',
  serviceCodes: ['paxiom-receipts-v0.4']
});
const decodedAttr = decodeErc8021Suffix(annotatedCalldata);
console.log(`  ✓ Appended Schema 2 suffix (${annotatedCalldata.length / 2 - 1} bytes)`);
console.log(`  ✓ Decoded backwards from 0x8021...8021:`, JSON.stringify(decodedAttr.attribution), '\n');

// ─── BEAT 3: Offline Base Mainnet Receipt-Trie MPT Proof + Gate 2 Arbiter
console.log('[3/3] v0.4.0 OFFLINE BASE MAINNET OP-STACK (0x7e/0x02) MPT SETTLEMENT PROOF');
const sellerKp = await generateReceiptKeyPair({ keyId: 'base-seller-01' });
const witnessKp = await generateReceiptKeyPair({ keyId: 'base-root-witness-01' });
const payload = { chain: 'eip155:8453', block: fixture.blockNumber, bestBid: '3412.55', verified: true };

const { receipt, receiptHeader } = await issueReceipt({
  privateKey: sellerKp.privateKeyPem,
  issuer: { name: 'Base Feed Seller', keyId: sellerKp.keyId, payTo: fixture.payTo },
  service: { name: 'Market Feed', resource: 'https://seller.base.example/v1/market-feed', method: 'GET' },
  request: { method: 'GET', resource: 'https://seller.base.example/v1/market-feed', body: '' },
  payment: {
    scheme: 'exact',
    network: 'eip155:8453',
    asset: 'USDC',
    amountAtomic: fixture.amountAtomic,
    amountDisplay: '4329.679740',
    payer: fixture.payer,
    payTo: fixture.payTo,
    settlement: { status: 'claimed_not_checked', transactionHash: fixture.settlementProof.transactionHash }
  },
  output: payload
});

const rootAttestation = await issueRootAttestation({
  privateKey: witnessKp.privateKeyPem,
  network: 'eip155:8453',
  blockNumber: fixture.blockNumber,
  blockHash: fixture.blockHash,
  stateRoot: fixture.stateRoot,
  receiptsRoot: fixture.receiptsRoot,
  finalityTier: 'l2-sequencer-attested',
  attester: { name: 'Paxiom Base Root Witness', keyId: witnessKp.keyId }
});

const t0 = performance.now();
const verified = await verifyReceipt(receipt, {
  output: payload,
  expectedIssuerPublicKeys: [sellerKp.publicKey],
  expectedPayTo: fixture.payTo,
  settlementProof: fixture.settlementProof,
  rootAttestation,
  trustedRootPublicKeys: [witnessKp.publicKey]
});
const elapsedMs = (performance.now() - t0).toFixed(2);

const proofHeader = bytesToBase64Url(
  utf8ToBytes(JSON.stringify({ ...fixture.settlementProof, rootAttestation }))
);
const arbiter = await evaluateDeliveryArbiter(
  {
    origin: 'https://seller.base.example',
    reservationId: validPreSign.reservationId,
    challenge: validPreSign.challenge,
    request: { url: 'https://seller.base.example/v1/market-feed', method: 'GET', body: '' },
    response: {
      status: 200,
      headers: { 'payment-receipt': receiptHeader, 'payment-settlement-proof': proofHeader }
    },
    body: JSON.stringify(payload)
  },
  {
    ledger,
    expectedIssuerPublicKeys: [sellerKp.publicKey],
    trustedRootPublicKeys: [witnessKp.publicKey],
    allowUncheckedSettlementClaim: false
  }
);

console.log(`  • Base Block #${fixture.blockNumber} Consensus receiptsRoot: ${fixture.receiptsRoot}`);
console.log(`  ✓ Offline Verify (${elapsedMs} ms, 0 RPC calls): valid=${verified.valid}, trustState=${verified.trustState}`);
console.log(`  ✓ Checks: settlement=${verified.checks.settlement}, proof=${verified.checks.proof}, outputHash=${verified.checks.outputHash}`);
console.log(`  ✓ Strict Gate 2 Escrow Arbiter: action=${arbiter.action} (${arbiter.reasonCode})`);
console.log('========================================================================');
