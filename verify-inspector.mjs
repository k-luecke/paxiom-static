// Client-side WebCrypto Receipt & x402 Header Inspector for paxiom.org/verify.html.
// Runs 100% locally via @paxiom/receipts/web (globalThis.crypto.subtle Ed25519 + SHA-256).
// Enforced by CSP `connect-src 'none'`: zero bytes ever leave the browser.

import {
  PAXIOM_LIVE_VERIFIER_PUBLIC_KEY,
  verifyReceipt,
  decodeReceiptHeader,
  parseX402Headers,
  canonicalize,
  generateReceiptKeyPair,
  issueReceipt,
  explain
} from './standards/receipts/v0/src/web.mjs';

const DEMO_OUTPUT = {
  demo: true,
  message: 'Paxiom receipt demo output. This is the bytes the payment bought.',
  service: 'Paxiom Receipt Demo',
  value: '42'
};

const VALID_FIXTURE = {
  receiptVersion: 'paxiom.receipt.v0',
  payload: {
    receiptId: 'rcpt_demo_001',
    issuedAt: '2026-07-07T00:00:00.000Z',
    issuer: {
      name: 'paxiom-demo',
      uri: 'https://paxiom.org',
      keyId: 'paxiom-demo-key-001'
    },
    service: {
      name: 'Paxiom Receipt Demo',
      resource: 'https://paxiom.org/v1/receipt/demo',
      method: 'POST'
    },
    request: {
      requestHash: '0x47c86b42d0b761b96ed6676406d9a2e96a73184c76bbff3836b66a9af092ec7a',
      resourceHash: '0xbcf52e751d2733e071e21ad9cd4206445f64602768574de002d0048474f50286',
      bodyHash: '0x8370e9bafcfa99853ed5c209559b1130ad125a7155ebc824746b95fdd26b2d1d'
    },
    payment: {
      scheme: 'x402',
      network: 'base',
      asset: 'USDC',
      amountAtomic: '1000',
      amountDisplay: '0.001',
      paymentRequirementsHash: '0x810c301531f1fbea54af8678c9da442ef218920c66169a6f8ea2e6bcea65d699',
      paymentPayloadHash: '0xc387405a4fab105788f3926832694243e0f4ed658b17fe8f2713dcb907fb3df6',
      settlement: {
        status: 'verify_only',
        transactionHash: null,
        checkedByPaxiom: false
      }
    },
    delivery: {
      outputHash: '0x36b33b7db29c8eacf3acc6bbff312ebbeabbaf53b70b956b5fc02d2c1281baf6',
      mimeType: 'application/json'
    },
    evidence: [
      {
        type: 'none',
        status: 'not_provided',
        hash: null,
        uri: null
      }
    ]
  },
  signature: {
    algorithm: 'ed25519',
    keyId: 'paxiom-demo-key-001',
    publicKey: 'cZASqM+TIUtIt4+ejhPvIOYxOeDBX/ofbG86H/NNLpQ=',
    value: 'P/1YDKMwtFmODNZ8p449sdpRdOJILW2Yc07lSInDu8+jMWdsdS8c+om/RTQnXvy0t9tdHmGcqimX/Wu4Nan9Cw=='
  }
};

const CLAIMED_FIXTURE = {
  receiptVersion: 'paxiom.receipt.v0',
  payload: {
    ...VALID_FIXTURE.payload,
    receiptId: 'rcpt_demo_002',
    payment: {
      ...VALID_FIXTURE.payload.payment,
      settlement: {
        status: 'claimed_not_checked',
        transactionHash: '0x1111111111111111111111111111111111111111111111111111111111111111',
        checkedByPaxiom: false
      }
    }
  },
  signature: {
    algorithm: 'ed25519',
    keyId: 'paxiom-demo-key-001',
    publicKey: 'cZASqM+TIUtIt4+ejhPvIOYxOeDBX/ofbG86H/NNLpQ=',
    value: 'Nl2meYXMO4e/mrD1A9AC3vh2JB9eSnooQrwZ/RTo2rx0l57rnJ1aNWhvDg3sFU0MDw1sEmq3x1NoHFWIG5OlCQ=='
  }
};

const CHECK_LABELS = [
  ['schema', 'Schema (draft-07)'],
  ['signature', 'Ed25519 signature'],
  ['issuerAuthorization', 'Signer authorization'],
  ['outputHash', 'Output hash binding'],
  ['requestBinding', 'Request binding'],
  ['paymentBinding', 'Payment binding'],
  ['settlement', 'Settlement status'],
  ['proof', 'Proof / evidence']
];

function byId(id) {
  return document.getElementById(id);
}

function parseReceiptInput(rawText) {
  const trimmed = String(rawText || '').trim();
  if (!trimmed) {
    throw new Error('Paste a Payment-Receipt / X-Paxiom-Receipt header value or a paxiom.receipt.v0 JSON object.');
  }
  if (trimmed.startsWith('{')) {
    return { receipt: JSON.parse(trimmed), sourceFormat: 'JSON envelope' };
  }
  const stripped = trimmed.replace(/^(?:payment-receipt|x-paxiom-receipt)\s*:\s*/i, '').trim();
  return { receipt: decodeReceiptHeader(stripped), sourceFormat: 'Base64url HTTP header' };
}

function renderBadgeClass(result) {
  if (result.valid) return 'verdict-badge pass';
  if (
    result.trustState === 'settlement_claimed_not_checked' ||
    result.trustState === 'valid_signature_only'
  ) {
    return 'verdict-badge warn';
  }
  return 'verdict-badge fail';
}

function renderCheckPillClass(val) {
  if (val === 'pass' || val === 'not_required' || val === 'verify_only' || val === 'verified_settled') {
    return 'check-val pass';
  }
  if (val === 'fail' || val === 'error' || val === 'failed' || val === 'invalid') {
    return 'check-val fail';
  }
  return 'check-val neutral';
}

async function runVerification() {
  const receiptInput = byId('receipt-input').value;
  const outputInput = byId('output-input').value;
  const keysInput = byId('expected-keys-input').value;
  const payToInput = byId('expected-payto-input').value;
  const trustPaxiom = byId('trust-paxiom-root').checked;

  const badgeEl = byId('verdict-badge');
  const timingEl = byId('verdict-timing');
  const summaryEl = byId('verdict-summary');
  const hashEl = byId('verdict-hash');
  const checksGrid = byId('checks-grid');
  const decodedPre = byId('decoded-receipt');
  const explainPre = byId('explain-output');

  const t0 = performance.now();
  let parsed;
  try {
    parsed = parseReceiptInput(receiptInput);
  } catch (err) {
    badgeEl.className = 'verdict-badge fail';
    badgeEl.textContent = 'MALFORMED INPUT';
    timingEl.textContent = `${(performance.now() - t0).toFixed(2)} ms · local parse`;
    summaryEl.textContent = String((err && err.message) || err);
    hashEl.textContent = '—';
    checksGrid.replaceChildren();
    decodedPre.textContent = '';
    explainPre.textContent = '';
    return;
  }

  const { receipt, sourceFormat } = parsed;
  const opts = {};

  const trimmedOut = outputInput.trim();
  if (trimmedOut !== '') {
    const mode = receipt?.payload?.delivery?.canonicalization || 'jcs-sha256';
    if (mode === 'raw-sha256') {
      opts.output = outputInput;
    } else {
      try {
        opts.output = JSON.parse(trimmedOut);
      } catch (err) {
        badgeEl.className = 'verdict-badge fail';
        badgeEl.textContent = 'INVALID OUTPUT JSON';
        timingEl.textContent = `${(performance.now() - t0).toFixed(2)} ms · local parse`;
        summaryEl.textContent = `Delivered output could not be parsed as JSON for jcs-sha256 verification: ${(err && err.message) || err}`;
        hashEl.textContent = '—';
        checksGrid.replaceChildren();
        decodedPre.textContent = JSON.stringify(receipt, null, 2);
        explainPre.textContent = '';
        return;
      }
    }
  }

  const keyList = keysInput
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (keyList.length > 0) {
    opts.expectedIssuerPublicKeys = keyList;
  }
  if (payToInput.trim() !== '') {
    opts.expectedPayTo = payToInput.trim();
  }
  if (trustPaxiom) {
    opts.trustedVerifierPublicKeys = [PAXIOM_LIVE_VERIFIER_PUBLIC_KEY];
  }

  const result = await verifyReceipt(receipt, opts);
  const elapsedMs = (performance.now() - t0).toFixed(2);

  badgeEl.className = renderBadgeClass(result);
  badgeEl.textContent = result.valid ? '✓ VERIFIED' : `✗ ${String(result.trustState).toUpperCase()}`;
  timingEl.textContent = `${elapsedMs} ms · WebCrypto Ed25519 · ${sourceFormat}`;
  summaryEl.textContent = result.summary;
  hashEl.textContent = result.receiptHash || '—';

  const rows = [];
  for (const [key, label] of CHECK_LABELS) {
    if (!result.checks || !Object.hasOwn(result.checks, key)) continue;
    const row = document.createElement('div');
    row.className = 'check-row';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'check-name';
    nameSpan.textContent = label;
    const valSpan = document.createElement('span');
    valSpan.className = renderCheckPillClass(result.checks[key]);
    valSpan.textContent = result.checks[key];
    row.append(nameSpan, valSpan);
    rows.push(row);
  }
  checksGrid.replaceChildren(...rows);

  decodedPre.textContent = JSON.stringify(receipt, null, 2);
  try {
    const canonSigning = canonicalize({
      receiptVersion: receipt.receiptVersion,
      payload: receipt.payload
    });
    explainPre.textContent = `${explain(result)}\n\nCanonical signing preimage (${canonSigning.length} UTF-8 bytes):\n${canonSigning}`;
  } catch {
    explainPre.textContent = explain(result);
  }
}

function runX402Decode() {
  const sigVal = byId('x402-sig-input').value.trim();
  const resVal = byId('x402-res-input').value.trim();
  const outEl = byId('x402-decoded-output');
  if (!sigVal && !resVal) {
    outEl.textContent = 'Paste a base64 PAYMENT-SIGNATURE and/or PAYMENT-RESPONSE header above to inspect normalized CAIP-2 fields.';
    return;
  }
  const parsed = parseX402Headers({
    paymentSignature: sigVal,
    paymentResponse: resVal
  });
  outEl.textContent = JSON.stringify(parsed, null, 2);
}

function loadPreset(kind) {
  if (kind === 'valid') {
    byId('receipt-input').value = JSON.stringify(VALID_FIXTURE, null, 2);
    byId('output-input').value = JSON.stringify(DEMO_OUTPUT, null, 2);
    byId('expected-keys-input').value = VALID_FIXTURE.signature.publicKey;
    byId('expected-payto-input').value = '';
    return runVerification();
  }
  if (kind === 'claimed') {
    byId('receipt-input').value = JSON.stringify(CLAIMED_FIXTURE, null, 2);
    byId('output-input').value = JSON.stringify(DEMO_OUTPUT, null, 2);
    byId('expected-keys-input').value = CLAIMED_FIXTURE.signature.publicKey;
    byId('expected-payto-input').value = '';
    return runVerification();
  }
  if (kind === 'tampered') {
    byId('receipt-input').value = JSON.stringify(VALID_FIXTURE, null, 2);
    byId('output-input').value = JSON.stringify({ ...DEMO_OUTPUT, value: '999999' }, null, 2);
    byId('expected-keys-input').value = VALID_FIXTURE.signature.publicKey;
    byId('expected-payto-input').value = '';
    return runVerification();
  }
  return Promise.resolve();
}

async function mintFreshInBrowser() {
  const kp = await generateReceiptKeyPair({ keyId: 'browser-ephemeral-01' });
  const payTo = '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4';
  const freshOutput = {
    ok: true,
    mintedInBrowser: true,
    issuedAt: new Date().toISOString(),
    runtime: 'WebCrypto Ed25519 (connect-src none)'
  };
  const { receiptHeader } = await issueReceipt({
    privateKey: kp.privateKeyPem,
    issuer: {
      name: 'Browser Demo Seller',
      uri: 'https://paxiom.org',
      keyId: kp.keyId,
      payTo
    },
    service: {
      name: 'Local WebCrypto Demo',
      resource: 'https://seller.example/v1/infer',
      method: 'POST'
    },
    request: {
      method: 'POST',
      resource: 'https://seller.example/v1/infer',
      body: JSON.stringify({ prompt: 'verify-delivery' })
    },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amountAtomic: '20000',
      amountDisplay: '0.02',
      payTo,
      settlement: {
        status: 'verify_only',
        transactionHash: null,
        checkedByVerifier: false
      }
    },
    output: freshOutput,
    statusCode: 200
  });

  byId('receipt-input').value = `Payment-Receipt: ${receiptHeader}`;
  byId('output-input').value = JSON.stringify(freshOutput, null, 2);
  byId('expected-keys-input').value = kp.publicKey;
  byId('expected-payto-input').value = payTo;
  await runVerification();
}

function init() {
  const supportEl = byId('webcrypto-support');
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    supportEl.textContent = 'WebCrypto unavailable in this browser context';
    return;
  }
  supportEl.textContent = 'Active · WebCrypto Ed25519 + SHA-256 · CSP connect-src \'none\' (zero network calls)';

  byId('btn-verify').addEventListener('click', () => { runVerification(); });
  byId('btn-preset-valid').addEventListener('click', () => { loadPreset('valid'); });
  byId('btn-preset-claimed').addEventListener('click', () => { loadPreset('claimed'); });
  byId('btn-preset-tampered').addEventListener('click', () => { loadPreset('tampered'); });
  byId('btn-preset-mint').addEventListener('click', () => { mintFreshInBrowser(); });
  byId('btn-decode-x402').addEventListener('click', () => { runX402Decode(); });

  loadPreset('valid');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
