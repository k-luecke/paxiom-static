// Generates real Ed25519 paxiom.receipt.v0 fixtures.
//
// MANUAL REGENERATION TOOL — NON-DETERMINISTIC BY DESIGN.
// Each run mints a FRESH Ed25519 keypair and DISCARDS the private key, so the
// signatures (and embedded publicKey) change every run. This is intentional: no
// private key is ever committed. The consequence is that rerunning this rewrites
// examples/*.json with new signatures and produces a churny git diff.
//
// The committed fixtures under ../examples ARE the canonical test vectors. Do NOT
// regenerate them as part of validation or CI. Only run this when you deliberately
// want new fixtures, and commit the result as an intentional change.
// validate.mjs is read-only and NEVER writes fixtures.
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';

const OUT = process.argv[2]; // examples dir

// --- Paxiom v0 canonical JSON profile ---
// UTF-8, object keys sorted lexicographically (recursive), array order preserved,
// no insignificant whitespace, strings for money/hashes.
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
const sha256hex = (buf) => '0x' + crypto.createHash('sha256').update(buf).digest('hex');
const hashCanonical = (obj) => sha256hex(Buffer.from(canonicalize(obj), 'utf8'));

// --- the delivered output (shared by both receipt fixtures) ---
const output = {
  demo: true,
  message: 'Paxiom receipt demo output. This is the bytes the payment bought.',
  service: 'Paxiom Receipt Demo',
  value: '42'
};
writeFileSync(`${OUT}/valid.output.json`, JSON.stringify(output, null, 2) + '\n');

// a DIFFERENT output whose hash will NOT match the receipt -> output_hash_mismatch
const mismatchOutput = { ...output, value: '43', tampered: true };
writeFileSync(`${OUT}/output-mismatch.output.json`, JSON.stringify(mismatchOutput, null, 2) + '\n');

// --- request preimages (self-consistent demo values) ---
const requestBody = { block: '21000000', contract: '0xabc0000000000000000000000000000000000001', slot: '0x0' };
const method = 'POST';
const resource = 'https://paxiom.org/v1/receipt/demo';
const bodyHash = hashCanonical(requestBody);
const resourceHash = sha256hex(Buffer.from(resource, 'utf8'));
const requestHash = hashCanonical({ bodyHash, method, resource });

// --- payment preimages ---
const paymentRequirements = { asset: 'USDC', maxAmountRequired: '1000', network: 'base', payTo: '0xPAX0000000000000000000000000000000000abcd', scheme: 'exact' };
const paymentPayload = { authorization: 'demo-authorization-blob', network: 'base', scheme: 'exact' };
const paymentRequirementsHash = hashCanonical(paymentRequirements);
const paymentPayloadHash = hashCanonical(paymentPayload);

const outputHash = hashCanonical(output);

// --- Ed25519 keypair (private key discarded after signing) ---
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const jwk = publicKey.export({ format: 'jwk' }); // { kty:'OKP', crv:'Ed25519', x: base64url }
const rawPub = Buffer.from(jwk.x, 'base64url');   // 32-byte raw public key
const publicKeyB64 = rawPub.toString('base64');
const keyId = 'paxiom-demo-key-001';

function buildReceipt({ receiptId, settlement }) {
  const payload = {
    receiptId,
    issuedAt: '2026-07-07T00:00:00.000Z',
    issuer: { name: 'paxiom-demo', uri: 'https://paxiom.org', keyId },
    service: { name: 'Paxiom Receipt Demo', resource, method },
    request: { requestHash, resourceHash, bodyHash },
    payment: {
      scheme: 'x402',
      network: 'base',
      asset: 'USDC',
      amountAtomic: '1000',
      amountDisplay: '0.001',
      paymentRequirementsHash,
      paymentPayloadHash,
      settlement
    },
    delivery: { outputHash, mimeType: 'application/json' },
    evidence: [{ type: 'none', status: 'not_provided', hash: null, uri: null }]
  };
  const signingInput = Buffer.from(canonicalize({ receiptVersion: 'paxiom.receipt.v0', payload }), 'utf8');
  const value = crypto.sign(null, signingInput, privateKey).toString('base64');
  return {
    receiptVersion: 'paxiom.receipt.v0',
    payload,
    signature: { algorithm: 'ed25519', keyId, publicKey: publicKeyB64, value }
  };
}

// valid receipt: verify-only x402 mode -> reaches trust state `verified` offline
const validReceipt = buildReceipt({
  receiptId: 'rcpt_demo_001',
  settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false }
});
writeFileSync(`${OUT}/valid.receipt.json`, JSON.stringify(validReceipt, null, 2) + '\n');

// claimed-not-checked receipt: asserts an onchain settlement Paxiom did NOT verify
const claimedReceipt = buildReceipt({
  receiptId: 'rcpt_demo_002',
  settlement: {
    status: 'claimed_not_checked',
    transactionHash: '0x' + '11'.repeat(32),
    checkedByPaxiom: false
  }
});
writeFileSync(`${OUT}/settlement-claimed-not-checked.receipt.json`, JSON.stringify(claimedReceipt, null, 2) + '\n');

// self-verify both signatures to prove the fixtures are real
for (const [name, r] of [['valid', validReceipt], ['claimed', claimedReceipt]]) {
  const si = Buffer.from(canonicalize({ receiptVersion: r.receiptVersion, payload: r.payload }), 'utf8');
  const ok = crypto.verify(null, si, crypto.createPublicKey({ format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: rawPub.toString('base64url') } }),
    Buffer.from(r.signature.value, 'base64'));
  console.log(`${name} signature self-verify: ${ok}`);
}
console.log('outputHash', outputHash);
console.log('publicKey(b64)', publicKeyB64);
