// Validation pass for paxiom.receipt.v0 spec — no external deps.
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

const DIR = 'standards/receipts/v0';
const EX = `${DIR}/examples`;
let fails = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fails++; };

function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
const sha256hex = (b) => '0x' + crypto.createHash('sha256').update(b).digest('hex');
const load = (p) => JSON.parse(readFileSync(p, 'utf8'));

// 1. all JSON parses
const files = ['paxiom.receipt.v0.schema.json'].map(f => `${DIR}/${f}`)
  .concat(['valid.output.json','valid.receipt.json','output-mismatch.output.json','settlement-claimed-not-checked.receipt.json'].map(f => `${EX}/${f}`));
let parsed = {};
for (const f of files) { try { parsed[f] = load(f); ok(true, `valid JSON: ${f}`); } catch (e) { ok(false, `valid JSON: ${f} — ${e.message}`); } }

const schema = parsed[`${DIR}/paxiom.receipt.v0.schema.json`];
const validReceipt = parsed[`${EX}/valid.receipt.json`];
const claimed = parsed[`${EX}/settlement-claimed-not-checked.receipt.json`];
const output = parsed[`${EX}/valid.output.json`];
const mismatch = parsed[`${EX}/output-mismatch.output.json`];

// 2. minimal draft-07 validator (covers the constructs this schema uses)
function validate(node, sch, path = '') {
  const errs = [];
  const t = sch.type;
  const typeof2 = (v) => Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v;
  if (t === 'object') {
    if (typeof2(node) !== 'object') return [`${path}: expected object`];
    if (sch.required) for (const r of sch.required) if (!(r in node)) errs.push(`${path}.${r}: required`);
    if (sch.additionalProperties === false) for (const k of Object.keys(node)) if (!(sch.properties && k in sch.properties)) errs.push(`${path}.${k}: additional property not allowed`);
    if (sch.properties) for (const [k, s] of Object.entries(sch.properties)) if (k in node) errs.push(...validate(node[k], s, `${path}.${k}`));
  } else if (t === 'array') {
    if (typeof2(node) !== 'array') return [`${path}: expected array`];
    if (sch.items) node.forEach((it, i) => errs.push(...validate(it, sch.items, `${path}[${i}]`)));
  } else if (t === 'string') {
    if (typeof node !== 'string') return [`${path}: expected string`];
    if (sch.minLength && node.length < sch.minLength) errs.push(`${path}: too short`);
    if (sch.const && node !== sch.const) errs.push(`${path}: expected const ${sch.const}`);
    if (sch.enum && !sch.enum.includes(node)) errs.push(`${path}: not in enum`);
    if (sch.pattern && !new RegExp(sch.pattern).test(node)) errs.push(`${path}: pattern ${sch.pattern}`);
  } else if (t === 'boolean') {
    if (typeof node !== 'boolean') errs.push(`${path}: expected boolean`);
  } else if (t === 'null') {
    if (node !== null) errs.push(`${path}: expected null`);
  }
  if (sch.$ref) { const def = sch.$ref.split('/').slice(1).reduce((o, k) => o[k], schema); errs.push(...validate(node, def, path)); }
  if (sch.oneOf) { const passes = sch.oneOf.filter(s => validate(node, s, path).length === 0).length; if (passes !== 1) errs.push(`${path}: oneOf matched ${passes}`); }
  return errs;
}

for (const [name, r] of [['valid.receipt.json', validReceipt], ['settlement-claimed-not-checked.receipt.json', claimed]]) {
  const errs = validate(r, schema, name);
  ok(errs.length === 0, `schema conformance: ${name}` + (errs.length ? ` — ${errs.slice(0,4).join('; ')}` : ''));
}

// 3. cross-file consistency: outputHash matches canonical(valid.output.json)
ok(validReceipt.payload.delivery.outputHash === sha256hex(Buffer.from(canonicalize(output), 'utf8')), 'valid.receipt outputHash == sha256(canonical(valid.output))');
ok(claimed.payload.delivery.outputHash === sha256hex(Buffer.from(canonicalize(output), 'utf8')), 'claimed.receipt outputHash == sha256(canonical(valid.output))');
ok(sha256hex(Buffer.from(canonicalize(mismatch), 'utf8')) !== validReceipt.payload.delivery.outputHash, 'output-mismatch hash != receipt outputHash (drives output_hash_mismatch)');

// 4. signatures actually verify with only the embedded public key
function verify(r) {
  const si = Buffer.from(canonicalize({ receiptVersion: r.receiptVersion, payload: r.payload }), 'utf8');
  const pub = crypto.createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(r.signature.publicKey, 'base64').toString('base64url') } });
  return crypto.verify(null, si, pub, Buffer.from(r.signature.value, 'base64'));
}
ok(verify(validReceipt), 'valid.receipt.json Ed25519 signature verifies');
ok(verify(claimed), 'settlement-claimed-not-checked.receipt.json Ed25519 signature verifies');

// 5. tamper detection: flip a payload byte -> signature must fail
const tampered = JSON.parse(JSON.stringify(validReceipt));
tampered.payload.delivery.mimeType = 'text/plain';
ok(!verify(tampered), 'tampered receipt signature fails (as expected)');

// 6. settlement statuses are within the schema enum
const enumVals = schema.properties.payload.properties.payment.properties.settlement.properties.status.enum;
ok(enumVals.includes(validReceipt.payload.payment.settlement.status), `valid settlement status in enum (${validReceipt.payload.payment.settlement.status})`);
ok(enumVals.includes(claimed.payload.payment.settlement.status), `claimed settlement status in enum (${claimed.payload.payment.settlement.status})`);

console.log(`\n${fails === 0 ? 'ALL CHECKS PASS' : fails + ' CHECK(S) FAILED'}`);
process.exit(fails === 0 ? 0 : 1);
