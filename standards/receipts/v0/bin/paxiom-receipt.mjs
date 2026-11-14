#!/usr/bin/env node
// paxiom-receipt — CLI for paxiom.receipt.v0 (verify, issue, keygen).
import { readFileSync, writeFileSync } from 'node:fs';
import { verifyFromFiles } from '../src/verify.mjs';
import { generateReceiptKeyPair, issueReceipt } from '../src/issue.mjs';
import { explain } from '../src/explain.mjs';

const USAGE = `paxiom-receipt — CLI for paxiom.receipt.v0

Usage:
  paxiom-receipt verify <receipt.json> [--output <output.json>] [--trusted-paxiom-key <pubKeyB64>] [--json]
  paxiom-receipt keygen [--key-id <id>] [--out <private.pem>]
  paxiom-receipt issue  --key <private.pem> --issuer-name <name> --key-id <id> --resource <url> --output <output.json> [--method POST] [--tx <0x...>] [--out <receipt.json>]

Exit codes:
  0  success (for verify: trustState === "verified")
  1  verification ran, trustState !== "verified"
  2  usage / IO error
`;

const VALUE_FLAGS = new Set([
  '--output', '-o', '--trusted-paxiom-key', '--key', '--key-id',
  '--issuer-name', '--service-name', '--resource', '--method', '--tx',
  '--amount-atomic', '--amount-display', '--network', '--out'
]);

function requireFlagValue(argv, index, flag) {
  const val = argv[index + 1];
  if (val === undefined || val === '' || val.startsWith('-')) {
    process.stderr.write(`Missing value for flag ${flag}\n\n${USAGE}`);
    process.exit(2);
  }
  return val;
}

function parseArgs(argv) {
  const args = { _: [], json: false, trustedKeys: [], hasOutFlag: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (VALUE_FLAGS.has(a)) {
      const val = requireFlagValue(argv, i, a);
      i++;
      if (a === '--output' || a === '-o') args.output = val;
      else if (a === '--trusted-paxiom-key') args.trustedKeys.push(val);
      else if (a === '--key') args.key = val;
      else if (a === '--key-id') args.keyId = val;
      else if (a === '--issuer-name') args.issuerName = val;
      else if (a === '--service-name') args.serviceName = val;
      else if (a === '--resource') args.resource = val;
      else if (a === '--method') args.method = val;
      else if (a === '--tx') args.tx = val;
      else if (a === '--amount-atomic') args.amountAtomic = val;
      else if (a === '--amount-display') args.amountDisplay = val;
      else if (a === '--network') args.network = val;
      else if (a === '--out') { args.out = val; args.hasOutFlag = true; }
    } else if (a === '--json') args.json = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else args._.push(a);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args._.length === 0) {
    process.stdout.write(USAGE);
    process.exit(args.help ? 0 : 2);
  }
  const [cmd, arg1] = args._;

  if (cmd === 'keygen') {
    const kp = generateReceiptKeyPair({ keyId: args.keyId });
    if (args.out) {
      writeFileSync(args.out, kp.privateKeyPem, { mode: 0o600 });
      process.stdout.write(JSON.stringify({
        keyId: kp.keyId,
        algorithm: kp.algorithm,
        publicKey: kp.publicKey,
        privateKeyPath: args.out
      }, null, 2) + '\n');
    } else {
      process.stdout.write(JSON.stringify(kp, null, 2) + '\n');
    }
    process.exit(0);
  }

  if (cmd === 'issue') {
    if (!args.key || !args.issuerName || !args.keyId || !args.resource || !args.output) {
      process.stderr.write(`issue requires --key, --issuer-name, --key-id, --resource, and --output\n\n${USAGE}`);
      process.exit(2);
    }
    try {
      const privateKey = readFileSync(args.key, 'utf8');
      const output = JSON.parse(readFileSync(args.output, 'utf8'));
      const { receipt } = issueReceipt({
        privateKey,
        issuer: { name: args.issuerName, keyId: args.keyId },
        service: {
          name: args.serviceName || args.issuerName,
          resource: args.resource,
          method: args.method || 'POST'
        },
        payment: {
          network: args.network || 'base',
          amountAtomic: args.amountAtomic || '0',
          amountDisplay: args.amountDisplay || '0',
          settlement: args.tx
            ? { status: 'claimed_not_checked', transactionHash: args.tx, checkedByPaxiom: false }
            : { status: 'verify_only', transactionHash: null, checkedByPaxiom: false }
        },
        output
      });
      const serialized = JSON.stringify(receipt, null, 2) + '\n';
      if (args.out) writeFileSync(args.out, serialized);
      else process.stdout.write(serialized);
      process.exit(0);
    } catch (err) {
      process.stderr.write(`Failed to issue receipt: ${(err && err.message) || err}\n`);
      process.exit(2);
    }
  }

  if (cmd !== 'verify') {
    process.stderr.write(`Unknown command: ${cmd}\n\n${USAGE}`);
    process.exit(2);
  }
  if (!arg1) {
    process.stderr.write(`verify requires a <receipt.json> path\n\n${USAGE}`);
    process.exit(2);
  }

  let result;
  try {
    const extraOpts = args.trustedKeys.length > 0
      ? { trustedPaxiomPublicKeys: args.trustedKeys }
      : {};
    result = verifyFromFiles(arg1, args.output, extraOpts);
  } catch (err) {
    result = { valid: false, trustState: 'error', checks: {}, receiptHash: null, summary: String((err && err.message) || err) };
    process.stdout.write(args.json ? JSON.stringify(result, null, 2) + '\n' : explain(result) + '\n');
    process.exit(2);
  }

  process.stdout.write(args.json ? JSON.stringify(result, null, 2) + '\n' : explain(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

main();
