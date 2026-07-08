#!/usr/bin/env node
// paxiom-receipt — reference CLI for paxiom.receipt.v0 (developer preview).
// Offline only: verifies a local receipt object. No chain / facilitator / network calls.
import { verifyFromFiles } from '../src/verify.mjs';
import { explain } from '../src/explain.mjs';

const USAGE = `paxiom-receipt — verify a paxiom.receipt.v0 receipt (offline)

Usage:
  paxiom-receipt verify <receipt.json> [--output <output.json>] [--json]

Options:
  --output <file>   delivered output JSON; enables the payment-to-output binding check
  --json            print the raw result object instead of the human-readable report
  -h, --help        show this help

Exit codes:
  0  trustState === "verified"
  1  any other trustState (not verified)
  2  usage / IO error
`;

function parseArgs(argv) {
  const args = { _: [], output: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--output' || a === '-o') args.output = argv[++i];
    else if (a === '--json') args.json = true;
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
  const [cmd, receiptPath] = args._;
  if (cmd !== 'verify') {
    process.stderr.write(`Unknown command: ${cmd}\n\n${USAGE}`);
    process.exit(2);
  }
  if (!receiptPath) {
    process.stderr.write(`verify requires a <receipt.json> path\n\n${USAGE}`);
    process.exit(2);
  }

  let result;
  try {
    result = verifyFromFiles(receiptPath, args.output);
  } catch (err) {
    // verifier-level failure (bad JSON, missing file) -> trustState "error"
    result = { valid: false, trustState: 'error', checks: {}, receiptHash: null, summary: String(err && err.message || err) };
    process.stdout.write(args.json ? JSON.stringify(result, null, 2) + '\n' : explain(result) + '\n');
    process.exit(2);
  }

  process.stdout.write(args.json ? JSON.stringify(result, null, 2) + '\n' : explain(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

main();
