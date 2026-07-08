// Human-readable rendering of a verifier result. Pure formatting — no logic.
const LABEL = {
  schema: 'Schema',
  signature: 'Signature',
  outputHash: 'Output binding',
  requestBinding: 'Request binding',
  paymentBinding: 'Payment binding',
  settlement: 'Settlement',
  proof: 'Proof / evidence'
};

export function explain(result) {
  const mark = result.valid ? 'VERIFIED' : result.trustState.toUpperCase();
  const lines = [];
  lines.push(`${result.valid ? '✓' : '✗'} ${mark}`);
  lines.push('');
  for (const [key, label] of Object.entries(LABEL)) {
    if (key in result.checks) lines.push(`  ${label.padEnd(16)} ${result.checks[key]}`);
  }
  lines.push('');
  if (result.receiptHash) lines.push(`  receiptHash      ${result.receiptHash}`);
  lines.push('');
  lines.push(result.summary);
  return lines.join('\n');
}
