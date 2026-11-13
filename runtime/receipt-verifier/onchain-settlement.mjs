// Zero-dependency on-chain EVM USDC settlement verifier for Base & Base Sepolia.
//
// Confirms that a receipt's claimed `transactionHash` actually succeeded on-chain,
// reached `minConfirmations`, and emitted an ERC-20 `Transfer(from, to, value)` log
// from the canonical USDC contract >= `amountAtomic` (and matching `expectedPayTo`
// when supplied).

export const ERC20_TRANSFER_TOPIC0 =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export const NETWORK_CONFIGS = {
  base: {
    chainIdHex: '0x2105',
    caip2: 'eip155:8453',
    usdcAddress: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    rpcEnvVar: 'BASE_RPC_URL'
  },
  'eip155:8453': {
    chainIdHex: '0x2105',
    caip2: 'eip155:8453',
    usdcAddress: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    rpcEnvVar: 'BASE_RPC_URL'
  },
  'base-sepolia': {
    chainIdHex: '0x14a34',
    caip2: 'eip155:84532',
    usdcAddress: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    rpcEnvVar: 'BASE_SEPOLIA_RPC_URL'
  },
  'eip155:84532': {
    chainIdHex: '0x14a34',
    caip2: 'eip155:84532',
    usdcAddress: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    rpcEnvVar: 'BASE_SEPOLIA_RPC_URL'
  }
};

function normalizeAddressFromTopic(topicHex) {
  if (typeof topicHex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(topicHex)) return null;
  return '0x' + topicHex.slice(26).toLowerCase();
}

async function rpcCall(rpcUrl, method, params, fetchImpl, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`RPC HTTP ${res.status}`);
    }
    const body = await res.json();
    if (body.error) {
      throw new Error(`RPC error: ${body.error.message || JSON.stringify(body.error)}`);
    }
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify a receipt's claimed USDC settlement transaction on-chain via JSON-RPC.
 */
export async function verifyOnchainUsdcSettlement(receipt, {
  env = process.env,
  fetchImpl = globalThis.fetch,
  expectedPayTo = null,
  minConfirmations = 1
} = {}) {
  const payment = receipt && receipt.payload && receipt.payload.payment;
  if (!payment || !payment.settlement || !payment.settlement.transactionHash) {
    return {
      checked: false,
      settled: false,
      reason: 'missing_transaction_hash',
      detail: 'Receipt does not contain a settlement.transactionHash to verify on-chain.'
    };
  }

  const netKey = String(payment.network || '').toLowerCase();
  const netCfg = NETWORK_CONFIGS[netKey];
  if (!netCfg) {
    return {
      checked: false,
      settled: false,
      reason: 'unsupported_network',
      detail: `Unsupported payment.network "${payment.network}" for live on-chain verification.`
    };
  }

  if (String(payment.asset || '').toUpperCase() !== 'USDC' &&
      String(payment.asset || '').toLowerCase() !== netCfg.usdcAddress) {
    return {
      checked: false,
      settled: false,
      reason: 'unsupported_asset',
      detail: `Unsupported payment.asset "${payment.asset}"; v0 live verifier checks canonical USDC.`
    };
  }

  const rpcUrl = env[netCfg.rpcEnvVar];
  if (!rpcUrl) {
    return {
      checked: false,
      settled: false,
      reason: 'rpc_unconfigured',
      detail: `RPC endpoint env var ${netCfg.rpcEnvVar} is not configured on this verifier.`
    };
  }

  const txHash = payment.settlement.transactionHash.toLowerCase();
  const [txReceipt, latestBlockHex] = await Promise.all([
    rpcCall(rpcUrl, 'eth_getTransactionReceipt', [txHash], fetchImpl),
    rpcCall(rpcUrl, 'eth_blockNumber', [], fetchImpl)
  ]);

  if (!txReceipt) {
    return {
      checked: true,
      settled: false,
      reason: 'tx_not_found',
      detail: `Transaction ${txHash} was not found on ${netCfg.caip2}.`
    };
  }

  if (String(txReceipt.status).toLowerCase() !== '0x1') {
    return {
      checked: true,
      settled: false,
      reason: 'tx_reverted',
      detail: `Transaction ${txHash} reverted on ${netCfg.caip2} (status=${txReceipt.status}).`
    };
  }

  const txBlock = BigInt(txReceipt.blockNumber);
  const headBlock = BigInt(latestBlockHex);
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock + 1n) : 0;
  if (confirmations < minConfirmations) {
    return {
      checked: true,
      settled: false,
      reason: 'insufficient_confirmations',
      confirmations,
      detail: `Transaction ${txHash} has ${confirmations} confirmations (requires ${minConfirmations}).`
    };
  }

  const requiredAmount = BigInt(payment.amountAtomic);
  const wantTo = expectedPayTo ? String(expectedPayTo).toLowerCase() : null;
  const logs = Array.isArray(txReceipt.logs) ? txReceipt.logs : [];

  const matchingTransfers = [];
  for (const log of logs) {
    if (!log || String(log.address || '').toLowerCase() !== netCfg.usdcAddress) continue;
    const topics = Array.isArray(log.topics) ? log.topics : [];
    if (String(topics[0] || '').toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
    const from = normalizeAddressFromTopic(topics[1]);
    const to = normalizeAddressFromTopic(topics[2]);
    if (!from || !to) continue;
    const value = BigInt(log.data && log.data !== '0x' ? log.data : '0x0');
    if (value < requiredAmount) continue;
    if (wantTo && to !== wantTo) continue;
    matchingTransfers.push({ from, to, amountAtomic: value.toString() });
  }

  if (matchingTransfers.length === 0) {
    return {
      checked: true,
      settled: false,
      reason: 'matching_usdc_transfer_not_found',
      confirmations,
      detail: `Transaction ${txHash} succeeded, but no canonical USDC Transfer >= ${payment.amountAtomic}${wantTo ? ` to ${wantTo}` : ''} was emitted.`
    };
  }

  return {
    checked: true,
    settled: true,
    network: netCfg.caip2,
    transactionHash: txHash,
    blockNumber: txBlock.toString(),
    confirmations,
    matchedTransfer: matchingTransfers[0]
  };
}
