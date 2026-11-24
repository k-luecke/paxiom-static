// Zero-dependency on-chain EVM USDC settlement verifier for Base & Base Sepolia.
//
// Confirms that a receipt's claimed `transactionHash` actually succeeded on-chain,
// reached `minConfirmations`, and emitted an ERC-20 `Transfer(from, to, value)` log
// from the canonical USDC contract >= `amountAtomic` (and matching `expectedPayTo`
// when supplied).

import {
  buildReceiptTrieProof,
  verifyUsdcSettlementProofSync
} from '../../standards/receipts/v0/src/proofs.mjs';

export const ERC20_TRANSFER_TOPIC0 =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_UINT_RE = /^0x[0-9a-fA-F]+$/;
const DEC_UINT_RE = /^[0-9]+$/;
const MAX_BLOCK_RECEIPTS_CACHE = 32;
const blockReceiptsProofCache = new Map();

function getCachedBlockBundle(cacheKey) {
  if (!blockReceiptsProofCache.has(cacheKey)) return null;
  const val = blockReceiptsProofCache.get(cacheKey);
  blockReceiptsProofCache.delete(cacheKey);
  blockReceiptsProofCache.set(cacheKey, val);
  return val;
}

function setCachedBlockBundle(cacheKey, val) {
  if (blockReceiptsProofCache.has(cacheKey)) blockReceiptsProofCache.delete(cacheKey);
  else if (blockReceiptsProofCache.size >= MAX_BLOCK_RECEIPTS_CACHE) {
    const oldest = blockReceiptsProofCache.keys().next().value;
    if (oldest !== undefined) blockReceiptsProofCache.delete(oldest);
  }
  blockReceiptsProofCache.set(cacheKey, val);
}

export const NETWORK_CONFIGS = Object.freeze(Object.assign(Object.create(null), {
  base: Object.freeze({
    chainIdHex: '0x2105',
    caip2: 'eip155:8453',
    usdcAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    eip712Name: 'USD Coin',
    rpcEnvVar: 'BASE_RPC_URL'
  }),
  'eip155:8453': Object.freeze({
    chainIdHex: '0x2105',
    caip2: 'eip155:8453',
    usdcAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    eip712Name: 'USD Coin',
    rpcEnvVar: 'BASE_RPC_URL'
  }),
  'base-sepolia': Object.freeze({
    chainIdHex: '0x14a34',
    caip2: 'eip155:84532',
    usdcAddress: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    eip712Name: 'USDC',
    rpcEnvVar: 'BASE_SEPOLIA_RPC_URL'
  }),
  'eip155:84532': Object.freeze({
    chainIdHex: '0x14a34',
    caip2: 'eip155:84532',
    usdcAddress: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    eip712Name: 'USDC',
    rpcEnvVar: 'BASE_SEPOLIA_RPC_URL'
  })
}));

export function getSupportedNetworkConfig(network) {
  if (typeof network !== 'string' || !network) return null;
  const netKey = network.toLowerCase();
  return Object.hasOwn(NETWORK_CONFIGS, netKey) ? NETWORK_CONFIGS[netKey] : null;
}

function normalizeAddressFromTopic(topicHex) {
  if (typeof topicHex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(topicHex)) return null;
  return '0x' + topicHex.slice(26).toLowerCase();
}

async function rpcCallSingle(rpcUrl, method, params, fetchImpl, timeoutMs = 8000) {
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

async function rpcCall(rpcUrlConfig, method, params, fetchImpl, timeoutMs = 8000) {
  const urls = String(rpcUrlConfig || '')
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean);
  let lastErr = new Error('No RPC URL configured');
  for (const url of urls) {
    try {
      return await rpcCallSingle(url, method, params, fetchImpl, timeoutMs);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * Verify a receipt's claimed USDC settlement transaction on-chain via JSON-RPC.
 */
export async function verifyOnchainUsdcSettlement(receipt, {
  env = process.env,
  fetchImpl = globalThis.fetch,
  expectedPayTo = null,
  minConfirmations = 1,
  includeSettlementProof = false
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

  if (expectedPayTo !== null && expectedPayTo !== undefined && expectedPayTo !== '' &&
      !EVM_ADDRESS_RE.test(String(expectedPayTo))) {
    return {
      checked: false,
      settled: false,
      reason: 'invalid_expected_pay_to',
      detail: 'expectedPayTo must be a 0x-prefixed 20-byte EVM hex address.'
    };
  }

  const netCfg = getSupportedNetworkConfig(String(payment.network || ''));
  if (!netCfg) {
    return {
      checked: false,
      settled: false,
      reason: 'unsupported_network',
      detail: `Unsupported payment.network "${payment.network}" for live on-chain verification.`
    };
  }

  if (String(payment.asset || '').toUpperCase() !== 'USDC' &&
      String(payment.asset || '').toLowerCase() !== netCfg.usdcAddress.toLowerCase()) {
    return {
      checked: false,
      settled: false,
      reason: 'unsupported_asset',
      detail: `Unsupported payment.asset "${payment.asset}"; v0 live verifier checks canonical USDC.`
    };
  }

  if (!DEC_UINT_RE.test(String(payment.amountAtomic ?? ''))) {
    return {
      checked: false,
      settled: false,
      reason: 'invalid_amount_atomic',
      detail: 'Receipt payment.amountAtomic must be a base-10 non-negative integer string.'
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

  if (!txReceipt.blockNumber || !HEX_UINT_RE.test(String(txReceipt.blockNumber))) {
    return {
      checked: true,
      settled: false,
      reason: 'tx_pending',
      confirmations: 0,
      detail: `Transaction ${txHash} is pending block inclusion on ${netCfg.caip2}.`
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

  if (!latestBlockHex || !HEX_UINT_RE.test(String(latestBlockHex))) {
    throw new Error('Invalid eth_blockNumber response from RPC');
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
    if (!log || String(log.address || '').toLowerCase() !== netCfg.usdcAddress.toLowerCase()) continue;
    const topics = Array.isArray(log.topics) ? log.topics : [];
    if (String(topics[0] || '').toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
    const from = normalizeAddressFromTopic(topics[1]);
    const to = normalizeAddressFromTopic(topics[2]);
    if (!from || !to) continue;
    const rawData = log.data && log.data !== '0x' ? String(log.data) : '0x0';
    if (!HEX_UINT_RE.test(rawData)) continue;
    const value = BigInt(rawData);
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
      recipientChecked: Boolean(wantTo),
      detail: `Transaction ${txHash} succeeded, but no canonical USDC Transfer >= ${payment.amountAtomic}${wantTo ? ` to ${wantTo}` : ''} was emitted.`
    };
  }

  // Opportunistically construct & cryptographically self-verify an offline `evm_receipt_trie_v0`
  // Merkle-Patricia settlement proof against the block header's canonical `receiptsRoot` (`0` buyer RPC trust!).
  let settlementProof = null;
  let cryptographicProofVerified = false;
  const shouldBuildMpt = Boolean(
    env.PAXIOM_DISABLE_MPT_SETTLEMENT_PROOF !== 'true' &&
    (includeSettlementProof || txReceipt.blockHash)
  );
  if (shouldBuildMpt) {
    try {
      const blockRef = txReceipt.blockHash || txReceipt.blockNumber;
      const cacheKey = `${netCfg.caip2}:${String(blockRef).toLowerCase()}`;
      let bundle = getCachedBlockBundle(cacheKey);
      if (!bundle) {
        const [blockHeader, blockReceipts] = await Promise.all([
          txReceipt.blockHash
            ? rpcCall(rpcUrl, 'eth_getBlockByHash', [txReceipt.blockHash, false], fetchImpl, 5000)
            : rpcCall(rpcUrl, 'eth_getBlockByNumber', [txReceipt.blockNumber, false], fetchImpl, 5000),
          rpcCall(rpcUrl, 'eth_getBlockReceipts', [blockRef], fetchImpl, 6000)
        ]);
        if (blockHeader && blockHeader.receiptsRoot && Array.isArray(blockReceipts) && blockReceipts.length > 0) {
          bundle = {
            receiptsRoot: String(blockHeader.receiptsRoot).toLowerCase(),
            blockHash: blockHeader.hash ? String(blockHeader.hash).toLowerCase() : null,
            blockReceipts
          };
          setCachedBlockBundle(cacheKey, bundle);
        }
      }
      if (bundle) {
        const candidateProof = buildReceiptTrieProof(bundle.blockReceipts, txHash, {
          network: netCfg.caip2,
          blockNumber: txBlock.toString(),
          blockHash: bundle.blockHash || txReceipt.blockHash || undefined
        });
        if (String(candidateProof.receiptsRoot).toLowerCase() === bundle.receiptsRoot) {
          const mptCheck = verifyUsdcSettlementProofSync({
            settlementProof: candidateProof,
            network: netCfg.caip2,
            expectedPayTo: wantTo || matchingTransfers[0].to,
            minAmountAtomic: requiredAmount,
            expectedTransactionHash: txHash,
            allowUnanchoredRoot: true
          });
          if (mptCheck && mptCheck.verified) {
            settlementProof = candidateProof;
            cryptographicProofVerified = true;
          }
        }
      }
    } catch {
      // Graceful fallback when an upstream RPC node does not implement `eth_getBlockReceipts`
    }
  }

  return {
    checked: true,
    settled: true,
    network: netCfg.caip2,
    transactionHash: txHash,
    blockNumber: txBlock.toString(),
    confirmations,
    recipientChecked: Boolean(wantTo),
    matchedTransfer: matchingTransfers[0],
    cryptographicProofVerified,
    ...(settlementProof ? { settlementProof } : {})
  };
}
