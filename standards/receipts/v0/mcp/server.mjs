#!/usr/bin/env node
// Zero-dependency Model Context Protocol (MCP) stdio server for Paxiom Receipts.
//
// Exposes offline verification, trust-state explanation, and receipt issuance to
// AI agents (Claude Desktop, Cursor, MCP gateways) without pulling any external
// npm packages.
import readline from 'node:readline';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyReceipt, RECEIPT_VERSION } from '../src/verify.mjs';
import { issueReceipt, generateReceiptKeyPair } from '../src/issue.mjs';
import { explain } from '../src/explain.mjs';
import {
  DEFAULT_PAXIOM_API_URL,
  preflightX402,
  verifyReceiptLive
} from '../src/client.mjs';

export const MCP_PROTOCOL_VERSION = '2024-11-05';
export const SERVER_INFO = {
  name: 'paxiom-receipt-mcp',
  version: '0.1.3'
};
const MAX_JSONRPC_LINE_BYTES = 1024 * 1024; // 1 MiB stdio line safety bound

function isValidJsonRpcId(id) {
  return id === null || typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
}

export const TOOLS = [
  {
    name: 'verify_receipt',
    description: 'Verify a paxiom.receipt.v0 cryptographic receipt (schema, Ed25519 signature, output SHA-256 JCS binding, expiry, and honest settlement/proof trust state). Offline and deterministic.',
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: {
          type: 'object',
          description: 'Parsed paxiom.receipt.v0 JSON object.'
        },
        output: {
          description: 'Optional delivered API response JSON to verify payment-to-output hash binding.'
        },
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional base64 32-byte Ed25519 public keys trusted to assert checkedByPaxiom=true.'
        }
      }
    }
  },
  {
    name: 'explain_receipt',
    description: 'Verify a paxiom.receipt.v0 receipt and return a concise human/agent-readable trust-state breakdown.',
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: { type: 'object' },
        output: {},
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional base64 32-byte Ed25519 public keys trusted to assert checkedByPaxiom=true.'
        }
      }
    }
  },
  {
    name: 'issue_receipt',
    description: 'Sign and issue a schema-valid paxiom.receipt.v0 Ed25519 receipt binding request, payment, and delivered output. Uses PAXIOM_ISSUER_PRIVATE_KEY_PEM from env, or mints an ephemeral demo key when demoEphemeralKey=true.',
    inputSchema: {
      type: 'object',
      required: ['issuerName', 'keyId', 'resource', 'output'],
      properties: {
        issuerName: { type: 'string' },
        keyId: { type: 'string' },
        serviceName: { type: 'string' },
        resource: { type: 'string' },
        method: { type: 'string', default: 'POST' },
        requestBody: {},
        payment: { type: 'object' },
        output: {},
        demoEphemeralKey: {
          type: 'boolean',
          description: 'Set true only for testing when PAXIOM_ISSUER_PRIVATE_KEY_PEM is not configured.'
        }
      }
    }
  },
  {
    name: 'preflight_x402_seller',
    description: 'Scan an untrusted https:// x402 seller endpoint before signing an EIP-3009 payment ($0.01 USDC via x402 or PAXIOM_API_KEY). Checks canonical Circle Base USDC asset address, EIP-712 domain, payTo manifest bait-and-switch, budget cap, and X-Paxiom-Receipt readiness.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: {
        url: {
          type: 'string',
          description: 'Target https:// x402 seller URL to inspect before paying.'
        },
        method: {
          type: 'string',
          enum: ['POST', 'GET', 'HEAD'],
          description: 'HTTP method to probe (default POST).'
        },
        maxBudgetAtomic: {
          type: 'string',
          description: 'Optional caller budget cap in USDC atomic units (6 decimals).'
        },
        expectedNetwork: {
          type: 'string',
          description: 'Optional expected network (base or base-sepolia).'
        },
        paymentHeader: {
          type: 'string',
          description: 'Optional base64 PAYMENT-SIGNATURE header when not using PAXIOM_API_KEY.'
        }
      }
    }
  },
  {
    name: 'verify_receipt_live',
    description: 'Confirm a paxiom.receipt.v0 receipt claimed Base / Base Sepolia USDC Transfer log on-chain via https://api.paxiom.org/v1/receipt/verify-live ($0.002 USDC via x402 or PAXIOM_API_KEY) and return Paxiom Ed25519 counter-attestation.',
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: {
          type: 'object',
          description: 'Parsed paxiom.receipt.v0 JSON object.'
        },
        output: {
          description: 'Optional delivered API response JSON.'
        },
        expectedPayTo: {
          type: 'string',
          description: 'Expected 0x seller USDC recipient address (required to mint portable Paxiom root counter-attestation).'
        },
        paymentHeader: {
          type: 'string',
          description: 'Optional base64 PAYMENT-SIGNATURE header when not using PAXIOM_API_KEY.'
        }
      }
    }
  }
];

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/**
 * Pure JSON-RPC 2.0 handler. Returns a response object, or `null` for notifications.
 */
export function handleJsonRpcMessage(msg, env = process.env, runtimeOpts = {}) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') {
    const rawId = msg && typeof msg === 'object' && !Array.isArray(msg) && Object.hasOwn(msg, 'id') ? msg.id : null;
    return jsonRpcError(isValidJsonRpcId(rawId) ? rawId : null, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  if (Object.hasOwn(msg, 'id') && !isValidJsonRpcId(msg.id)) {
    return jsonRpcError(null, -32600, 'Invalid JSON-RPC 2.0 id: must be string, finite number, or null');
  }

  if (typeof msg.method !== 'string') {
    return jsonRpcError(Object.hasOwn(msg, 'id') ? msg.id : null, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  const isNotification = !Object.hasOwn(msg, 'id');
  if (isNotification) return null;

  const { id, method, params = {} } = msg;

  if (method === 'initialize') {
    return jsonRpcResult(id, {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO
    });
  }

  if (method === 'ping') {
    return jsonRpcResult(id, {});
  }

  if (method === 'tools/list') {
    return jsonRpcResult(id, { tools: TOOLS });
  }

  if (method === 'tools/call') {
    const toolName = params && params.name;
    const args = (params && params.arguments) || {};

    try {
      if (toolName === 'verify_receipt') {
        if (!args.receipt || typeof args.receipt !== 'object') {
          return jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: 'Missing required object argument: receipt' }]
          });
        }
        const opts = {};
        if (Object.prototype.hasOwnProperty.call(args, 'output')) opts.output = args.output;
        if (Array.isArray(args.trustedPaxiomPublicKeys)) {
          opts.trustedPaxiomPublicKeys = args.trustedPaxiomPublicKeys;
        }
        const result = verifyReceipt(args.receipt, opts);
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          structuredContent: result
        });
      }

      if (toolName === 'explain_receipt') {
        if (!args.receipt || typeof args.receipt !== 'object') {
          return jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: 'Missing required object argument: receipt' }]
          });
        }
        const opts = {};
        if (Object.prototype.hasOwnProperty.call(args, 'output')) opts.output = args.output;
        if (Array.isArray(args.trustedPaxiomPublicKeys)) {
          opts.trustedPaxiomPublicKeys = args.trustedPaxiomPublicKeys;
        }
        const result = verifyReceipt(args.receipt, opts);
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: explain(result) }]
        });
      }

      if (toolName === 'issue_receipt') {
        let privateKey = env.PAXIOM_ISSUER_PRIVATE_KEY_PEM;
        let ephemeralWarning = null;
        if (!privateKey) {
          if (!args.demoEphemeralKey) {
            return jsonRpcResult(id, {
              isError: true,
              content: [{
                type: 'text',
                text: 'PAXIOM_ISSUER_PRIVATE_KEY_PEM is not set. Configure an Ed25519 PKCS#8 PEM key or pass demoEphemeralKey=true for demo receipts.'
              }]
            });
          }
          const kp = generateReceiptKeyPair({ keyId: args.keyId });
          privateKey = kp.privateKeyPem;
          ephemeralWarning = 'Signed with a one-time ephemeral demo key (demoEphemeralKey=true).';
        }
        const { receipt, receiptHeader } = issueReceipt({
          privateKey,
          issuer: { name: args.issuerName, keyId: args.keyId },
          service: {
            name: args.serviceName || args.issuerName,
            resource: args.resource,
            method: args.method || 'POST'
          },
          request: {
            method: args.method || 'POST',
            resource: args.resource,
            body: args.requestBody
          },
          payment: args.payment || {
            settlement: { status: 'verify_only', transactionHash: null, checkedByPaxiom: false }
          },
          output: args.output
        });
        const payload = {
          receiptVersion: RECEIPT_VERSION,
          receipt,
          receiptHeader,
          ...(ephemeralWarning ? { note: ephemeralWarning } : {})
        };
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
          structuredContent: payload
        });
      }

      if (toolName === 'preflight_x402_seller') {
        if (typeof args.url !== 'string' || !args.url.trim()) {
          return jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: 'Missing required string argument: url' }]
          });
        }
        return preflightX402(args.url, {
          method: args.method,
          maxBudgetAtomic: args.maxBudgetAtomic,
          expectedNetwork: args.expectedNetwork,
          apiKey: env.PAXIOM_API_KEY,
          paymentHeader: args.paymentHeader,
          baseUrl: env.PAXIOM_API_URL || DEFAULT_PAXIOM_API_URL,
          fetchImpl: runtimeOpts.fetchImpl
        }).then(
          (out) => jsonRpcResult(id, {
            isError: !out.ok && !out.paymentRequired,
            content: [{ type: 'text', text: JSON.stringify(out, null, 2) }],
            structuredContent: out
          }),
          (err) => jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: `Tool error: ${(err && err.message) || err}` }]
          })
        );
      }

      if (toolName === 'verify_receipt_live') {
        if (!args.receipt || typeof args.receipt !== 'object' || Array.isArray(args.receipt)) {
          return jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: 'Missing required object argument: receipt' }]
          });
        }
        return verifyReceiptLive(args.receipt, {
          ...(Object.hasOwn(args, 'output') ? { output: args.output } : {}),
          expectedPayTo: args.expectedPayTo,
          apiKey: env.PAXIOM_API_KEY,
          paymentHeader: args.paymentHeader,
          baseUrl: env.PAXIOM_API_URL || DEFAULT_PAXIOM_API_URL,
          fetchImpl: runtimeOpts.fetchImpl
        }).then(
          (out) => jsonRpcResult(id, {
            isError: !out.ok && !out.paymentRequired,
            content: [{ type: 'text', text: JSON.stringify(out, null, 2) }],
            structuredContent: out
          }),
          (err) => jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: `Tool error: ${(err && err.message) || err}` }]
          })
        );
      }

      return jsonRpcError(id, -32601, `Unknown tool: ${toolName}`);
    } catch (err) {
      return jsonRpcResult(id, {
        isError: true,
        content: [{ type: 'text', text: `Tool error: ${(err && err.message) || err}` }]
      });
    }
  }

  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

export function startStdioServer({
  input = process.stdin,
  output = process.stdout,
  env = process.env,
  fetchImpl
} = {}) {
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (Buffer.byteLength(line, 'utf8') > MAX_JSONRPC_LINE_BYTES) {
      output.write(JSON.stringify(jsonRpcError(null, -32600, 'JSON-RPC message exceeds 1 MiB line limit')) + '\n');
      return;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.toLowerCase().startsWith('content-length:')) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      output.write(JSON.stringify(jsonRpcError(null, -32700, 'Parse error')) + '\n');
      return;
    }
    Promise.resolve(handleJsonRpcMessage(parsed, env, { fetchImpl })).then((resp) => {
      if (resp) {
        output.write(JSON.stringify(resp) + '\n');
      }
    });
  });
  return rl;
}

function isDirectCliInvocation(argv1) {
  if (!argv1) return false;
  try {
    return pathToFileURL(realpathSync(argv1)).href === import.meta.url;
  } catch {
    return pathToFileURL(argv1).href === import.meta.url;
  }
}

if (isDirectCliInvocation(process.argv[1])) {
  startStdioServer();
}
