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

export const MCP_PROTOCOL_VERSION = '2024-11-05';
export const SERVER_INFO = {
  name: 'paxiom-receipt-mcp',
  version: '0.1.2'
};
const MAX_JSONRPC_LINE_BYTES = 1024 * 1024; // 1 MiB stdio line safety bound

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
export function handleJsonRpcMessage(msg, env = process.env) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return jsonRpcError(msg && msg.id !== undefined ? msg.id : null, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  const isNotification = !Object.prototype.hasOwnProperty.call(msg, 'id');
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

export function startStdioServer({ input = process.stdin, output = process.stdout, env = process.env } = {}) {
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
    const resp = handleJsonRpcMessage(parsed, env);
    if (resp) {
      output.write(JSON.stringify(resp) + '\n');
    }
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
