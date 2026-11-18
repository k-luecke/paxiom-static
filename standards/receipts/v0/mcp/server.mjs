#!/usr/bin/env node
// Zero-dependency Model Context Protocol (MCP) stdio server for Paxiom Receipts.
//
// Exposes offline verification, trust-state explanation, receipt issuance, and
// free public reference preflight / on-chain settlement checks to AI agents
// (Claude Desktop, Cursor, MCP gateways) without pulling any external npm packages.
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
  version: '0.3.0'
};
const MAX_JSONRPC_LINE_BYTES = 1024 * 1024; // 1 MiB stdio line safety bound

function isValidJsonRpcId(id) {
  return id === null || typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
}

const TRUST_STATE_ENUM = [
  'verified',
  'valid_signature_only',
  'settlement_claimed_not_checked',
  'unsupported_format',
  'schema_invalid',
  'invalid_signature',
  'unauthorized_issuer',
  'expired',
  'output_hash_mismatch',
  'settlement_failed',
  'proof_invalid',
  'proof_unavailable',
  'error'
];

export const TOOLS = [
  {
    name: 'verify_receipt',
    title: 'Verify Paxiom Receipt (Structured JSON)',
    description:
      'Validate an Ed25519-signed paxiom.receipt.v0 API delivery receipt (JSON Schema, Ed25519 signature, signer authorization against expectedIssuerPublicKeys / expectedPayTo, JCS or raw SHA-256 output binding, expiry, and settlement trust state) and return structured JSON fields. Use this instead of explain_receipt when automated code branches on valid or trustState; use explain_receipt for human-readable prose, or verify_receipt_live to confirm an on-chain Base USDC Transfer log. Deterministic and offline: invalid receipts return isError=false with valid=false and the failing trustState, and omitting output caps trustState at valid_signature_only.',
    annotations: {
      title: 'Verify Paxiom Receipt (Structured JSON)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: {
          type: 'object',
          description: 'Parsed paxiom.receipt.v0 JSON envelope (decoded from Payment-Receipt or X-Paxiom-Receipt header).'
        },
        output: {
          description: 'Optional delivered HTTP response payload (JSON value for jcs-sha256, or UTF-8 string for raw-sha256); required to reach trustState="verified".'
        },
        expectedIssuerPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional pinned base64 Ed25519 seller public keys (e.g. from /.well-known/x402-keys.json). Mismatch returns trustState="unauthorized_issuer".'
        },
        expectedPayTo: {
          type: 'string',
          description: 'Optional expected seller payTo address from the 402 quote. Mismatch returns trustState="unauthorized_issuer".'
        },
        trustedVerifierPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional canonical base64 32-byte Ed25519 public keys trusted to assert settlement.checkedByVerifier=true.'
        },
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Backward-compatible alias for trustedVerifierPublicKeys.'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['valid', 'trustState', 'checks', 'receiptHash', 'summary'],
      properties: {
        valid: { type: 'boolean', description: 'True only when trustState is "verified".' },
        trustState: { type: 'string', enum: TRUST_STATE_ENUM, description: 'Machine-readable verification outcome classification.' },
        checks: { type: 'object', description: 'Per-stage schema, signature, issuerAuthorization, outputHash, binding, settlement, and proof statuses.' },
        receiptHash: { type: ['string', 'null'], description: 'Hex SHA-256 digest of the canonical signing input, or null if schema validation failed.' },
        summary: { type: 'string', description: 'One-sentence diagnostic summary of the verification outcome.' }
      }
    }
  },
  {
    name: 'explain_receipt',
    title: 'Format Human-Readable Receipt Explanation',
    description:
      'Format a plain-text trust breakdown and next-action remediation checklist for an Ed25519-signed paxiom.receipt.v0 API delivery receipt. Use this instead of verify_receipt when displaying a readable verdict to a user or operator; use verify_receipt when code needs raw check fields for programmatic gating. Runs deterministically offline with no network calls: tampered, unauthorized, expired, or unconfirmed receipts return isError=false with an actionable diagnostic explanation rather than throwing. Pass output with the delivered HTTP response body to evaluate SHA-256 payload binding (omitting output caps trustState at valid_signature_only).',
    annotations: {
      title: 'Format Human-Readable Receipt Explanation',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: {
          type: 'object',
          description: 'Parsed paxiom.receipt.v0 JSON envelope (decoded from Payment-Receipt or X-Paxiom-Receipt header).'
        },
        output: {
          description: 'Optional delivered HTTP response payload; pass whenever available so SHA-256 payload binding is evaluated alongside the Ed25519 signature.'
        },
        expectedIssuerPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional pinned base64 Ed25519 seller public keys (e.g. from /.well-known/x402-keys.json).'
        },
        expectedPayTo: {
          type: 'string',
          description: 'Optional expected seller payTo address from the 402 quote.'
        },
        trustedVerifierPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional canonical base64 32-byte Ed25519 public keys trusted to assert settlement.checkedByVerifier=true.'
        },
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Backward-compatible alias for trustedVerifierPublicKeys.'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['explanation', 'valid', 'trustState', 'receiptHash'],
      properties: {
        explanation: { type: 'string', description: 'Multi-line human-readable trust breakdown and next-step remediation guidance.' },
        valid: { type: 'boolean', description: 'True only when trustState reaches "verified".' },
        trustState: { type: 'string', enum: TRUST_STATE_ENUM, description: 'Underlying verification state explained in the report.' },
        receiptHash: { type: ['string', 'null'], description: 'Hex SHA-256 digest of the canonical signing input, or null when schema validation failed.' }
      }
    }
  },
  {
    name: 'issue_receipt',
    title: 'Sign & Issue Local Paxiom Receipt',
    description:
      'Sign and issue a schema-valid paxiom.receipt.v0 Ed25519 delivery receipt locally, binding HTTP request metadata, x402 payment claim, and JCS or raw SHA-256 output hash. Use this on a seller or agent host to mint Payment-Receipt / X-Paxiom-Receipt headers offline; never sends private keys over the network. Reads PAXIOM_ISSUER_PRIVATE_KEY_PEM from the local environment, or generates a one-time ephemeral key only when demoEphemeralKey=true (returns isError=true if neither is set).',
    annotations: {
      title: 'Sign & Issue Local Paxiom Receipt',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    },
    inputSchema: {
      type: 'object',
      required: ['issuerName', 'keyId', 'resource', 'output'],
      properties: {
        issuerName: { type: 'string', description: 'Human-readable seller or service issuer name.' },
        keyId: { type: 'string', description: 'Signer key identifier written into payload.issuer.keyId and signature.keyId.' },
        serviceName: { type: 'string', description: 'Optional service display name (defaults to issuerName).' },
        payTo: { type: 'string', description: 'Optional seller recipient address bound into issuer.payTo and payment.payTo.' },
        resource: { type: 'string', description: 'Canonical HTTPS URL or URI of the delivered API resource.' },
        method: { type: 'string', default: 'POST', description: 'HTTP method bound to the receipt (defaults to POST).' },
        requestBody: { description: 'Optional request body (JSON value or string) to bind via SHA-256 hash.' },
        payment: { type: 'object', description: 'Optional payment and settlement claim metadata (defaults to status="verify_only").' },
        output: { description: 'Delivered response payload whose SHA-256 digest is signed into delivery.outputHash.' },
        canonicalization: {
          type: 'string',
          enum: ['jcs-sha256', 'raw-sha256'],
          description: 'Output hash mode: jcs-sha256 for structured JSON (default) or raw-sha256 for text/Markdown/binary.'
        },
        mimeType: { type: 'string', description: 'Delivered response MIME type (defaults to application/json).' },
        statusCode: { type: 'integer', description: 'Optional HTTP response status code (100-599).' },
        demoEphemeralKey: {
          type: 'boolean',
          description: 'Set true only for testing to mint an ephemeral Ed25519 key when PAXIOM_ISSUER_PRIVATE_KEY_PEM is unset.'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['receiptVersion', 'receipt', 'receiptHeader'],
      properties: {
        receiptVersion: { type: 'string', description: 'Issued receipt format version ("paxiom.receipt.v0").' },
        receipt: { type: 'object', description: 'Signed paxiom.receipt.v0 JSON object.' },
        receiptHeader: { type: 'string', description: 'Base64url-encoded receipt ready to attach as Payment-Receipt and X-Paxiom-Receipt HTTP headers.' },
        note: { type: 'string', description: 'Present when signed with a temporary demo key (demoEphemeralKey=true).' }
      }
    }
  },
  {
    name: 'preflight_x402_seller',
    title: 'Preflight Untrusted x402 Seller Endpoint',
    description:
      'Scan an untrusted https:// x402 seller URL before signing an EIP-3009 USDC authorization via the free rate-limited reference scanner at api.paxiom.org/v1/x402/preflight. Use this prior to paying an unfamiliar x402 endpoint to catch spoofed non-Circle USDC contracts, invalid EIP-712 domains, payTo manifest bait-and-switch, budget overruns, or missing Payment-Receipt / X-Paxiom-Receipt support.',
    annotations: {
      title: 'Preflight Untrusted x402 Seller Endpoint',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true
    },
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
          description: 'HTTP method to probe on the seller URL (defaults to POST).'
        },
        maxBudgetAtomic: {
          type: 'string',
          description: 'Optional caller budget ceiling in USDC atomic units (6 decimals, e.g. "50000" for 0.05 USDC).'
        },
        expectedNetwork: {
          type: 'string',
          description: 'Optional expected CAIP-2 or short network identifier ("eip155:8453", "base", or "eip155:84532").'
        },
        paymentHeader: {
          type: 'string',
          description: 'Optional base64 x402 PAYMENT-SIGNATURE header if calling a custom gated verifier host.'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['ok', 'status'],
      properties: {
        ok: { type: 'boolean', description: 'True when the preflight scan HTTP call succeeded.' },
        status: { type: 'number', description: 'HTTP status returned by the preflight endpoint (200, or 429 when rate-limited).' },
        paymentRequired: { type: 'boolean', description: 'True only if a custom host returned HTTP 402.' }
      }
    }
  },
  {
    name: 'verify_receipt_live',
    title: 'Verify Receipt On-Chain & Counter-Attest',
    description:
      'Confirm a paxiom.receipt.v0 receipt claimed Base or Base Sepolia USDC Transfer log on-chain via the free rate-limited reference verifier at api.paxiom.org/v1/receipt/verify-live and mint an Ed25519 counter-attestation. Use this instead of offline verify_receipt when verify_receipt reports settlement_claimed_not_checked and you need independent on-chain settlement confirmation; pass expectedPayTo to bind the seller recipient address.',
    annotations: {
      title: 'Verify Receipt On-Chain & Counter-Attest',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true
    },
    inputSchema: {
      type: 'object',
      required: ['receipt'],
      properties: {
        receipt: {
          type: 'object',
          description: 'Parsed paxiom.receipt.v0 JSON object containing a settlement.transactionHash.'
        },
        output: {
          description: 'Optional delivered HTTP response payload to bind alongside on-chain settlement.'
        },
        expectedPayTo: {
          type: 'string',
          description: 'Expected 0x seller USDC recipient address (required to mint a portable counter-attested receipt).'
        },
        paymentHeader: {
          type: 'string',
          description: 'Optional base64 x402 PAYMENT-SIGNATURE header if calling a custom gated verifier host.'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['ok', 'status'],
      properties: {
        ok: { type: 'boolean', description: 'True when live on-chain verification completed with HTTP 200.' },
        status: { type: 'number', description: 'HTTP status returned by the live verifier (200, or 429 when rate-limited).' },
        paymentRequired: { type: 'boolean', description: 'True only if a custom host returned HTTP 402.' }
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

function buildVerifyOpts(args) {
  const opts = {};
  if (Object.prototype.hasOwnProperty.call(args, 'output')) opts.output = args.output;
  if (Array.isArray(args.expectedIssuerPublicKeys)) {
    opts.expectedIssuerPublicKeys = args.expectedIssuerPublicKeys;
  }
  if (typeof args.expectedPayTo === 'string' && args.expectedPayTo.trim()) {
    opts.expectedPayTo = args.expectedPayTo;
  }
  if (Array.isArray(args.trustedVerifierPublicKeys)) {
    opts.trustedVerifierPublicKeys = args.trustedVerifierPublicKeys;
  } else if (Array.isArray(args.trustedPaxiomPublicKeys)) {
    opts.trustedPaxiomPublicKeys = args.trustedPaxiomPublicKeys;
  }
  return opts;
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
        const result = verifyReceipt(args.receipt, buildVerifyOpts(args));
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
        const result = verifyReceipt(args.receipt, buildVerifyOpts(args));
        const explanation = explain(result);
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: explanation }],
          structuredContent: {
            explanation,
            valid: result.valid,
            trustState: result.trustState,
            receiptHash: result.receiptHash
          }
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
        const paymentObj = args.payment
          ? { ...args.payment, ...(args.payTo && !args.payment.payTo ? { payTo: args.payTo } : {}) }
          : {
            ...(args.payTo ? { payTo: args.payTo } : {}),
            settlement: { status: 'verify_only', transactionHash: null, checkedByVerifier: false }
          };
        const { receipt, receiptHeader } = issueReceipt({
          privateKey,
          issuer: {
            name: args.issuerName,
            keyId: args.keyId,
            ...(args.payTo ? { payTo: args.payTo } : {})
          },
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
          payment: paymentObj,
          output: args.output,
          canonicalization: args.canonicalization || 'jcs-sha256',
          mimeType: args.mimeType || 'application/json',
          statusCode: args.statusCode
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
