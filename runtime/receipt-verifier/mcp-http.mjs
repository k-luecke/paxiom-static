// Stateless Model Context Protocol (MCP) Streamable-HTTP handler for `api.paxiom.org/mcp`.
//
// Implements JSON-RPC 2.0 over HTTP POST per the MCP Streamable-HTTP specification
// (`2025-06-18` / `2025-03-26`, backward-compatible with `2024-11-05`).
//
// Security invariant:
//   - Strictly stateless and zero external dependencies.
//   - Intentionally exposes ONLY read/verify/discovery tools (`verify_receipt`,
//     `explain_receipt`, `get_x402_verifier_info`) over remote HTTP so seller
//     Ed25519 private keys never traverse the network (`issue_receipt` remains
//     exclusively in the local stdio MCP server `@paxiom/receipts`).

import { verifyReceipt, RECEIPT_VERSION } from '../../standards/receipts/v0/src/verify.mjs';
import { explain } from '../../standards/receipts/v0/src/explain.mjs';
import { publicKeyFromPrivateKey } from '../../standards/receipts/v0/src/issue.mjs';

export const DEFAULT_MCP_HTTP_PROTOCOL_VERSION = '2025-03-26';
export const SUPPORTED_MCP_HTTP_VERSIONS = new Set([
  '2025-06-18',
  '2025-03-26',
  '2024-11-05'
]);
export const MAX_MCP_BATCH_SIZE = 32;

export const REMOTE_MCP_SERVER_INFO = Object.freeze({
  name: 'io.github.k-luecke/paxiom-receipts',
  title: 'Paxiom Receipts MCP',
  version: '0.1.3'
});

const TRUST_STATE_ENUM = [
  'verified',
  'valid_signature_only',
  'settlement_claimed_not_checked',
  'unsupported_format',
  'schema_invalid',
  'invalid_signature',
  'expired',
  'output_hash_mismatch',
  'settlement_failed',
  'proof_invalid',
  'proof_unavailable',
  'error'
];

export const REMOTE_MCP_TOOLS = Object.freeze([
  {
    name: 'verify_receipt',
    title: 'Verify Paxiom Receipt (Structured JSON)',
    description:
      'Validate an Ed25519-signed paxiom.receipt.v0 API delivery receipt (JSON Schema, Ed25519 signature, RFC 8785 JCS SHA-256 output binding, expiry, and settlement trust state) and return structured JSON fields. Use this instead of explain_receipt when automated code branches on valid or trustState; use explain_receipt when presenting human-readable guidance, or get_x402_verifier_info for live on-chain settlement endpoints. Deterministic, offline, and free with no auth or rate limits: invalid or tampered receipts return isError=false with valid=false and the failing trustState, omitting output caps trustState at valid_signature_only, and omitting trustedPaxiomPublicKeys trusts the host Paxiom counter-attestation key by default.',
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
          description: 'Parsed paxiom.receipt.v0 JSON envelope (or base64url-decoded X-Paxiom-Receipt HTTP header).'
        },
        output: {
          description: 'Optional delivered HTTP response JSON body; required to verify SHA-256 JCS outputHash binding and reach trustState="verified".'
        },
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional canonical base64 32-byte Ed25519 public keys trusted to assert settlement.checkedByPaxiom=true (defaults to the host Paxiom key).'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['valid', 'trustState', 'checks', 'receiptHash', 'summary'],
      properties: {
        valid: {
          type: 'boolean',
          description: 'True only when trustState is "verified" (valid signature, matching outputHash, non-expired, and confirmed or verify_only settlement).'
        },
        trustState: {
          type: 'string',
          enum: TRUST_STATE_ENUM,
          description: 'Machine-readable verification outcome classification.'
        },
        checks: {
          type: 'object',
          required: ['schema', 'signature', 'outputHash', 'requestBinding', 'paymentBinding', 'settlement', 'proof'],
          properties: {
            schema: { type: 'string', description: 'Draft-07 schema check status (pass, fail, not_checked).' },
            signature: { type: 'string', description: 'Ed25519 signature and keyId consistency status (pass, fail, not_checked).' },
            outputHash: { type: 'string', description: 'RFC 8785 JCS SHA-256 payload hash check (pass, fail, not_provided, not_checked, error).' },
            requestBinding: { type: 'string', description: 'Request method and resource binding check (pass, not_checked).' },
            paymentBinding: { type: 'string', description: 'Payment metadata binding check (pass, not_checked).' },
            settlement: { type: 'string', description: 'Reported settlement state from the receipt payload.' },
            proof: { type: 'string', description: 'Evidence array status summary (provided, not_provided, invalid, unavailable).' }
          },
          description: 'Per-stage cryptographic and structural check statuses.'
        },
        receiptHash: {
          type: ['string', 'null'],
          description: 'Hex SHA-256 digest of the canonical signing input, or null if schema validation failed.'
        },
        summary: {
          type: 'string',
          description: 'One-sentence diagnostic summary of the verification outcome.'
        }
      }
    }
  },
  {
    name: 'explain_receipt',
    title: 'Format Human-Readable Receipt Explanation',
    description:
      'Format a plain-text trust breakdown and next-action remediation checklist for an Ed25519-signed paxiom.receipt.v0 API delivery receipt. Use this instead of verify_receipt when displaying a readable verdict to a user or operator; use verify_receipt when code needs raw check fields for programmatic gating, or get_x402_verifier_info to discover live Base USDC settlement endpoints. Runs deterministically offline for free with no auth or rate limits: tampered, expired, or unconfirmed receipts return isError=false with an actionable diagnostic explanation rather than throwing, and omitting trustedPaxiomPublicKeys trusts the host Paxiom counter-attestation key by default. Pass output with the delivered HTTP response body to check SHA-256 JCS payload binding (omitting output caps trustState at valid_signature_only).',
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
          description: 'Parsed paxiom.receipt.v0 JSON envelope (or base64url-decoded X-Paxiom-Receipt HTTP header).'
        },
        output: {
          description: 'Optional delivered HTTP response JSON body; pass whenever available so SHA-256 JCS payload binding is evaluated alongside the Ed25519 signature.'
        },
        trustedPaxiomPublicKeys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional canonical base64 32-byte Ed25519 public keys trusted to assert settlement.checkedByPaxiom=true (defaults to the host Paxiom key).'
        }
      }
    },
    outputSchema: {
      type: 'object',
      required: ['explanation', 'valid', 'trustState', 'receiptHash'],
      properties: {
        explanation: {
          type: 'string',
          description: 'Multi-line human-readable trust breakdown, failed/skipped check details, and next-step remediation guidance.'
        },
        valid: {
          type: 'boolean',
          description: 'True only when trustState reaches "verified".'
        },
        trustState: {
          type: 'string',
          enum: TRUST_STATE_ENUM,
          description: 'Underlying verification state explained in the report.'
        },
        receiptHash: {
          type: ['string', 'null'],
          description: 'Hex SHA-256 digest of the canonical signing input, or null when schema validation failed.'
        }
      }
    }
  },
  {
    name: 'get_x402_verifier_info',
    title: 'Get Paxiom x402 Verifier & Preflight Metadata',
    description:
      'Retrieve Paxiom Receipt Verifier service discovery metadata, published Ed25519 counter-attestation public keys, free HTTP endpoints, and x402 Base USDC payment terms for live on-chain settlement verification ($0.002 USDC) and pre-payment seller preflight ($0.01 USDC). Call this before invoking paid HTTP routes (/v1/receipt/verify-live or /v1/x402/preflight) to inspect current pricing, facilitator URL, and payTo recipient; use verify_receipt or explain_receipt instead when evaluating a receipt you already hold. Stateless, read-only, and free with no authentication or rate limits.',
    annotations: {
      title: 'Get Paxiom x402 Verifier & Preflight Metadata',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    inputSchema: {
      type: 'object',
      properties: {}
    },
    outputSchema: {
      type: 'object',
      required: ['service', 'receiptVersion', 'baseUrl', 'mcpEndpoint', 'npmPackage', 'trustedPaxiomKeys', 'freeEndpoints', 'paidX402Endpoints'],
      properties: {
        service: { type: 'string', description: 'Canonical verifier service identifier ("paxiom-receipt-verifier").' },
        receiptVersion: { type: 'string', description: 'Supported Paxiom receipt schema version ("paxiom.receipt.v0").' },
        baseUrl: { type: 'string', description: 'HTTPS origin of the verifier API.' },
        mcpEndpoint: { type: 'string', description: 'Streamable-HTTP MCP endpoint URL.' },
        npmPackage: {
          type: 'object',
          description: 'Local zero-dependency npm SDK and stdio MCP package details (@paxiom/receipts).'
        },
        trustedPaxiomKeys: {
          type: 'array',
          description: 'Published Ed25519 root counter-attestation public keys ({ keyId, algorithm, publicKey }).'
        },
        freeEndpoints: {
          type: 'object',
          description: 'Unauthenticated free HTTP routes for offline verification, demo fixtures, and .well-known discovery.'
        },
        paidX402Endpoints: {
          type: ['object', 'null'],
          description: 'Active x402 Base USDC payment terms, payTo address, facilitator URL, and priced route descriptors, or null if disabled.'
        }
      }
    }
  }
]);

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function isValidJsonRpcId(id) {
  return id === null || typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
}

function isFlagEnabled(val) {
  return val === 'true' || val === '1';
}

function resolveHostPaxiomPublicKey(env = {}) {
  const pem = env.PAXIOM_SIGNING_PRIVATE_KEY_PEM;
  if (!pem) return null;
  try {
    return {
      keyId: env.PAXIOM_SIGNING_KEY_ID || 'paxiom-live-verifier-001',
      publicKey: publicKeyFromPrivateKey(pem)
    };
  } catch {
    return null;
  }
}

export function buildVerifierDiscoveryPayload(env = {}) {
  const liveEnabled = isFlagEnabled(env.LIVE_VERIFY_ENABLED) || isFlagEnabled(env.X402_ENABLED);
  const x402Enabled = isFlagEnabled(env.X402_ENABLED);
  const hostKey = resolveHostPaxiomPublicKey(env);
  const verifyLiveResource = env.X402_RESOURCE_URL || 'https://api.paxiom.org/v1/receipt/verify-live';
  const preflightResource = env.X402_PREFLIGHT_RESOURCE_URL || 'https://api.paxiom.org/v1/x402/preflight';
  let baseUrl = 'https://api.paxiom.org';
  try {
    baseUrl = new URL(verifyLiveResource).origin;
  } catch {
    // keep default origin if X402_RESOURCE_URL is not a valid absolute URL
  }

  return {
    service: 'paxiom-receipt-verifier',
    receiptVersion: RECEIPT_VERSION,
    baseUrl,
    mcpEndpoint: `${baseUrl}/mcp`,
    npmPackage: {
      name: '@paxiom/receipts',
      version: REMOTE_MCP_SERVER_INFO.version,
      localStdioMcpCommand: 'npx --yes --package=@paxiom/receipts paxiom-receipt-mcp',
      note: 'Use local @paxiom/receipts middleware or stdio MCP for issue_receipt so seller private keys never leave your host.'
    },
    trustedPaxiomKeys: hostKey
      ? [{ keyId: hostKey.keyId, algorithm: 'ed25519', publicKey: hostKey.publicKey }]
      : [],
    freeEndpoints: {
      offlineVerify: `${baseUrl}/v1/receipt/verify`,
      demoFixture: `${baseUrl}/v1/receipt/demo`,
      paxiomKeys: `${baseUrl}/.well-known/paxiom-keys.json`,
      x402Discovery: `${baseUrl}/.well-known/x402.json`
    },
    paidX402Endpoints: liveEnabled
      ? {
          x402Enabled,
          network: env.X402_NETWORK || 'base',
          asset: 'USDC',
          payTo: env.X402_PAY_TO || null,
          facilitatorUrl: env.X402_FACILITATOR_URL || 'https://facilitator.payai.network',
          routes: [
            {
              method: 'POST',
              url: verifyLiveResource,
              priceAtomic: String(env.X402_PRICE_ATOMIC || '2000'),
              priceUsd: '0.002',
              purpose: 'Confirm Base / Base Sepolia USDC Transfer log on-chain and emit Paxiom Ed25519 counter-attested X-Paxiom-Receipt.'
            },
            {
              method: 'POST',
              url: preflightResource,
              priceAtomic: String(env.X402_PREFLIGHT_PRICE_ATOMIC || '10000'),
              priceUsd: '0.01',
              purpose: 'SSRF-hardened pre-payment x402 seller readiness scan (canonical Circle USDC check, EIP-712 domain check, payTo bait-and-switch check, X-Paxiom-Receipt readiness).'
            }
          ]
        }
      : null
  };
}

/**
 * Pure JSON-RPC 2.0 handler for a single message object.
 * Returns a JSON-RPC response object, or `null` for notifications / client responses.
 */
export function buildMcpServerCard(env = {}) {
  const verifyLiveResource = env.X402_RESOURCE_URL || 'https://api.paxiom.org/v1/receipt/verify-live';
  let baseUrl = 'https://api.paxiom.org';
  try {
    baseUrl = new URL(verifyLiveResource).origin;
  } catch {
    baseUrl = 'https://api.paxiom.org';
  }
  return {
    name: REMOTE_MCP_SERVER_INFO.name,
    title: REMOTE_MCP_SERVER_INFO.title,
    version: REMOTE_MCP_SERVER_INFO.version,
    description:
      'Verify and explain Ed25519 proof-bound receipts (paxiom.receipt.v0) for x402 APIs, and discover live Base USDC settlement & preflight endpoints.',
    websiteUrl: 'https://paxiom.org/receipts.html',
    transport: {
      type: 'streamable-http',
      url: `${baseUrl}/mcp`
    },
    protocolVersion: DEFAULT_MCP_HTTP_PROTOCOL_VERSION,
    supportedProtocolVersions: Array.from(SUPPORTED_MCP_HTTP_VERSIONS),
    stateless: true,
    tools: REMOTE_MCP_TOOLS.map((t) => ({ name: t.name, description: t.description }))
  };
}

export function handleRemoteMcpMessage(msg, env = {}, onMcpEvent = null) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') {
    const rawId = msg && typeof msg === 'object' && !Array.isArray(msg) && Object.hasOwn(msg, 'id') ? msg.id : null;
    return jsonRpcError(isValidJsonRpcId(rawId) ? rawId : null, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  if (Object.hasOwn(msg, 'id') && !isValidJsonRpcId(msg.id)) {
    return jsonRpcError(null, -32600, 'Invalid JSON-RPC 2.0 id: must be string, finite number, or null');
  }

  // Client JSON-RPC response (has result or error, no method) -> acknowledge with 202 (null)
  if (!Object.hasOwn(msg, 'method')) {
    if (Object.hasOwn(msg, 'result') || Object.hasOwn(msg, 'error')) {
      return null;
    }
    return jsonRpcError(Object.hasOwn(msg, 'id') ? msg.id : null, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  if (typeof msg.method !== 'string') {
    return jsonRpcError(Object.hasOwn(msg, 'id') ? msg.id : null, -32600, 'Invalid JSON-RPC 2.0 method');
  }

  // Notifications (e.g. notifications/initialized) do not carry an `id`
  if (!Object.hasOwn(msg, 'id')) {
    return null;
  }

  if (typeof onMcpEvent === 'function') onMcpEvent({ kind: 'jsonrpc' });
  const { id, method } = msg;
  const params = msg.params && typeof msg.params === 'object' ? msg.params : {};

  if (method === 'initialize') {
    const requestedVersion = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiatedVersion = SUPPORTED_MCP_HTTP_VERSIONS.has(requestedVersion)
      ? requestedVersion
      : DEFAULT_MCP_HTTP_PROTOCOL_VERSION;
    return jsonRpcResult(id, {
      protocolVersion: negotiatedVersion,
      capabilities: {
        tools: { listChanged: false }
      },
      serverInfo: REMOTE_MCP_SERVER_INFO,
      instructions:
        'Use verify_receipt or explain_receipt to check paxiom.receipt.v0 cryptographic receipts offline for free. Use get_x402_verifier_info for live Base USDC settlement counter-attestation ($0.002) and pre-payment x402 seller preflight ($0.01) endpoints.'
    });
  }

  if (method === 'ping') {
    return jsonRpcResult(id, {});
  }

  if (method === 'tools/list') {
    return jsonRpcResult(id, { tools: REMOTE_MCP_TOOLS });
  }

  if (method === 'prompts/list') {
    return jsonRpcResult(id, { prompts: [] });
  }

  if (method === 'resources/list') {
    return jsonRpcResult(id, { resources: [] });
  }

  if (method === 'tools/call') {
    const toolName = params.name;
    const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};

    if (typeof onMcpEvent === 'function' && (toolName === 'verify_receipt' || toolName === 'explain_receipt' || toolName === 'get_x402_verifier_info')) {
      onMcpEvent({ kind: 'tool', tool: toolName });
    }
    try {
      if (toolName === 'verify_receipt' || toolName === 'explain_receipt') {
        if (!args.receipt || typeof args.receipt !== 'object' || Array.isArray(args.receipt)) {
          return jsonRpcResult(id, {
            isError: true,
            content: [{ type: 'text', text: 'Missing required object argument: receipt' }]
          });
        }
        const opts = {};
        if (Object.hasOwn(args, 'output')) {
          opts.output = args.output;
        }
        if (Array.isArray(args.trustedPaxiomPublicKeys)) {
          opts.trustedPaxiomPublicKeys = args.trustedPaxiomPublicKeys;
        } else {
          const hostKey = resolveHostPaxiomPublicKey(env);
          if (hostKey) {
            opts.trustedPaxiomPublicKeys = [hostKey.publicKey];
          }
        }
        const verdict = verifyReceipt(args.receipt, opts);
        if (toolName === 'explain_receipt') {
          const explanation = explain(verdict);
          return jsonRpcResult(id, {
            isError: false,
            content: [{ type: 'text', text: explanation }],
            structuredContent: {
              explanation,
              valid: verdict.valid,
              trustState: verdict.trustState,
              receiptHash: verdict.receiptHash
            }
          });
        }
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify(verdict, null, 2) }],
          structuredContent: verdict
        });
      }

      if (toolName === 'get_x402_verifier_info') {
        const info = buildVerifierDiscoveryPayload(env);
        return jsonRpcResult(id, {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify(info, null, 2) }],
          structuredContent: info
        });
      }

      if (toolName === 'issue_receipt') {
        return jsonRpcResult(id, {
          isError: true,
          content: [{
            type: 'text',
            text: 'issue_receipt is intentionally disabled on the remote HTTP MCP server so private keys never traverse the network. Run `npx --yes --package=@paxiom/receipts paxiom-receipt-mcp` locally or use `withPaxiomReceipt` from `@paxiom/receipts`.'
          }]
        });
      }

      return jsonRpcError(id, -32601, `Unknown tool: ${String(toolName || '')}`);
    } catch (err) {
      return jsonRpcResult(id, {
        isError: true,
        content: [{ type: 'text', text: `Tool error: ${(err && err.message) || err}` }]
      });
    }
  }

  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

/**
 * HTTP route handler for `/mcp` (`POST`, `GET`, `DELETE`).
 */
export async function handleMcpHttpRequest(req, res, { env = {}, readBody, corsHeaders = {}, onMcpEvent = null }) {
  const sendJson = (status, payload, extraHeaders = {}) => {
    res.writeHead(status, {
      'content-type': 'application/json',
      'x-content-type-options': 'nosniff',
      ...corsHeaders,
      ...extraHeaders
    });
    res.end(JSON.stringify(payload));
  };

  if (req.method === 'DELETE') {
    return sendJson(
      405,
      jsonRpcError(null, -32000, 'Stateless MCP server: session termination is not required.'),
      { allow: 'POST, GET, OPTIONS' }
    );
  }

  if (req.method === 'GET') {
    const accept = String((req.headers && req.headers.accept) || '').toLowerCase();
    // Per MCP Streamable-HTTP spec, stateless servers without server-initiated SSE streams
    // MUST return 405 Method Not Allowed when a client attempts to open an SSE listener.
    if (accept.includes('text/event-stream')) {
      return sendJson(
        405,
        jsonRpcError(null, -32000, 'Stateless MCP server does not open server-push SSE streams; send JSON-RPC requests via POST /mcp.'),
        { allow: 'POST, OPTIONS' }
      );
    }
    if (typeof onMcpEvent === 'function') onMcpEvent({ kind: 'get_metadata' });
    return sendJson(200, {
      service: REMOTE_MCP_SERVER_INFO.name,
      title: REMOTE_MCP_SERVER_INFO.title,
      version: REMOTE_MCP_SERVER_INFO.version,
      transport: 'streamable-http',
      protocolVersion: DEFAULT_MCP_HTTP_PROTOCOL_VERSION,
      supportedProtocolVersions: Array.from(SUPPORTED_MCP_HTTP_VERSIONS),
      stateless: true,
      endpoint: 'POST /mcp',
      tools: REMOTE_MCP_TOOLS.map((t) => ({ name: t.name, description: t.description }))
    });
  }

  if (req.method !== 'POST') {
    return sendJson(
      405,
      jsonRpcError(null, -32000, `Method ${req.method} not allowed on /mcp`),
      { allow: 'POST, GET, OPTIONS' }
    );
  }

  let raw;
  try {
    raw = await readBody(req);
  } catch (err) {
    if (err && err.code === 'body_too_large') {
      return sendJson(413, jsonRpcError(null, -32600, 'JSON-RPC request body exceeds 256 KiB limit'), {
        connection: 'close'
      });
    }
    return sendJson(400, jsonRpcError(null, -32700, 'Failed to read request body'));
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return sendJson(400, jsonRpcError(null, -32700, 'Parse error: request body is not valid JSON'));
  }

  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      return sendJson(400, jsonRpcError(null, -32600, 'Invalid JSON-RPC batch: empty array'));
    }
    if (parsed.length > MAX_MCP_BATCH_SIZE) {
      return sendJson(400, jsonRpcError(null, -32600, `JSON-RPC batch exceeds maximum size (${MAX_MCP_BATCH_SIZE})`));
    }
    const responses = [];
    for (const item of parsed) {
      const out = handleRemoteMcpMessage(item, env, onMcpEvent);
      if (out !== null) responses.push(out);
    }
    if (responses.length === 0) {
      res.writeHead(202, { 'x-content-type-options': 'nosniff', ...corsHeaders });
      return res.end();
    }
    return sendJson(200, responses);
  }

  const singleResponse = handleRemoteMcpMessage(parsed, env, onMcpEvent);
  if (singleResponse === null) {
    res.writeHead(202, { 'x-content-type-options': 'nosniff', ...corsHeaders });
    return res.end();
  }
  return sendJson(200, singleResponse);
}
