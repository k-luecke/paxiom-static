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

export const REMOTE_MCP_TOOLS = Object.freeze([
  {
    name: 'verify_receipt',
    description:
      'Verify a paxiom.receipt.v0 cryptographic receipt (schema, Ed25519 signature, output SHA-256 JCS binding, expiry, and honest settlement/proof trust state). Deterministic and free; automatically trusts the host Paxiom counter-attestation public key when trustedPaxiomPublicKeys is omitted.',
    annotations: {
      title: 'Verify Paxiom Receipt (Offline)',
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
          description: 'Parsed paxiom.receipt.v0 JSON object (or decoded X-Paxiom-Receipt header).'
        },
        output: {
          description: 'Optional delivered API response JSON to verify payment-to-output SHA-256 hash binding.'
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
    description:
      'Verify a paxiom.receipt.v0 receipt and return a concise human/agent-readable trust-state breakdown and next-action guidance.',
    annotations: {
      title: 'Explain Paxiom Receipt Verdict',
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
          description: 'Parsed paxiom.receipt.v0 JSON object.'
        },
        output: {
          description: 'Optional delivered API response JSON.'
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
    name: 'get_x402_verifier_info',
    description:
      'Return Paxiom Receipt Verifier service metadata, published Ed25519 counter-attestation public keys, and x402 Base USDC payment terms for live on-chain settlement verification ($0.002 USDC) and pre-payment seller preflight ($0.01 USDC).',
    annotations: {
      title: 'Get Paxiom x402 Verifier & Preflight Info',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    },
    inputSchema: {
      type: 'object',
      properties: {}
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
export function handleRemoteMcpMessage(msg, env = {}) {
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
          return jsonRpcResult(id, {
            isError: false,
            content: [{ type: 'text', text: explain(verdict) }]
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
export async function handleMcpHttpRequest(req, res, { env = {}, readBody, corsHeaders = {} }) {
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
      const out = handleRemoteMcpMessage(item, env);
      if (out !== null) responses.push(out);
    }
    if (responses.length === 0) {
      res.writeHead(202, { 'x-content-type-options': 'nosniff', ...corsHeaders });
      return res.end();
    }
    return sendJson(200, responses);
  }

  const singleResponse = handleRemoteMcpMessage(parsed, env);
  if (singleResponse === null) {
    res.writeHead(202, { 'x-content-type-options': 'nosniff', ...corsHeaders });
    return res.end();
  }
  return sendJson(200, singleResponse);
}
