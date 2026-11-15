import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from '../server.mjs';
import { generateReceiptKeyPair, issueReceipt } from '../../../standards/receipts/v0/src/issue.mjs';

const EX = new URL('../../../standards/receipts/v0/examples/', import.meta.url);
const validReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const validOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

async function withServer(options, fn) {
  const srv = createServer(options);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => srv.close(r));
  }
}

test('POST /mcp negotiates Streamable-HTTP initialize + 202 notification + tools/list', async () => {
  await withServer({ env: {} }, async (base) => {
    const initRes = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'test-client', version: '1.0.0' }
        }
      })
    });
    assert.equal(initRes.status, 200);
    const initBody = await initRes.json();
    assert.equal(initBody.jsonrpc, '2.0');
    assert.equal(initBody.id, 1);
    assert.equal(initBody.result.protocolVersion, '2025-03-26');
    assert.equal(initBody.result.serverInfo.name, 'io.github.k-luecke/paxiom-receipts');

    // Notification must return 202 Accepted with empty body per Streamable-HTTP spec
    const notifRes = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
    });
    assert.equal(notifRes.status, 202);
    assert.equal(await notifRes.text(), '');

    const listRes = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
    });
    assert.equal(listRes.status, 200);
    const listBody = await listRes.json();
    const names = listBody.result.tools.map((t) => t.name);
    assert.deepEqual(names, ['verify_receipt', 'explain_receipt', 'get_x402_verifier_info']);
  });
});

test('POST /mcp verify_receipt, explain_receipt, get_x402_verifier_info, and issue_receipt safety guard', async () => {
  const hostKey = generateReceiptKeyPair({ keyId: 'paxiom-live-verifier-001' });
  const counterReceipt = issueReceipt({
    privateKey: hostKey.privateKeyPem,
    issuer: { name: 'Paxiom Receipt Verifier', uri: 'https://paxiom.org', keyId: hostKey.keyId },
    service: { name: 'Demo Paid Service', resource: 'https://seller.example/api', method: 'POST' },
    payment: {
      scheme: 'x402',
      network: 'base',
      asset: 'USDC',
      amountAtomic: '2000',
      settlement: {
        status: 'verified_settled',
        transactionHash: '0x' + 'ab'.repeat(32),
        checkedByPaxiom: true
      }
    },
    output: validOutput
  }).receipt;

  const env = {
    LIVE_VERIFY_ENABLED: 'true',
    X402_ENABLED: 'true',
    X402_PAY_TO: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4',
    PAXIOM_SIGNING_PRIVATE_KEY_PEM: hostKey.privateKeyPem,
    PAXIOM_SIGNING_KEY_ID: hostKey.keyId
  };

  await withServer({ env }, async (base) => {
    // 1. Verify standard fixture receipt
    const v1 = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: {
          name: 'verify_receipt',
          arguments: { receipt: validReceipt, output: validOutput }
        }
      })
    });
    const b1 = await v1.json();
    assert.equal(b1.result.isError, false);
    assert.equal(b1.result.structuredContent.valid, true);
    assert.equal(b1.result.structuredContent.trustState, 'verified');

    // 2. Verify host counter-attested receipt (checkedByPaxiom=true) without passing trustedPaxiomPublicKeys
    const v2 = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: {
          name: 'verify_receipt',
          arguments: { receipt: counterReceipt, output: validOutput }
        }
      })
    });
    const b2 = await v2.json();
    assert.equal(b2.result.structuredContent.valid, true);
    assert.equal(b2.result.structuredContent.trustState, 'verified');

    // 3. explain_receipt returns human/agent text + structuredContent matching outputSchema
    const v3 = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: {
          name: 'explain_receipt',
          arguments: { receipt: validReceipt, output: validOutput }
        }
      })
    });
    const b3 = await v3.json();
    assert.equal(b3.result.isError, false);
    assert.match(b3.result.content[0].text, /verified/i);
    assert.equal(b3.result.structuredContent.valid, true);
    assert.equal(b3.result.structuredContent.trustState, 'verified');
    assert.equal(b3.result.structuredContent.explanation, b3.result.content[0].text);

    // 4. get_x402_verifier_info returns live discovery routes + public key
    const v4 = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 13,
        method: 'tools/call',
        params: { name: 'get_x402_verifier_info', arguments: {} }
      })
    });
    const b4 = await v4.json();
    assert.equal(b4.result.isError, false);
    assert.equal(b4.result.structuredContent.trustedPaxiomKeys[0].publicKey, hostKey.publicKey);
    assert.equal(b4.result.structuredContent.paidX402Endpoints.routes.length, 2);

    // 5. issue_receipt is explicitly blocked over remote HTTP
    const v5 = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 14,
        method: 'tools/call',
        params: { name: 'issue_receipt', arguments: {} }
      })
    });
    const b5 = await v5.json();
    assert.equal(b5.result.isError, true);
    assert.match(b5.result.content[0].text, /intentionally disabled/i);
  });
});

test('GET /mcp SSE probe -> 405, GET /mcp JSON -> 200, DELETE /mcp -> 405, batch & parse bounds', async () => {
  await withServer({ env: {} }, async (base) => {
    // SSE listener probe must return 405 Method Not Allowed on stateless server
    const sseProbe = await fetch(`${base}/mcp`, {
      headers: { accept: 'text/event-stream' }
    });
    assert.equal(sseProbe.status, 405);
    assert.match(sseProbe.headers.get('allow') || '', /POST/);

    // Browser / directory probe returns 200 JSON discovery metadata
    const jsonProbe = await fetch(`${base}/mcp`, {
      headers: { accept: 'application/json' }
    });
    assert.equal(jsonProbe.status, 200);
    const meta = await jsonProbe.json();
    assert.equal(meta.transport, 'streamable-http');
    assert.equal(meta.stateless, true);

    // Session teardown returns 405 on stateless server
    const delProbe = await fetch(`${base}/mcp`, { method: 'DELETE' });
    assert.equal(delProbe.status, 405);

    // Malformed JSON -> 400 -32700
    const badJson = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{invalid'
    });
    assert.equal(badJson.status, 400);
    assert.equal((await badJson.json()).error.code, -32700);

    // Empty batch -> 400 -32600
    const emptyBatch = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '[]'
    });
    assert.equal(emptyBatch.status, 400);
    assert.equal((await emptyBatch.json()).error.code, -32600);

    // Oversized batch (>32 items) -> 400 -32600
    const hugeBatch = Array.from({ length: 33 }, (_, i) => ({ jsonrpc: '2.0', id: i, method: 'ping' }));
    const hugeRes = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(hugeBatch)
    });
    assert.equal(hugeRes.status, 400);
    assert.equal((await hugeRes.json()).error.code, -32600);

    // Mixed request + notification batch returns only request responses
    const mixedBatch = [
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 99, method: 'ping' }
    ];
    const mixedRes = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(mixedBatch)
    });
    assert.equal(mixedRes.status, 200);
    const mixedBody = await mixedRes.json();
    assert.equal(mixedBody.length, 1);
    assert.equal(mixedBody[0].id, 99);

    // FERMI-PAX-R2-03: Non-conforming JSON-RPC id (object, array, boolean) rejected -32600 with id: null
    for (const badId of [{ nested: [1, 2, 3] }, [1, 2], true]) {
      const badIdRes = await fetch(`${base}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: badId, method: 'ping' })
      });
      assert.equal(badIdRes.status, 200);
      const badIdBody = await badIdRes.json();
      assert.equal(badIdBody.id, null);
      assert.equal(badIdBody.error.code, -32600);
    }

    // Even when jsonrpc !== '2.0', invalid object id is never echoed
    const badVerObjId = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '1.0', id: { leak: true }, method: 'ping' })
    });
    const badVerBody = await badVerObjId.json();
    assert.equal(badVerBody.id, null);
    assert.equal(badVerBody.error.code, -32600);
  });

  // FERMI-PAX-R2-03: Malformed X402_RESOURCE_URL falls back cleanly to https://api.paxiom.org
  await withServer({ env: { LIVE_VERIFY_ENABLED: 'true', X402_RESOURCE_URL: 'not-a-valid-url' } }, async (base) => {
    const res = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'info-fallback',
        method: 'tools/call',
        params: { name: 'get_x402_verifier_info', arguments: {} }
      })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.result.isError, false);
    assert.equal(body.result.structuredContent.baseUrl, 'https://api.paxiom.org');
  });
});

test('GET /, /openapi.json, /llms.txt, /.well-known/mcp.json, and zero-PII GET /stats counters', async () => {
  await withServer(
    {
      env: {
        LIVE_VERIFY_ENABLED: 'true',
        X402_ENABLED: 'true',
        X402_PAY_TO: '0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4'
      }
    },
    async (base) => {
      const rootRes = await fetch(`${base}/`);
      assert.equal(rootRes.status, 200);
      const rootJson = await rootRes.json();
      assert.equal(rootJson.ok, true);
      assert.equal(rootJson.version, '0.1.3');
      assert.equal(rootJson.discovery.openApi, '/openapi.json');
      assert.equal(rootJson.discovery.x402Manifest, '/.well-known/x402.json');

      const oaRes = await fetch(`${base}/openapi.json`);
      assert.equal(oaRes.status, 200);
      const oaJson = await oaRes.json();
      assert.equal(oaJson.info.version, '0.1.3');
      assert.ok(oaJson.paths['/v1/x402/preflight']);

      const llmsRes = await fetch(`${base}/llms.txt`);
      assert.equal(llmsRes.status, 200);
      assert.match(llmsRes.headers.get('content-type') || '', /text\/plain/);
      const llmsText = await llmsRes.text();
      assert.match(llmsText, /paxiom\.receipt\.v0/);

      const cardRes = await fetch(`${base}/.well-known/mcp.json`);
      assert.equal(cardRes.status, 200);
      const cardJson = await cardRes.json();
      assert.equal(cardJson.name, 'io.github.k-luecke/paxiom-receipts');
      assert.equal(cardJson.version, '0.1.3');

      // Trigger one unpaid 402 quote on preflight + one MCP tool call + one demo read
      const demo = await (await fetch(`${base}/v1/receipt/demo`)).json();
      const vRes = await fetch(`${base}/v1/receipt/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ receipt: demo.receipt, output: demo.output })
      });
      assert.equal((await vRes.json()).valid, true);

      const q402 = await fetch(`${base}/v1/x402/preflight`);
      assert.equal(q402.status, 402);

      await fetch(`${base}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'get_x402_verifier_info', arguments: {} }
        })
      });

      const statsRes = await fetch(`${base}/stats`);
      assert.equal(statsRes.status, 200);
      const stats = await statsRes.json();
      assert.equal(stats.ok, true);
      assert.equal(stats.privacy, 'aggregate_counters_only_zero_pii');
      assert.equal(stats.discovery.rootIndexReads, 1);
      assert.equal(stats.discovery.openApiReads, 1);
      assert.equal(stats.discovery.llmsTxtReads, 1);
      assert.equal(stats.discovery.mcpCardReads, 1);
      assert.equal(stats.discovery.mcpJsonRpcCalls, 1);
      assert.equal(stats.discovery.mcpToolCalls.get_x402_verifier_info, 1);
      assert.equal(stats.offlineVerify.demoReads, 1);
      assert.equal(stats.offlineVerify.calls, 1);
      assert.equal(stats.offlineVerify.validVerdicts, 1);
      assert.equal(stats.x402Preflight.unpaid402Quotes, 1);
    }
  );
});
