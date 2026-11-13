import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { handleJsonRpcMessage } from './server.mjs';
import { generateReceiptKeyPair } from '../src/issue.mjs';
import { verifyReceipt } from '../src/verify.mjs';

const EX = new URL('../examples/', import.meta.url);
const validReceipt = JSON.parse(readFileSync(new URL('valid.receipt.json', EX), 'utf8'));
const validOutput = JSON.parse(readFileSync(new URL('valid.output.json', EX), 'utf8'));

test('MCP initialize + tools/list exposes verify_receipt, explain_receipt, and issue_receipt', () => {
  const init = handleJsonRpcMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(init.result.serverInfo.name, 'paxiom-receipt-mcp');

  const list = handleJsonRpcMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = list.result.tools.map((t) => t.name);
  assert.deepEqual(names, ['verify_receipt', 'explain_receipt', 'issue_receipt']);
});

test('MCP verify_receipt and issue_receipt round-trip', () => {
  const kp = generateReceiptKeyPair({ keyId: 'mcp-k1' });
  const issued = handleJsonRpcMessage(
    {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: {
        name: 'issue_receipt',
        arguments: {
          issuerName: 'MCP Test Seller',
          keyId: kp.keyId,
          resource: 'https://mcp.example.com/tool',
          output: { answer: 'hello-agent' }
        }
      }
    },
    { PAXIOM_ISSUER_PRIVATE_KEY_PEM: kp.privateKeyPem }
  );
  assert.equal(issued.result.isError, false);
  const { receipt } = issued.result.structuredContent;
  assert.equal(verifyReceipt(receipt, { output: { answer: 'hello-agent' } }).trustState, 'verified');

  const verified = handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 11,
    method: 'tools/call',
    params: {
      name: 'verify_receipt',
      arguments: { receipt: validReceipt, output: validOutput }
    }
  });
  assert.equal(verified.result.isError, false);
  assert.equal(verified.result.structuredContent.trustState, 'verified');
});

test('MCP stdio transport processes newline-delimited JSON-RPC messages over child process', async () => {
  const serverPath = new URL('./server.mjs', import.meta.url).pathname;
  const child = spawn(process.execPath, [serverPath], { stdio: ['pipe', 'pipe', 'pipe'] });

  const lines = [];
  let buf = '';
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line) lines.push(JSON.parse(line));
    }
  });

  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  child.stdin.write(JSON.stringify({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'explain_receipt', arguments: { receipt: validReceipt, output: validOutput } }
  }) + '\n');
  child.stdin.end();

  await new Promise((resolve) => child.on('close', resolve));
  assert.equal(lines.length, 2);
  assert.equal(lines[0].id, 1);
  assert.equal(lines[1].id, 2);
  assert.match(lines[1].result.content[0].text, /VERIFIED/);
});
