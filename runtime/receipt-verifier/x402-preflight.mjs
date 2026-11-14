// SSRF-hardened pre-payment x402 seller readiness & trust scanner (`POST /v1/x402/preflight`).
//
// Evaluates an untrusted x402 endpoint BEFORE a buyer agent signs an EIP-3009 payment:
//   1. Strict URL + DNS + IP range guard (https:443 only, blocks private/loopback/CGNAT/metadata
//      IPv4 & IPv6, pins resolved IP for TLS SNI connection, never follows redirects).
//   2. Probes the target's unpaid 402 challenge + `/.well-known/x402.json` + `/.well-known/paxiom-keys.json`.
//   3. Verifies canonical Base / Base Sepolia Circle USDC asset address, EIP-712 domain parameters,
//      `payTo` validity & manifest consistency (bait-and-switch detection), budget cap, and whether
//      the seller supports proof-bound `paxiom.receipt.v0` (`X-Paxiom-Receipt`).
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';
import { getSupportedNetworkConfig, EVM_ADDRESS_RE } from './onchain-settlement.mjs';

const MAX_URL_LENGTH = 2048;
const DNS_TIMEOUT_MS = 4000;
const PROBE_TIMEOUT_MS = 6000;
const WELL_KNOWN_TIMEOUT_MS = 4000;
const MAX_PROBE_BODY_BYTES = 64 * 1024; // 64 KiB
const HIGH_SINGLE_CALL_USDC_ATOMIC = 100_000_000n; // $100.00 USDC (6 decimals)
const DEC_UINT_RE = /^[0-9]+$/;

const ZERO_OR_BURN_ADDRESSES = new Set([
  '0x0000000000000000000000000000000000000000',
  '0x000000000000000000000000000000000000dead'
]);

const BLOCKED_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.home.arpa',
  '.lan',
  '.nip.io',
  '.sslip.io',
  '.xip.io'
];

function parseIpv4Uint32(ip) {
  if (net.isIP(ip) !== 4) return null;
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    acc = ((acc << 8) | n) >>> 0;
  }
  return acc >>> 0;
}

export function isPublicGlobalIpv4Uint32(u) {
  const v = u >>> 0;
  if (((v & 0xff000000) >>> 0) === 0x00000000) return false; // 0.0.0.0/8 ("this" network)
  if (((v & 0xff000000) >>> 0) === 0x0a000000) return false; // 10.0.0.0/8 (RFC 1918)
  if (((v & 0xffc00000) >>> 0) === 0x64400000) return false; // 100.64.0.0/10 (RFC 6598 CGNAT)
  if (((v & 0xff000000) >>> 0) === 0x7f000000) return false; // 127.0.0.0/8 (loopback)
  if (((v & 0xffff0000) >>> 0) === 0xa9fe0000) return false; // 169.254.0.0/16 (link-local / cloud metadata)
  if (((v & 0xfff00000) >>> 0) === 0xac100000) return false; // 172.16.0.0/12 (RFC 1918)
  if (((v & 0xffffff00) >>> 0) === 0xc0000000) return false; // 192.0.0.0/24 (IETF)
  if (((v & 0xffffff00) >>> 0) === 0xc0000200) return false; // 192.0.2.0/24 (TEST-NET-1)
  if (((v & 0xffffff00) >>> 0) === 0xc0586300) return false; // 192.88.99.0/24 (6to4 anycast)
  if (((v & 0xffff0000) >>> 0) === 0xc0a80000) return false; // 192.168.0.0/16 (RFC 1918)
  if (((v & 0xfffe0000) >>> 0) === 0xc6120000) return false; // 198.18.0.0/15 (benchmarking)
  if (((v & 0xffffff00) >>> 0) === 0xc6336400) return false; // 198.51.100.0/24 (TEST-NET-2)
  if (((v & 0xffffff00) >>> 0) === 0xcb007100) return false; // 203.0.113.0/24 (TEST-NET-3)
  if (((v & 0xe0000000) >>> 0) === 0xe0000000) return false; // 224.0.0.0/3 (multicast + reserved/broadcast)
  return true;
}

function parseIpv6Groups(ip) {
  if (typeof ip !== 'string' || ip.includes('%') || net.isIP(ip) !== 6) return null;
  let normalized = ip.toLowerCase();

  // Convert trailing dotted-quad IPv4 (e.g. ::ffff:127.0.0.1) into two 16-bit hex groups
  const lastColon = normalized.lastIndexOf(':');
  if (lastColon !== -1 && normalized.slice(lastColon + 1).includes('.')) {
    const v4Str = normalized.slice(lastColon + 1);
    const u32 = parseIpv4Uint32(v4Str);
    if (u32 === null) return null;
    const hi = ((u32 >>> 16) & 0xffff).toString(16);
    const lo = (u32 & 0xffff).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const dblParts = normalized.split('::');
  if (dblParts.length > 2) return null;

  let groups;
  if (dblParts.length === 2) {
    const left = dblParts[0] ? dblParts[0].split(':') : [];
    const right = dblParts[1] ? dblParts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    groups = normalized.split(':');
  }

  if (groups.length !== 8) return null;
  const nums = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    nums.push(parseInt(g, 16));
  }
  return nums;
}

export function isPublicGlobalIp(ip) {
  if (typeof ip !== 'string' || !ip || ip.includes('%')) return false;
  const kind = net.isIP(ip);
  if (kind === 4) {
    const u32 = parseIpv4Uint32(ip);
    return u32 !== null && isPublicGlobalIpv4Uint32(u32);
  }
  if (kind === 6) {
    const g = parseIpv6Groups(ip);
    if (!g) return false;
    const allZeroPrefix6 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
    // :: (unspecified) or ::1 (loopback) or ::/96 IPv4-compatible
    if (allZeroPrefix6 && g[5] === 0) {
      if (g[6] === 0 && (g[7] === 0 || g[7] === 1)) return false;
      return isPublicGlobalIpv4Uint32(((g[6] << 16) | g[7]) >>> 0);
    }
    // ::ffff:0:0/96 IPv4-mapped IPv6
    if (allZeroPrefix6 && g[5] === 0xffff) {
      return isPublicGlobalIpv4Uint32(((g[6] << 16) | g[7]) >>> 0);
    }
    // NAT64 64:ff9b::/96 and 64:ff9b:1::/48
    if (g[0] === 0x0064 && g[1] === 0xff9b && (g[2] === 0 || g[2] === 1)) {
      return isPublicGlobalIpv4Uint32(((g[6] << 16) | g[7]) >>> 0);
    }
    // 6to4 2002::/16
    if (g[0] === 0x2002) {
      return isPublicGlobalIpv4Uint32(((g[1] << 16) | g[2]) >>> 0);
    }
    // Discard 100::/64, Teredo 2001:0000::/32, Documentation 2001:db8::/32
    if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return false;
    if (g[0] === 0x2001 && (g[1] === 0x0000 || g[1] === 0x0db8)) return false;
    // Unique local fc00::/7, Link-local fe80::/10, Multicast ff00::/8
    if ((g[0] & 0xfe00) === 0xfc00) return false;
    if ((g[0] & 0xffc0) === 0xfe80) return false;
    if ((g[0] & 0xff00) === 0xff00) return false;
    // Public IANA global unicast resides strictly in 2000::/3
    return (g[0] & 0xe000) === 0x2000;
  }
  return false;
}

function withTimeout(promise, ms, errCode, errMsg) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(Object.assign(new Error(errMsg), { code: errCode }));
    }, ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

/**
 * Validate a caller-supplied URL and pre-resolve its DNS records to public global IPs
 * BEFORE charging x402 payment or opening any outbound socket.
 */
export async function validatePublicHttpsTarget(rawUrl, { lookupImpl = dns.lookup } = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, code: 'missing_target_url', message: 'Field "url" must be a non-empty https:// URL string.' };
  }
  const trimmed = rawUrl.trim();
  if (trimmed.length > MAX_URL_LENGTH) {
    return { ok: false, code: 'invalid_target_url', message: `Target URL exceeds ${MAX_URL_LENGTH} characters.` };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, code: 'invalid_target_url', message: 'Target URL is not a valid URL.' };
  }

  if (parsed.protocol !== 'https:') {
    return { ok: false, code: 'invalid_target_scheme', message: 'Target URL must use https:// (plaintext http:// and non-HTTP schemes are rejected).' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, code: 'invalid_target_url', message: 'Target URL must not contain embedded credentials.' };
  }
  if (parsed.port && parsed.port !== '443') {
    return { ok: false, code: 'disallowed_target_port', message: 'Target URL must use standard HTTPS port 443.' };
  }

  const bareHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!bareHost) {
    return { ok: false, code: 'invalid_target_url', message: 'Target URL is missing a hostname.' };
  }
  if (bareHost === 'localhost' || BLOCKED_HOST_SUFFIXES.some((sfx) => bareHost.endsWith(sfx))) {
    return { ok: false, code: 'ssrf_blocked', message: `Target hostname "${bareHost}" is in a disallowed local or rebinding domain.` };
  }

  const literalKind = net.isIP(bareHost);
  if (literalKind !== 0) {
    if (!isPublicGlobalIp(bareHost)) {
      return {
        ok: false,
        code: 'ssrf_blocked',
        message: 'Target IP address is in a private, loopback, link-local, or reserved range.'
      };
    }
    return {
      ok: true,
      parsedUrl: parsed,
      normalizedUrl: parsed.toString(),
      origin: parsed.origin,
      hostname: bareHost,
      pinnedIp: bareHost,
      pinnedFamily: literalKind
    };
  }

  if (!bareHost.includes('.')) {
    return { ok: false, code: 'ssrf_blocked', message: 'Single-label internal hostnames are not allowed.' };
  }

  let records;
  try {
    const rawRecords = await withTimeout(
      lookupImpl(bareHost, { all: true, verbatim: true }),
      DNS_TIMEOUT_MS,
      'dns_timeout',
      `DNS lookup timed out for ${bareHost}`
    );
    records = Array.isArray(rawRecords) ? rawRecords : (rawRecords ? [rawRecords] : []);
  } catch {
    return { ok: false, code: 'dns_resolution_failed', message: `Could not resolve public DNS records for "${bareHost}".` };
  }

  if (records.length === 0) {
    return { ok: false, code: 'dns_resolution_failed', message: `No DNS records returned for "${bareHost}".` };
  }

  for (const rec of records) {
    const addr = rec && rec.address;
    if (!addr || !isPublicGlobalIp(addr)) {
      return {
        ok: false,
        code: 'ssrf_blocked',
        message: `Target hostname "${bareHost}" resolves to a private, loopback, or reserved IP address.`
      };
    }
  }

  const chosen = records.find((r) => net.isIP(r.address) === 4) || records[0];
  return {
    ok: true,
    parsedUrl: parsed,
    normalizedUrl: parsed.toString(),
    origin: parsed.origin,
    hostname: bareHost,
    pinnedIp: chosen.address,
    pinnedFamily: chosen.family || net.isIP(chosen.address)
  };
}

async function readBoundedResponseFetch(fetchImpl, url, { method, headers, body, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method,
      headers,
      ...(body !== undefined ? { body } : {}),
      redirect: 'manual',
      signal: controller.signal
    });

    const outHeaders = Object.create(null);
    if (res.headers && typeof res.headers.forEach === 'function') {
      res.headers.forEach((v, k) => {
        outHeaders[String(k).toLowerCase()] = String(v);
      });
    }

    let bodyBuf = Buffer.alloc(0);
    let truncated = false;
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const buf = Buffer.from(value);
        if (total + buf.length > MAX_PROBE_BODY_BYTES) {
          chunks.push(buf.subarray(0, MAX_PROBE_BODY_BYTES - total));
          truncated = true;
          try { await reader.cancel(); } catch { /* ignore */ }
          break;
        }
        chunks.push(buf);
        total += buf.length;
      }
      bodyBuf = Buffer.concat(chunks);
    } else if (typeof res.text === 'function') {
      const txt = await res.text();
      const full = Buffer.from(txt, 'utf8');
      if (full.length > MAX_PROBE_BODY_BYTES) {
        bodyBuf = full.subarray(0, MAX_PROBE_BODY_BYTES);
        truncated = true;
      } else {
        bodyBuf = full;
      }
    }

    return {
      status: Number(res.status) || 0,
      headers: outHeaders,
      bodyText: bodyBuf.toString('utf8'),
      truncated
    };
  } finally {
    clearTimeout(timer);
  }
}

function readBoundedResponsePinnedHttps(target, fullUrl, { method, headers, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(fullUrl);
    const pinnedLookup = (_hostname, opts, cb) => {
      const callback = typeof opts === 'function' ? opts : cb;
      if (opts && typeof opts === 'object' && opts.all) {
        return callback(null, [{ address: target.pinnedIp, family: target.pinnedFamily }]);
      }
      return callback(null, target.pinnedIp, target.pinnedFamily);
    };

    const req = https.request({
      protocol: 'https:',
      hostname: target.hostname,
      port: 443,
      servername: target.hostname,
      path: `${parsed.pathname}${parsed.search}`,
      method,
      headers: {
        host: target.hostname,
        ...headers,
        ...(body !== undefined ? { 'content-length': String(Buffer.byteLength(body, 'utf8')) } : {})
      },
      lookup: pinnedLookup,
      agent: false
    }, (res) => {
      const outHeaders = Object.create(null);
      for (const [k, v] of Object.entries(res.headers || {})) {
        if (v !== undefined) {
          outHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
        }
      }
      const chunks = [];
      let total = 0;
      let truncated = false;
      let settled = false;

      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({
          status: Number(res.statusCode) || 0,
          headers: outHeaders,
          bodyText: Buffer.concat(chunks).toString('utf8'),
          truncated
        });
      };

      res.on('data', (chunk) => {
        if (settled) return;
        if (total + chunk.length > MAX_PROBE_BODY_BYTES) {
          chunks.push(chunk.subarray(0, MAX_PROBE_BODY_BYTES - total));
          truncated = true;
          res.destroy();
          finish();
          return;
        }
        chunks.push(chunk);
        total += chunk.length;
      });
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      });
    });

    const timer = setTimeout(() => {
      req.destroy(Object.assign(new Error('Upstream HTTPS probe timed out'), { code: 'probe_timeout' }));
    }, timeoutMs);

    req.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    if (body !== undefined) req.write(body);
    req.end();
  });
}

function decodePaymentRequiredHeader(headerVal) {
  if (!headerVal || typeof headerVal !== 'string') return null;
  const trimmed = headerVal.trim();
  if (!trimmed) return null;
  for (const enc of ['base64', 'base64url']) {
    try {
      const obj = JSON.parse(Buffer.from(trimmed, enc).toString('utf8'));
      if (obj && typeof obj === 'object') return obj;
    } catch {
      // try next encoding
    }
  }
  return null;
}

function safeParseJson(text) {
  if (!text || typeof text !== 'string') return null;
  try {
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' ? obj : null;
  } catch {
    return null;
  }
}

/**
 * Execute an SSRF-safe preflight probe against a validated HTTPS target.
 */
export async function runX402Preflight(validatedTarget, {
  method = 'POST',
  maxBudgetAtomic = null,
  expectedNetwork = null
} = {}, {
  fetchImpl = null
} = {}) {
  const upperMethod = String(method || 'POST').toUpperCase();
  const baseHeaders = {
    accept: 'application/json',
    'user-agent': 'Paxiom-x402-Preflight/0.1 (+https://paxiom.org)'
  };
  const probeHeaders = upperMethod === 'POST'
    ? { ...baseHeaders, 'content-type': 'application/json' }
    : baseHeaders;
  const probeBody = upperMethod === 'POST' ? '{}' : undefined;

  const doProbe = (url, opts) => (fetchImpl
    ? readBoundedResponseFetch(fetchImpl, url, opts)
    : readBoundedResponsePinnedHttps(validatedTarget, url, opts));

  const wkX402Url = `${validatedTarget.origin}/.well-known/x402.json`;
  const wkPaxiomKeysUrl = `${validatedTarget.origin}/.well-known/paxiom-keys.json`;

  const [mainOutcome, wkX402Outcome, wkKeysOutcome] = await Promise.all([
    doProbe(validatedTarget.normalizedUrl, {
      method: upperMethod,
      headers: probeHeaders,
      body: probeBody,
      timeoutMs: PROBE_TIMEOUT_MS
    }).then((res) => ({ ok: true, res }), (err) => ({ ok: false, err })),
    doProbe(wkX402Url, {
      method: 'GET',
      headers: baseHeaders,
      timeoutMs: WELL_KNOWN_TIMEOUT_MS
    }).then((res) => ({ ok: true, res }), () => ({ ok: false, res: null })),
    doProbe(wkPaxiomKeysUrl, {
      method: 'GET',
      headers: baseHeaders,
      timeoutMs: WELL_KNOWN_TIMEOUT_MS
    }).then((res) => ({ ok: true, res }), () => ({ ok: false, res: null }))
  ]);

  const findings = [];
  const checks = {
    httpChallenge: 'fail',
    networkSupported: 'not_checked',
    canonicalUsdcAsset: 'not_checked',
    eip712Domain: 'not_checked',
    payToAddress: 'not_checked',
    manifestConsistency: 'not_checked',
    budgetCap: maxBudgetAtomic !== null ? 'not_checked' : 'not_provided',
    bazaarSchema: 'not_detected',
    paxiomReceipts: 'not_detected'
  };

  if (!mainOutcome.ok) {
    findings.push({
      code: 'target_unreachable',
      severity: 'high',
      message: 'Target HTTPS endpoint timed out or refused connection during unpaid probe.'
    });
    return {
      ok: true,
      targetUrl: validatedTarget.normalizedUrl,
      probedMethod: upperMethod,
      verdict: 'block',
      riskLevel: 'high',
      httpStatus: 0,
      selectedQuote: null,
      recommendedMaxPaymentAtomic: null,
      checks,
      receiptSupport: { paxiomHeaderExposed: false, paxiomWellKnownKeys: 0 },
      findings
    };
  }

  const mainRes = mainOutcome.res;
  const wkX402Json = wkX402Outcome.ok && wkX402Outcome.res.status === 200
    ? safeParseJson(wkX402Outcome.res.bodyText)
    : null;
  const wkKeysJson = wkKeysOutcome.ok && wkKeysOutcome.res.status === 200
    ? safeParseJson(wkKeysOutcome.res.bodyText)
    : null;

  const paxiomKeysCount = wkKeysJson && Array.isArray(wkKeysJson.keys)
    ? wkKeysJson.keys.filter((k) => k && k.algorithm === 'ed25519' && typeof k.publicKey === 'string').length
    : 0;
  const exposeHdr = String(mainRes.headers['access-control-expose-headers'] || '').toLowerCase();
  const paxiomHeaderExposed = exposeHdr.includes('x-paxiom-receipt') || Boolean(mainRes.headers['x-paxiom-receipt']);
  if (paxiomHeaderExposed || paxiomKeysCount > 0) {
    checks.paxiomReceipts = 'ready';
  }

  // Never follow redirects on x402 endpoints (prevents payment header leakage / payTo hijack)
  if (mainRes.status >= 300 && mainRes.status < 400) {
    findings.push({
      code: 'redirect_not_allowed',
      severity: 'high',
      message: `Endpoint returned HTTP ${mainRes.status} redirect; x402 buyers should never send signed payment headers across redirects.`
    });
    return {
      ok: true,
      targetUrl: validatedTarget.normalizedUrl,
      probedMethod: upperMethod,
      verdict: 'block',
      riskLevel: 'high',
      httpStatus: mainRes.status,
      selectedQuote: null,
      recommendedMaxPaymentAtomic: null,
      checks,
      receiptSupport: { paxiomHeaderExposed, paxiomWellKnownKeys: paxiomKeysCount },
      findings
    };
  }

  const headerChallenge = decodePaymentRequiredHeader(mainRes.headers['payment-required']);
  const bodyJson = safeParseJson(mainRes.bodyText);
  const challengeSource = (headerChallenge && Array.isArray(headerChallenge.accepts) && headerChallenge) ||
    (mainRes.status === 402 && bodyJson && Array.isArray(bodyJson.accepts) && bodyJson) ||
    (mainRes.status === 402 && wkX402Json && Array.isArray(wkX402Json.accepts) && wkX402Json) ||
    null;

  if (mainRes.status !== 402 || !challengeSource || challengeSource.accepts.length === 0) {
    const code = mainRes.status === 402 ? 'malformed_402_challenge' : 'non_402_response';
    const severity = mainRes.status >= 200 && mainRes.status < 300 ? 'medium' : 'high';
    findings.push({
      code,
      severity,
      message: mainRes.status === 402
        ? 'Endpoint returned HTTP 402 without a valid x402 accepts[] PaymentRequirements list.'
        : `Endpoint returned HTTP ${mainRes.status} instead of an x402 402 Payment Required challenge.`
    });
    return {
      ok: true,
      targetUrl: validatedTarget.normalizedUrl,
      probedMethod: upperMethod,
      verdict: severity === 'high' ? 'block' : 'caution',
      riskLevel: severity,
      httpStatus: mainRes.status,
      selectedQuote: null,
      recommendedMaxPaymentAtomic: null,
      checks,
      receiptSupport: { paxiomHeaderExposed, paxiomWellKnownKeys: paxiomKeysCount },
      findings
    };
  }

  checks.httpChallenge = 'pass';
  const accepts = challengeSource.accepts.filter((a) => a && typeof a === 'object');
  const wantedNetCfg = expectedNetwork ? getSupportedNetworkConfig(String(expectedNetwork)) : null;

  let chosen = accepts[0];
  if (wantedNetCfg) {
    const match = accepts.find((a) => {
      const cfg = getSupportedNetworkConfig(String(a.network || ''));
      return cfg && cfg.caip2 === wantedNetCfg.caip2;
    });
    if (match) chosen = match;
  } else {
    const baseMain = accepts.find((a) => {
      const cfg = getSupportedNetworkConfig(String(a.network || ''));
      return cfg && cfg.caip2 === 'eip155:8453';
    });
    if (baseMain) chosen = baseMain;
  }

  const rawNetwork = String(chosen.network || '');
  const netCfg = getSupportedNetworkConfig(rawNetwork);
  if (!netCfg) {
    checks.networkSupported = 'fail';
    findings.push({
      code: 'unsupported_network',
      severity: 'high',
      message: `Seller quoted unsupported or unrecognized network "${rawNetwork}" (Paxiom v0 verifies Base & Base Sepolia USDC).`
    });
  } else if (wantedNetCfg && netCfg.caip2 !== wantedNetCfg.caip2) {
    checks.networkSupported = 'fail';
    findings.push({
      code: 'expected_network_mismatch',
      severity: 'high',
      message: `Seller did not offer a quote on requested network "${expectedNetwork}" (offered "${rawNetwork}").`
    });
  } else {
    checks.networkSupported = 'pass';
  }

  const rawAsset = String(chosen.asset || '');
  let canonicalUsdc = false;
  if (netCfg) {
    if (rawAsset.toLowerCase() === netCfg.usdcAddress.toLowerCase()) {
      canonicalUsdc = true;
      checks.canonicalUsdcAsset = 'pass';
    } else {
      checks.canonicalUsdcAsset = 'fail';
      findings.push({
        code: 'non_canonical_usdc_asset',
        severity: 'high',
        message: `Seller requested non-canonical token "${rawAsset}" instead of Circle USDC (${netCfg.usdcAddress}) on ${netCfg.caip2}.`
      });
    }

    const extraName = chosen.extra && typeof chosen.extra === 'object' ? chosen.extra.name : undefined;
    const extraVer = chosen.extra && typeof chosen.extra === 'object' ? chosen.extra.version : undefined;
    if (extraName !== undefined) {
      if (String(extraName) === netCfg.eip712Name && (extraVer === undefined || String(extraVer) === '2')) {
        checks.eip712Domain = 'pass';
      } else {
        checks.eip712Domain = 'fail';
        findings.push({
          code: 'eip712_domain_mismatch',
          severity: 'high',
          message: `EIP-712 extra domain (${JSON.stringify({ name: extraName, version: extraVer })}) does not match canonical USDC (${netCfg.eip712Name} v2).`
        });
      }
    } else {
      checks.eip712Domain = 'warn';
      findings.push({
        code: 'missing_eip712_extra',
        severity: 'medium',
        message: 'Quote omitted extra.name/version EIP-712 domain hints; EIP-3009 signing may fail on strict clients.'
      });
    }
  }

  const rawPayTo = String(chosen.payTo || '');
  if (!EVM_ADDRESS_RE.test(rawPayTo) || ZERO_OR_BURN_ADDRESSES.has(rawPayTo.toLowerCase())) {
    checks.payToAddress = 'fail';
    findings.push({
      code: 'invalid_pay_to',
      severity: 'high',
      message: `Seller payTo "${rawPayTo}" is missing, malformed, or a burn/zero address.`
    });
  } else {
    checks.payToAddress = 'pass';
  }

  // Bait-and-switch check against /.well-known/x402.json when published
  if (wkX402Json && Array.isArray(wkX402Json.accepts) && wkX402Json.accepts.length > 0 && checks.payToAddress === 'pass') {
    const wkMatch = wkX402Json.accepts.find((a) => a && String(a.resource || '') === validatedTarget.normalizedUrl) ||
      (wkX402Json.accepts.length === 1 ? wkX402Json.accepts[0] : null);
    if (wkMatch && wkMatch.payTo && String(wkMatch.payTo).toLowerCase() !== rawPayTo.toLowerCase()) {
      checks.manifestConsistency = 'fail';
      findings.push({
        code: 'payto_manifest_mismatch',
        severity: 'high',
        message: `Live 402 payTo (${rawPayTo}) differs from /.well-known/x402.json payTo (${wkMatch.payTo}).`
      });
    } else {
      checks.manifestConsistency = 'pass';
    }
  } else {
    checks.manifestConsistency = 'not_published';
  }

  const rawAmount = String(chosen.maxAmountRequired ?? chosen.amount ?? '');
  let parsedAmount = null;
  if (!DEC_UINT_RE.test(rawAmount)) {
    findings.push({
      code: 'invalid_amount_atomic',
      severity: 'high',
      message: `Quoted maxAmountRequired "${rawAmount}" is not a valid base-10 atomic integer.`
    });
  } else {
    parsedAmount = BigInt(rawAmount);
    if (parsedAmount <= 0n) {
      findings.push({
        code: 'zero_amount_quote',
        severity: 'medium',
        message: 'Seller returned HTTP 402 with maxAmountRequired = 0.'
      });
    } else if (parsedAmount > HIGH_SINGLE_CALL_USDC_ATOMIC) {
      findings.push({
        code: 'unusually_high_price',
        severity: 'medium',
        message: `Quoted price (${rawAmount} atomic = $${(Number(parsedAmount) / 1e6).toFixed(2)} USDC) exceeds $100 for a single call.`
      });
    }
    if (maxBudgetAtomic !== null) {
      const cap = BigInt(maxBudgetAtomic);
      if (parsedAmount <= cap) {
        checks.budgetCap = 'pass';
      } else {
        checks.budgetCap = 'fail';
        findings.push({
          code: 'exceeds_max_budget',
          severity: 'high',
          message: `Quoted price (${rawAmount} atomic) exceeds caller maxBudgetAtomic (${maxBudgetAtomic} atomic).`
        });
      }
    }
  }

  if (chosen.outputSchema && typeof chosen.outputSchema === 'object') {
    checks.bazaarSchema = 'present';
  }

  if (checks.paxiomReceipts === 'not_detected') {
    findings.push({
      code: 'no_delivery_receipt_advertised',
      severity: 'low',
      message: 'Seller does not advertise X-Paxiom-Receipt or /.well-known/paxiom-keys.json; payment alone will not cryptographically bind delivered output.'
    });
  }

  const hasHigh = findings.some((f) => f.severity === 'high');
  const hasMedium = findings.some((f) => f.severity === 'medium');
  const riskLevel = hasHigh ? 'high' : (hasMedium ? 'medium' : 'low');
  const verdict = hasHigh ? 'block' : (hasMedium ? 'caution' : 'proceed');

  return {
    ok: true,
    targetUrl: validatedTarget.normalizedUrl,
    probedMethod: upperMethod,
    verdict,
    riskLevel,
    httpStatus: mainRes.status,
    selectedQuote: {
      scheme: String(chosen.scheme || 'exact'),
      network: netCfg ? netCfg.caip2 : rawNetwork,
      rawNetwork,
      asset: rawAsset,
      canonicalUsdc,
      payTo: rawPayTo,
      amountAtomic: parsedAmount !== null ? parsedAmount.toString() : rawAmount,
      maxTimeoutSeconds: Number(chosen.maxTimeoutSeconds) || null
    },
    recommendedMaxPaymentAtomic: verdict === 'block' || parsedAmount === null ? null : parsedAmount.toString(),
    checks,
    receiptSupport: {
      paxiomHeaderExposed,
      paxiomWellKnownKeys: paxiomKeysCount
    },
    findings
  };
}
