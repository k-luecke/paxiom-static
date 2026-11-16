import { issueReceipt, normalizeTransactionId } from './issue.mjs';

export const STANDARD_RECEIPT_HEADER_NAME = 'payment-receipt';
export const RECEIPT_HEADER_NAME = 'x-paxiom-receipt';

const MAX_CAPTURE_BYTES = 256 * 1024;
const DEC_UINT_RE = /^[0-9]+$/;

function extractHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function decodeBase64Json(headerVal) {
  if (!headerVal || typeof headerVal !== 'string') return null;
  const trimmed = headerVal.trim();
  if (!trimmed) return null;
  for (const enc of ['base64', 'base64url']) {
    try {
      const parsed = JSON.parse(Buffer.from(trimmed, enc).toString('utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {
      // try next encoding
    }
  }
  return null;
}

function normalizeCaip2Network(rawNet) {
  if (!rawNet || typeof rawNet !== 'string') return null;
  const trimmed = rawNet.trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'base') return 'eip155:8453';
  if (lower === 'base-sepolia') return 'eip155:84532';
  if (lower === 'solana' || lower === 'solana-mainnet') return 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
  if (lower === 'solana-devnet') return 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
  return trimmed;
}

function formatUsdcDisplay(atomicStr) {
  if (!DEC_UINT_RE.test(atomicStr)) return '0';
  const n = BigInt(atomicStr);
  const whole = n / 1000000n;
  const frac = (n % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}

/**
 * Parse x402 v1 / v2 HTTP headers (`PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`, `PAYMENT-REQUIRED`)
 * into normalized CAIP-2 payment & settlement fields (`network`, `scheme`, `asset`,
 * `amountAtomic`, `payer`, `payTo`, `transactionHash`).
 */
export function parseX402Headers(arg1 = {}, responseHeaders = null) {
  let paymentSignature = '';
  let paymentResponse = '';
  let paymentRequired = '';
  if (
    responseHeaders !== null ||
    typeof arg1?.get === 'function' ||
    (arg1 && typeof arg1 === 'object' && !Object.hasOwn(arg1, 'paymentSignature') && !Object.hasOwn(arg1, 'paymentResponse') && !Object.hasOwn(arg1, 'paymentRequired'))
  ) {
    paymentSignature = extractHeader(arg1, 'payment-signature') || extractHeader(arg1, 'x-payment') || '';
    paymentRequired = extractHeader(arg1, 'payment-required') || extractHeader(responseHeaders, 'payment-required') || '';
    paymentResponse = extractHeader(responseHeaders, 'payment-response') || extractHeader(responseHeaders, 'x-payment-response') || extractHeader(arg1, 'payment-response') || '';
  } else if (arg1 && typeof arg1 === 'object') {
    paymentSignature = arg1.paymentSignature || '';
    paymentResponse = arg1.paymentResponse || '';
    paymentRequired = arg1.paymentRequired || '';
  }
  const sigObj = decodeBase64Json(paymentSignature);
  const resObj = decodeBase64Json(paymentResponse);
  const reqObj = decodeBase64Json(paymentRequired);

  const accepted = (sigObj && typeof sigObj.accepted === 'object' && sigObj.accepted) ||
    (reqObj && Array.isArray(reqObj.accepts) && reqObj.accepts[0]) ||
    null;
  const auth = (sigObj && sigObj.payload && typeof sigObj.payload.authorization === 'object' && sigObj.payload.authorization) || null;

  let txHash = null;
  if (resObj) {
    const rawTx = resObj.transaction || resObj.txHash || resObj.transactionHash || null;
    if (typeof rawTx === 'string' && rawTx.trim()) {
      try {
        txHash = normalizeTransactionId(rawTx.trim());
      } catch {
        txHash = null;
      }
    }
  }

  const rawNetwork = (resObj && (resObj.network || resObj.networkId)) ||
    (accepted && accepted.network) ||
    (sigObj && sigObj.network) ||
    null;
  const network = normalizeCaip2Network(rawNetwork);

  const scheme = (accepted && accepted.scheme) || (sigObj && sigObj.scheme) || null;
  const asset = (accepted && accepted.asset) || null;
  const rawAmount = (accepted && (accepted.amount ?? accepted.maxAmountRequired)) ??
    (auth && auth.value) ??
    null;
  const amountAtomic = rawAmount !== null && rawAmount !== undefined && DEC_UINT_RE.test(String(rawAmount))
    ? String(rawAmount)
    : null;

  const payTo = (accepted && accepted.payTo) || (auth && auth.to) || null;
  const payer = (resObj && resObj.payer) || (auth && auth.from) || null;
  const settlementFailed = Boolean(resObj && resObj.success === false);

  return {
    txHash,
    transactionHash: txHash,
    settlementFailed,
    network,
    scheme: typeof scheme === 'string' && scheme ? scheme : null,
    asset: typeof asset === 'string' && asset ? asset : null,
    amountAtomic,
    amountDisplay: amountAtomic ? formatUsdcDisplay(amountAtomic) : null,
    payer: typeof payer === 'string' && payer ? payer : null,
    payTo: typeof payTo === 'string' && payTo ? payTo : null
  };
}

function isJsonContentType(ct) {
  return !ct || ct === 'application/json' || ct.endsWith('+json');
}

function appendExposeHeaders(existing, headerNames) {
  const cur = existing ? String(existing) : '';
  const parts = cur ? cur.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const lowerSet = new Set(parts.map((s) => s.toLowerCase()));
  for (const h of headerNames) {
    if (!lowerSet.has(h.toLowerCase())) {
      parts.push(h);
      lowerSet.add(h.toLowerCase());
    }
  }
  return parts.join(', ');
}

/**
 * Wrap a Web Standard `(request: Request) => Promise<Response>` handler (Hono,
 * Cloudflare Workers, Next.js App Router, Bun, Node fetch adapters) so every 2xx
 * response (JSON via `jcs-sha256` or non-JSON text/binary via `raw-sha256`, up to 256 KiB)
 * emits signed `Payment-Receipt` and `X-Paxiom-Receipt` headers.
 */
export function withPaxiomReceipt(handler, options = {}) {
  const {
    privateKey: rawPrivateKey,
    privateKeyPem,
    issuer,
    serviceName,
    paymentDefaults = {},
    resolvePayment,
    onReceipt
  } = options;
  const privateKey = rawPrivateKey || privateKeyPem;
  if (!privateKey) throw new TypeError('withPaxiomReceipt requires options.privateKey');
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('withPaxiomReceipt requires options.issuer { name, keyId }');
  }

  return async function paxiomWrappedFetchHandler(request, ...rest) {
    const clonedReq = request.clone();
    const rawReqBytes = new Uint8Array(await clonedReq.arrayBuffer());
    const response = await handler(request, ...rest);

    if (!response || response.status < 200 || response.status >= 300) {
      return response;
    }
    if (rawReqBytes.byteLength > MAX_CAPTURE_BYTES) {
      return response;
    }

    const rawResBytes = new Uint8Array(await response.clone().arrayBuffer());
    if (rawResBytes.byteLength > MAX_CAPTURE_BYTES) {
      return response;
    }

    const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    const jsonMode = isJsonContentType(contentType);
    let outputForIssue;
    let canonicalization;
    if (jsonMode) {
      try {
        outputForIssue = JSON.parse(Buffer.from(rawResBytes).toString('utf8'));
        canonicalization = 'jcs-sha256';
      } catch {
        if (!contentType) {
          outputForIssue = Buffer.from(rawResBytes);
          canonicalization = 'raw-sha256';
        } else {
          return response;
        }
      }
    } else {
      outputForIssue = Buffer.from(rawResBytes);
      canonicalization = 'raw-sha256';
    }

    const paymentSigHeader = extractHeader(request.headers, 'payment-signature')
      || extractHeader(request.headers, 'x-payment')
      || '';
    const paymentResHeader = extractHeader(response.headers, 'payment-response')
      || extractHeader(response.headers, 'x-payment-response')
      || '';
    const paymentReqHeader = extractHeader(response.headers, 'payment-required') || '';
    const parsedX402 = parseX402Headers({
      paymentSignature: paymentSigHeader,
      paymentResponse: paymentResHeader,
      paymentRequired: paymentReqHeader
    });
    const txHash = parsedX402.txHash;

    const dynamicPayment = typeof resolvePayment === 'function'
      ? await resolvePayment({ request, response, txHash, parsedX402 })
      : {};

    const payment = {
      scheme: parsedX402.scheme || 'x402',
      network: parsedX402.network || 'eip155:8453',
      asset: parsedX402.asset || 'USDC',
      amountAtomic: parsedX402.amountAtomic || '0',
      amountDisplay: parsedX402.amountDisplay || '0',
      ...(parsedX402.payer ? { payer: parsedX402.payer } : {}),
      ...(parsedX402.payTo ? { payTo: parsedX402.payTo } : {}),
      ...(paymentReqHeader ? { paymentRequirements: paymentReqHeader } : {}),
      paymentPayload: paymentSigHeader || 'none',
      ...paymentDefaults,
      ...dynamicPayment,
      settlement: {
        status: parsedX402.settlementFailed ? 'failed' : (txHash ? 'claimed_not_checked' : (paymentSigHeader ? 'verify_only' : 'not_required')),
        transactionHash: txHash,
        checkedByVerifier: false,
        ...(paymentDefaults.settlement || {}),
        ...(dynamicPayment && dynamicPayment.settlement ? dynamicPayment.settlement : {})
      }
    };

    const { receipt, receiptHeader } = issueReceipt({
      privateKey,
      issuer,
      service: {
        name: serviceName || issuer.name,
        resource: request.url,
        method: request.method
      },
      request: {
        method: request.method,
        resource: request.url,
        body: rawReqBytes.length > 0 ? Buffer.from(rawReqBytes) : ''
      },
      payment,
      output: outputForIssue,
      mimeType: contentType || (canonicalization === 'jcs-sha256' ? 'application/json' : 'application/octet-stream'),
      canonicalization,
      statusCode: response.status
    });

    if (typeof onReceipt === 'function') {
      Promise.resolve(onReceipt(receipt)).catch(() => {});
    }

    const headers = new Headers(response.headers);
    headers.set(STANDARD_RECEIPT_HEADER_NAME, receiptHeader);
    headers.set(RECEIPT_HEADER_NAME, receiptHeader);
    headers.set(
      'access-control-expose-headers',
      appendExposeHeaders(headers.get('access-control-expose-headers'), [
        'Payment-Receipt',
        'X-Paxiom-Receipt'
      ])
    );

    return new Response(rawResBytes, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  };
}

const SAFE_HOST_RE = /^(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::\d{1,5})?$/;

function resolveSafeOrigin(baseUrl, req) {
  if (baseUrl) return String(baseUrl).replace(/\/+$/, '');
  const rawHost = req && req.headers && typeof req.headers.host === 'string' ? req.headers.host.trim() : '';
  if (rawHost && SAFE_HOST_RE.test(rawHost)) {
    const scheme = req && req.socket && req.socket.encrypted ? 'https' : 'http';
    return `${scheme}://${rawHost}`;
  }
  return 'http://localhost';
}

/**
 * Node `http` / Express / Connect middleware `(req, res, next)` that signs 2xx
 * JSON (`jcs-sha256`) and non-JSON (`raw-sha256`) responses and attaches both
 * `Payment-Receipt` and `X-Paxiom-Receipt`.
 */
export function createReceiptMiddleware(options = {}) {
  const {
    privateKey: rawPrivateKey,
    privateKeyPem,
    issuer,
    serviceName,
    baseUrl = '',
    paymentDefaults = {},
    resolvePayment,
    onReceipt
  } = options;
  const privateKey = rawPrivateKey || privateKeyPem;
  if (!privateKey) throw new TypeError('createReceiptMiddleware requires options.privateKey');
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('createReceiptMiddleware requires options.issuer { name, keyId }');
  }
  if (typeof resolvePayment === 'function' && resolvePayment.constructor && resolvePayment.constructor.name === 'AsyncFunction') {
    throw new TypeError(
      'createReceiptMiddleware requires a synchronous resolvePayment callback (use withPaxiomReceipt for async callbacks, or pre-populate req.paxiomPayment / res.locals.paxiomPayment before res.end)'
    );
  }

  return function paxiomReceiptMiddleware(req, res, next) {
    const reqChunks = [];
    let capturedBytes = 0;
    let reqCapped = false;

    if (req.body !== undefined && typeof req.body === 'object' && req.body !== null) {
      const serialized = Buffer.from(JSON.stringify(req.body), 'utf8');
      if (serialized.length > MAX_CAPTURE_BYTES) {
        reqCapped = true;
      } else {
        reqChunks.push(serialized);
        capturedBytes = serialized.length;
      }
    } else if (typeof req.on === 'function') {
      req.on('data', (c) => {
        if (reqCapped) return;
        const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
        if (capturedBytes + buf.length > MAX_CAPTURE_BYTES) {
          reqCapped = true;
          reqChunks.length = 0;
          return;
        }
        reqChunks.push(buf);
        capturedBytes += buf.length;
      });
    }

    const origEnd = res.end.bind(res);
    const resChunks = [];
    let resBytes = 0;
    let resCapped = false;
    const origWrite = res.write.bind(res);

    res.write = function wrappedWrite(chunk, encoding, cb) {
      if (chunk && !resCapped) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
        if (resBytes + buf.length > MAX_CAPTURE_BYTES) {
          resCapped = true;
          resChunks.length = 0;
        } else {
          resChunks.push(buf);
          resBytes += buf.length;
        }
      }
      return origWrite(chunk, encoding, cb);
    };

    res.end = function wrappedEnd(chunk, encoding, cb) {
      if (chunk && typeof chunk !== 'function' && !resCapped) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
        if (resBytes + buf.length > MAX_CAPTURE_BYTES) {
          resCapped = true;
          resChunks.length = 0;
        } else {
          resChunks.push(buf);
          resBytes += buf.length;
        }
      }
      try {
        if (!reqCapped && !resCapped) {
          const status = res.statusCode || 200;
          const ctHeader = String(res.getHeader('content-type') || '').split(';')[0].trim().toLowerCase();
          if (!res.headersSent && status >= 200 && status < 300) {
            const fullBuf = Buffer.concat(resChunks);
            const jsonMode = isJsonContentType(ctHeader);
            let outputForIssue;
            let canonicalization;
            let skipSign = false;
            if (jsonMode) {
              try {
                outputForIssue = JSON.parse(fullBuf.toString('utf8'));
                canonicalization = 'jcs-sha256';
              } catch {
                if (!ctHeader) {
                  outputForIssue = fullBuf;
                  canonicalization = 'raw-sha256';
                } else {
                  skipSign = true;
                }
              }
            } else {
              outputForIssue = fullBuf;
              canonicalization = 'raw-sha256';
            }

            if (!skipSign) {
              const origin = resolveSafeOrigin(baseUrl, req);
              const rawPath = String(req.originalUrl || req.url || '/');
              const safePath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
              const resource = `${origin}${safePath}`;
              const paymentSigHeader = extractHeader(req.headers, 'payment-signature')
                || extractHeader(req.headers, 'x-payment')
                || '';
              const paymentResHeader = String(res.getHeader('payment-response') || res.getHeader('x-payment-response') || '');
              const paymentReqHeader = String(res.getHeader('payment-required') || '');
              const parsedX402 = parseX402Headers({
                paymentSignature: paymentSigHeader,
                paymentResponse: paymentResHeader,
                paymentRequired: paymentReqHeader
              });
              const txHash = parsedX402.txHash;
              const preResolved = (req && req.paxiomPayment) || (res && res.locals && res.locals.paxiomPayment) || null;
              const dynamicPayment = typeof resolvePayment === 'function'
                ? resolvePayment({ req, res, txHash, parsedX402 })
                : (preResolved || {});

              if (dynamicPayment && typeof dynamicPayment.then === 'function') {
                return origEnd(chunk, encoding, cb);
              }

              const { receipt, receiptHeader } = issueReceipt({
                privateKey,
                issuer,
                service: {
                  name: serviceName || issuer.name,
                  resource,
                  method: req.method || 'GET'
                },
                request: {
                  method: req.method || 'GET',
                  resource,
                  body: reqChunks.length > 0 ? Buffer.concat(reqChunks) : ''
                },
                payment: {
                  scheme: parsedX402.scheme || 'x402',
                  network: parsedX402.network || 'eip155:8453',
                  asset: parsedX402.asset || 'USDC',
                  amountAtomic: parsedX402.amountAtomic || '0',
                  amountDisplay: parsedX402.amountDisplay || '0',
                  ...(parsedX402.payer ? { payer: parsedX402.payer } : {}),
                  ...(parsedX402.payTo ? { payTo: parsedX402.payTo } : {}),
                  ...(paymentReqHeader ? { paymentRequirements: paymentReqHeader } : {}),
                  paymentPayload: paymentSigHeader || 'none',
                  ...paymentDefaults,
                  ...(dynamicPayment || {}),
                  settlement: {
                    status: txHash ? 'claimed_not_checked' : (paymentSigHeader ? 'verify_only' : 'not_required'),
                    transactionHash: txHash,
                    checkedByVerifier: false,
                    ...(paymentDefaults.settlement || {}),
                    ...(dynamicPayment && dynamicPayment.settlement ? dynamicPayment.settlement : {})
                  }
                },
                output: outputForIssue,
                mimeType: ctHeader || (canonicalization === 'jcs-sha256' ? 'application/json' : 'application/octet-stream'),
                canonicalization,
                statusCode: status
              });
              res.setHeader('Payment-Receipt', receiptHeader);
              res.setHeader('X-Paxiom-Receipt', receiptHeader);
              res.setHeader(
                'Access-Control-Expose-Headers',
                appendExposeHeaders(res.getHeader('access-control-expose-headers'), [
                  'Payment-Receipt',
                  'X-Paxiom-Receipt'
                ])
              );
              if (typeof onReceipt === 'function') {
                Promise.resolve(onReceipt(receipt)).catch(() => {});
              }
            }
          }
        }
      } catch {
        // Never fail the caller's response if headers were already flushed.
      }
      return origEnd(chunk, encoding, cb);
    };

    if (typeof next === 'function') next();
  };
}
