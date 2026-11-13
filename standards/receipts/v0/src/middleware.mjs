import { issueReceipt } from './issue.mjs';

export const RECEIPT_HEADER_NAME = 'x-paxiom-receipt';

function extractHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function tryDecodePaymentResponseTx(headerVal) {
  if (!headerVal) return null;
  try {
    const decoded = JSON.parse(Buffer.from(headerVal, 'base64').toString('utf8'));
    const tx = decoded.transaction || decoded.txHash || decoded.transactionHash || null;
    return typeof tx === 'string' && /^0x[0-9a-fA-F]{64}$/.test(tx) ? tx.toLowerCase() : null;
  } catch {
    return null;
  }
}

/**
 * Wrap a Web Standard `(request: Request) => Promise<Response>` handler (Hono,
 * Cloudflare Workers, Next.js App Router, Bun, Node fetch adapters) so every 2xx
 * JSON response automatically emits a signed `X-Paxiom-Receipt` header.
 */
export function withPaxiomReceipt(handler, options = {}) {
  const {
    privateKey,
    issuer,
    serviceName,
    paymentDefaults = {},
    resolvePayment,
    onReceipt
  } = options;
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
    const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (contentType && contentType !== 'application/json') {
      return response;
    }

    const rawResText = await response.clone().text();
    let parsedOutput;
    try {
      parsedOutput = JSON.parse(rawResText);
    } catch {
      return response;
    }

    const paymentSigHeader = extractHeader(request.headers, 'payment-signature')
      || extractHeader(request.headers, 'x-payment')
      || '';
    const paymentResHeader = extractHeader(response.headers, 'payment-response')
      || extractHeader(response.headers, 'x-payment-response')
      || '';
    const txHash = tryDecodePaymentResponseTx(paymentResHeader);

    const dynamicPayment = typeof resolvePayment === 'function'
      ? await resolvePayment({ request, response, txHash })
      : {};

    const payment = {
      scheme: 'x402',
      network: 'base',
      asset: 'USDC',
      amountAtomic: '0',
      amountDisplay: '0',
      paymentPayload: paymentSigHeader || 'none',
      ...paymentDefaults,
      ...dynamicPayment,
      settlement: {
        status: txHash ? 'claimed_not_checked' : (paymentSigHeader ? 'verify_only' : 'not_required'),
        transactionHash: txHash,
        checkedByPaxiom: false,
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
      output: parsedOutput,
      mimeType: contentType || 'application/json'
    });

    if (typeof onReceipt === 'function') {
      Promise.resolve(onReceipt(receipt)).catch(() => {});
    }

    const headers = new Headers(response.headers);
    headers.set(RECEIPT_HEADER_NAME, receiptHeader);
    const expose = headers.get('access-control-expose-headers');
    if (!expose || !expose.toLowerCase().includes(RECEIPT_HEADER_NAME)) {
      headers.set('access-control-expose-headers', expose ? `${expose}, ${RECEIPT_HEADER_NAME}` : RECEIPT_HEADER_NAME);
    }

    return new Response(rawResText, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  };
}

/**
 * Node `http` / Express / Connect middleware `(req, res, next)` that signs 2xx
 * JSON responses (`res.json(...)` or buffered `res.end(jsonString)`) and attaches
 * `X-Paxiom-Receipt`.
 */
export function createReceiptMiddleware(options = {}) {
  const {
    privateKey,
    issuer,
    serviceName,
    baseUrl = '',
    paymentDefaults = {},
    resolvePayment,
    onReceipt
  } = options;
  if (!privateKey) throw new TypeError('createReceiptMiddleware requires options.privateKey');
  if (!issuer || !issuer.name || !issuer.keyId) {
    throw new TypeError('createReceiptMiddleware requires options.issuer { name, keyId }');
  }

  return function paxiomReceiptMiddleware(req, res, next) {
    const reqChunks = [];
    let reqCapped = false;
    const MAX_CAPTURE = 256 * 1024;

    if (req.body !== undefined && typeof req.body === 'object' && req.body !== null) {
      // Express body-parser already parsed req.body
      reqChunks.push(Buffer.from(JSON.stringify(req.body), 'utf8'));
    } else if (typeof req.on === 'function') {
      req.on('data', (c) => {
        if (reqCapped) return;
        const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
        if (buf.length + reqChunks.reduce((n, b) => n + b.length, 0) > MAX_CAPTURE) {
          reqCapped = true;
          return;
        }
        reqChunks.push(buf);
      });
    }

    const origEnd = res.end.bind(res);
    const resChunks = [];
    const origWrite = res.write.bind(res);

    res.write = function wrappedWrite(chunk, encoding, cb) {
      if (chunk) resChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      return origWrite(chunk, encoding, cb);
    };

    res.end = function wrappedEnd(chunk, encoding, cb) {
      if (chunk && typeof chunk !== 'function') {
        resChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      try {
        const status = res.statusCode || 200;
        const ctHeader = String(res.getHeader('content-type') || '').split(';')[0].trim().toLowerCase();
        if (!res.headersSent && status >= 200 && status < 300 && (!ctHeader || ctHeader === 'application/json')) {
          const fullBody = Buffer.concat(resChunks).toString('utf8');
          const parsedOutput = JSON.parse(fullBody);
          const host = req.headers && req.headers.host ? `http://${req.headers.host}` : 'http://localhost';
          const resource = `${baseUrl || host}${req.originalUrl || req.url || '/'}`;
          const paymentSigHeader = extractHeader(req.headers, 'payment-signature')
            || extractHeader(req.headers, 'x-payment')
            || '';
          const paymentResHeader = String(res.getHeader('payment-response') || res.getHeader('x-payment-response') || '');
          const txHash = tryDecodePaymentResponseTx(paymentResHeader);
          const dynamicPayment = typeof resolvePayment === 'function'
            ? resolvePayment({ req, res, txHash })
            : {};

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
              scheme: 'x402',
              network: 'base',
              asset: 'USDC',
              amountAtomic: '0',
              amountDisplay: '0',
              paymentPayload: paymentSigHeader || 'none',
              ...paymentDefaults,
              ...(dynamicPayment || {}),
              settlement: {
                status: txHash ? 'claimed_not_checked' : (paymentSigHeader ? 'verify_only' : 'not_required'),
                transactionHash: txHash,
                checkedByPaxiom: false,
                ...(paymentDefaults.settlement || {}),
                ...(dynamicPayment && dynamicPayment.settlement ? dynamicPayment.settlement : {})
              }
            },
            output: parsedOutput,
            mimeType: ctHeader || 'application/json'
          });
          res.setHeader('X-Paxiom-Receipt', receiptHeader);
          if (typeof onReceipt === 'function') {
            Promise.resolve(onReceipt(receipt)).catch(() => {});
          }
        }
      } catch {
        // Never fail the caller's response if body is non-JSON or headers were already flushed.
      }
      return origEnd(chunk, encoding, cb);
    };

    if (typeof next === 'function') next();
  };
}
