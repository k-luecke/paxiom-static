// Pure Web-Standard / Cloudflare Workers / Edge / Browser TypeScript declarations.
// Zero `@types/node` and zero `Buffer` references — compiles cleanly under
// `"types": ["@cloudflare/workers-types"]`, `"lib": ["ES2022", "WebWorker"]`, or `"DOM"`.

export const RECEIPT_VERSION: 'paxiom.receipt.v0';
export const RECEIPT_SCHEMA: Readonly<Record<string, unknown>>;
export const STANDARD_RECEIPT_HEADER_NAME: 'payment-receipt';
export const RECEIPT_HEADER_NAME: 'x-paxiom-receipt';
export const MAX_DEPTH: number;
export const DEFAULT_PAXIOM_API_URL: 'https://api.paxiom.org';
export const PAXIOM_LIVE_VERIFIER_PUBLIC_KEY: string;
export const PAXIOM_TRUSTED_VERIFIER_PUBLIC_KEYS: readonly string[];
export const PAXIOM_TRUSTED_PUBLIC_KEYS: readonly string[];

export interface WebCryptoKeyLike {
  readonly type?: string;
  readonly extractable?: boolean;
  readonly algorithm?: unknown;
  readonly usages?: readonly string[];
}

export type WebPrivateKeyInput =
  | string
  | Uint8Array
  | WebCryptoKeyLike
  | { privateKey: WebCryptoKeyLike; publicKey?: string | Uint8Array | WebCryptoKeyLike }
  | Record<string, unknown>;

export type PaxiomSettlementStatus =
  | 'not_required'
  | 'disabled'
  | 'verify_only'
  | 'claimed_not_checked'
  | 'verified_settled'
  | 'failed'
  | 'unknown';

export type PaxiomCanonicalizationMode = 'jcs-sha256' | 'raw-sha256';

export type PaxiomTrustState =
  | 'verified'
  | 'valid_signature_only'
  | 'settlement_claimed_not_checked'
  | 'settlement_failed'
  | 'unauthorized_issuer'
  | 'proof_invalid'
  | 'proof_unavailable'
  | 'output_hash_mismatch'
  | 'invalid_signature'
  | 'expired'
  | 'schema_invalid'
  | 'unsupported_format'
  | 'error';

export interface PaxiomReceiptIssuer {
  name: string;
  uri?: string;
  keyId: string;
  payTo?: string;
  keysUri?: string;
}

export interface PaxiomReceiptService {
  name: string;
  resource: string;
  method: string;
}

export interface PaxiomReceiptSettlement {
  status: PaxiomSettlementStatus;
  transactionHash?: string | null;
  checkedByVerifier?: boolean;
  verifier?: string | null;
  checkedByPaxiom?: boolean;
}

export interface PaxiomReceiptEvidence {
  type: 'none' | 'zk' | 'attestation' | 'tee' | 'archive' | 'other';
  status: 'not_provided' | 'provided' | 'unavailable' | 'invalid' | 'verified';
  hash: string | null;
  uri: string | null;
}

export interface PaxiomReceiptV0 {
  receiptVersion: 'paxiom.receipt.v0';
  payload: {
    receiptId: string;
    issuedAt: string;
    expiresAt?: string;
    issuer: PaxiomReceiptIssuer;
    service: PaxiomReceiptService;
    request: {
      requestHash: string;
      resourceHash: string;
      bodyHash: string;
    };
    payment: {
      scheme: string;
      network: string;
      asset: string;
      amountAtomic: string;
      amountDisplay: string;
      payer?: string;
      payTo?: string;
      paymentRequirementsHash: string;
      paymentPayloadHash: string;
      settlement: PaxiomReceiptSettlement;
    };
    evidence: PaxiomReceiptEvidence[];
    delivery: {
      outputHash: string;
      mimeType: string;
      canonicalization?: PaxiomCanonicalizationMode;
      statusCode?: number;
    };
  };
  signature: {
    algorithm: 'ed25519';
    keyId: string;
    publicKey: string;
    value: string;
  };
}

export interface VerifyReceiptOptions {
  output?: unknown;
  now?: string | number | Date;
  expectedIssuerPublicKeys?: readonly string[] | ReadonlySet<string>;
  expectedPayTo?: string;
  trustedVerifierPublicKeys?: readonly string[] | ReadonlySet<string>;
  trustedPaxiomPublicKeys?: readonly string[] | ReadonlySet<string>;
}

export interface VerifyReceiptResult {
  valid: boolean;
  trustState: PaxiomTrustState;
  checks: Record<string, string>;
  receiptHash: string | null;
  summary: string;
  errors?: string[];
}

export interface GeneratedReceiptKeyPair {
  keyId: string;
  algorithm: 'ed25519';
  publicKey: string;
  privateKeyPem: string;
  publicKeyJwk: Record<string, unknown>;
}

export interface WebIssueReceiptOptions {
  privateKey: WebPrivateKeyInput;
  issuer: PaxiomReceiptIssuer;
  service: PaxiomReceiptService;
  request?: {
    method?: string;
    resource?: string;
    body?: unknown;
    requestHash?: string;
    resourceHash?: string;
    bodyHash?: string;
  };
  payment?: {
    scheme?: string;
    network?: string;
    asset?: string;
    amountAtomic?: string | number | bigint;
    amountDisplay?: string;
    payer?: string;
    payTo?: string;
    paymentRequirements?: unknown;
    paymentPayload?: unknown;
    paymentRequirementsHash?: string;
    paymentPayloadHash?: string;
    settlement?: Partial<PaxiomReceiptSettlement>;
  };
  output?: unknown;
  outputHash?: string;
  mimeType?: string;
  canonicalization?: PaxiomCanonicalizationMode;
  statusCode?: number;
  evidence?: PaxiomReceiptEvidence[];
  receiptId?: string;
  issuedAt?: string | Date;
  expiresAt?: string | Date;
}

export interface IssuedReceiptBundle {
  receipt: PaxiomReceiptV0;
  receiptHeader: string;
}

export interface ParsedX402Headers {
  txHash: string | null;
  transactionHash: string | null;
  settlementFailed: boolean;
  network: string | null;
  scheme: string | null;
  asset: string | null;
  amountAtomic: string | null;
  amountDisplay: string | null;
  payer: string | null;
  payTo: string | null;
}

export interface WebMiddlewareOptions {
  privateKey?: WebPrivateKeyInput;
  privateKeyPem?: string;
  issuer: PaxiomReceiptIssuer;
  serviceName?: string;
  paymentDefaults?: Record<string, unknown>;
  resolvePayment?: (ctx: {
    request: Request;
    response: Response;
    txHash: string | null;
    parsedX402: ParsedX402Headers;
  }) => Record<string, unknown> | Promise<Record<string, unknown>>;
  onReceipt?: (receipt: PaxiomReceiptV0) => void | Promise<void>;
}

export interface DiscoverIssuerKeysResult {
  ok: boolean;
  status: number;
  origin: string;
  keysUrl: string | null;
  issuer?: string | null;
  payTo?: string | null;
  keys: Array<{ keyId?: string; algorithm?: string; publicKey: string }>;
  publicKeys: string[];
}

export interface VerifyResponseReceiptResult {
  present: boolean;
  valid: boolean;
  trustState: PaxiomTrustState | 'malformed_header' | null;
  checks?: Record<string, string>;
  receipt: PaxiomReceiptV0 | null;
  verdict: VerifyReceiptResult | null;
  error?: string;
}

export interface PaxiomClientCommonOptions {
  baseUrl?: string;
  apiKey?: string;
  paymentHeader?: string;
  fetch?: typeof globalThis.fetch;
  fetchImpl?: typeof globalThis.fetch;
  timeoutMs?: number;
  trustedVerifierPublicKeys?: readonly string[];
  trustedPaxiomPublicKeys?: readonly string[];
}

export interface PreflightX402Options extends PaxiomClientCommonOptions {
  method?: 'POST' | 'GET' | 'HEAD';
  maxBudgetAtomic?: string | number | bigint;
  expectedNetwork?: string;
}

export interface PreflightX402Report {
  ok: boolean;
  targetUrl: string;
  probedMethod: string;
  verdict: 'proceed' | 'caution' | 'block';
  riskLevel: 'low' | 'medium' | 'high';
  httpStatus: number;
  selectedQuote: {
    scheme: string;
    network: string;
    rawNetwork: string;
    asset: string;
    canonicalUsdc: boolean;
    payTo: string;
    amountAtomic: string;
    maxTimeoutSeconds: number | null;
  } | null;
  recommendedMaxPaymentAtomic: string | null;
  checks: Record<string, string>;
  receiptSupport: {
    paxiomHeaderExposed: boolean;
    paxiomWellKnownKeys: number;
  };
  findings: Array<{ code: string; severity: string; message: string }>;
}

export interface PreflightX402Result {
  ok: boolean;
  status: number;
  paymentRequired: boolean;
  verdict?: 'proceed' | 'caution' | 'block' | null;
  riskLevel?: 'low' | 'medium' | 'high' | null;
  challenge?: Record<string, unknown> | null;
  error?: { code?: string; message?: string };
  report: PreflightX402Report | null;
  receiptVerification: VerifyResponseReceiptResult | null;
  paymentResponse: Record<string, unknown> | null;
}

export interface VerifyReceiptLiveOptions extends PaxiomClientCommonOptions {
  output?: unknown;
  expectedPayTo?: string;
}

export interface VerifyReceiptLiveResult {
  ok: boolean;
  status: number;
  paymentRequired: boolean;
  valid?: boolean;
  trustState?: PaxiomTrustState | null;
  challenge?: Record<string, unknown> | null;
  error?: { code?: string; message?: string };
  result: Record<string, unknown> | null;
  counterAttestedReceipt: PaxiomReceiptV0 | null;
  counterAttestedVerification: VerifyReceiptResult | null;
  paymentResponse: Record<string, unknown> | null;
}

export function canonicalize(value: unknown): string;
export function signingInputBytes(doc: { receiptVersion: string; payload: unknown }): Uint8Array;
export function signingInput(doc: { receiptVersion: string; payload: unknown }): Uint8Array;
export function explain(result: VerifyReceiptResult): string;

export function isByteArray(value: unknown): value is ArrayBufferView;
export function utf8ToBytes(str: string): Uint8Array;
export function bytesToUtf8(bytes: ArrayBufferView | ArrayBuffer): string;
export function bytesToHex(bytes: ArrayBufferView | ArrayBuffer): string;
export function hexToBytes(hexStr: string): Uint8Array;
export function bytesToBase64(bytes: ArrayBufferView | ArrayBuffer): string;
export function base64ToBytes(value: string): Uint8Array;
export function bytesToBase64Url(bytes: ArrayBufferView | ArrayBuffer): string;
export function base64UrlToBytes(value: string): Uint8Array;

export function normalizeTransactionId(rawTx: string | null | undefined): string | null;
export function decodeReceiptHeader(headerValue: string): PaxiomReceiptV0;
export function parseX402Headers(
  headers?: unknown,
  responseHeaders?: unknown
): ParsedX402Headers;

export function sha256Hex(bytes: ArrayBufferView | ArrayBuffer | string): Promise<string>;
export function hashCanonical(value: unknown): Promise<string>;
export function publicKeyFromPrivateKey(privateKey: WebPrivateKeyInput): Promise<string>;
export function generateReceiptKeyPair(opts?: string | { keyId?: string }): Promise<GeneratedReceiptKeyPair>;
export function issueReceipt(options: WebIssueReceiptOptions): Promise<IssuedReceiptBundle>;
export function verifyReceipt(receipt: unknown, options?: VerifyReceiptOptions): Promise<VerifyReceiptResult>;

export function withPaxiomReceipt<TArgs extends unknown[]>(
  handler: (request: Request, ...rest: TArgs) => Response | Promise<Response>,
  options: WebMiddlewareOptions
): (request: Request, ...rest: TArgs) => Promise<Response>;

export function resolveSafeApiOrigin(rawBaseUrl?: string): string;
export function discoverIssuerKeys(
  originOrResourceUrl: string,
  options?: { fetch?: typeof globalThis.fetch; fetchImpl?: typeof globalThis.fetch; timeoutMs?: number }
): Promise<DiscoverIssuerKeysResult>;
export function verifyResponseReceipt(
  responseOrHeaders: unknown,
  options?: VerifyReceiptOptions
): Promise<VerifyResponseReceiptResult>;
export function preflightX402(
  targetUrl: string,
  options?: PreflightX402Options
): Promise<PreflightX402Result>;
export function verifyReceiptLive(
  receipt: unknown,
  options?: VerifyReceiptLiveOptions
): Promise<VerifyReceiptLiveResult>;
