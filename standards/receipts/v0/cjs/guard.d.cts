import type { PaxiomReceiptV0, VerifyReceiptResult } from './web.cjs';
import type {
  EvmReceiptTrieProof,
  ClaimProofEnvelope,
  PaxiomRootAttestationV0,
  TrustedRootsInput,
  RootFinalityTier
} from './proofs.cjs';

export type VerifyResult = VerifyReceiptResult;

export const ESCROW_SCHEMES: readonly string[];
export const DEFAULT_ALLOWED_SCHEMES: readonly string[];

export type AtomicAmountInput = bigint | string | number;

export interface AuthCaptureTerms {
  operator: string | null;
  minFeeBps: bigint | null;
  maxFeeBps: bigint | null;
  authorizationExpiry: bigint | null;
  preApprovalExpiry: bigint | null;
  refundExpiry: bigint | null;
  paymentInfoHash: string | null;
  feeReceiver: string | null;
  collector: string | null;
  escrowAddress: string | null;
}

export interface NormalizedPaymentChallenge {
  scheme: string | null;
  network: string | null;
  asset: string | null;
  payTo: string | null;
  amountAtomic: bigint | null;
  amountAtomicString: string | null;
  authCapture: AuthCaptureTerms | null;
  rawRequirement: Record<string, unknown>;
}

export interface BuyerFirewallPolicy {
  maxPerCallAtomic?: AtomicAmountInput | null;
  maxPerOriginWindowAtomic?: AtomicAmountInput | null;
  maxSessionAtomic?: AtomicAmountInput | null;
  maxUnescrowedExactAtomic?: AtomicAmountInput | null;
  allowedOrigins?: string[];
  deniedOrigins?: string[];
  allowedNetworks?: string[];
  allowedAssets?: string[];
  allowedSchemes?: string[];
  allowedPayTo?: string[];
  pinnedPayToByOrigin?: Record<string, string | string[]>;
  trustedOperators?: string[];
  allowUnpinnedEscrowOperator?: boolean;
  maxAllowedFeeBps?: AtomicAmountInput;
  minAuthWindowSec?: number;
  maxAuthWindowSec?: number;
  allowLoopbackHttp?: boolean;
  allowZeroAmount?: boolean;
  maxConsecutiveFailures?: number;
  cooldownMs?: number;
}

export interface PreSignDecision {
  allow: boolean;
  code: string;
  reason: string;
  origin: string | null;
  challenge: NormalizedPaymentChallenge | null;
  reservationId: string | null;
  reservedAtomic: bigint;
}

export interface FraudEvidenceRecord {
  recordedAt: string;
  reasonCode: string;
  reason: string;
  nonRepudiable: boolean;
  origin: string | null;
  status: number;
  paymentInfoHash: string | null;
  settlementFinality: 'escrow_hold' | 'irreversible_exact';
  issuerKeyId: string | null;
  issuerPublicKey: string | null;
  receiptId: string | null;
  receiptHash: string | null;
  claimedOutputHash: string | null;
  observedBodySha256: string | null;
  rawReceiptHeader: string | null;
}

export interface ArbiterDecision {
  action: 'CAPTURE' | 'VOID';
  ok: boolean;
  reasonCode: string;
  reason: string;
  settlementFinality: 'escrow_hold' | 'irreversible_exact';
  paymentInfoHash: string | null;
  captureAmountAtomic: bigint;
  receipt: PaxiomReceiptV0 | null;
  receiptHash: string | null;
  verification: VerifyResult | null;
  parsedOutput: unknown;
  fraudEvidence: FraudEvidenceRecord | null;
}

export interface SpendLedger {
  readonly windowMs: number;
  isCircuitOpen(origin: string, nowMs?: number): {
    open: boolean;
    cooldownUntilMs: number;
    consecutiveFailures: number;
    lastFailureReason: string | null;
  };
  getUsage(origin: string, nowMs?: number): {
    committedSessionAtomic: bigint;
    reservedSessionAtomic: bigint;
    activeSessionAtomic: bigint;
    originCommittedWindowAtomic: bigint;
    originReservedAtomic: bigint;
    activeOriginWindowAtomic: bigint;
  };
  reserve(args: {
    origin: string;
    amountAtomic: AtomicAmountInput;
    scheme?: string;
    nowMs?: number;
  }): string;
  commit(
    reservationId: string,
    opts?: { actualAmountAtomic?: AtomicAmountInput; receiptHash?: string | null; nowMs?: number }
  ): boolean;
  release(
    reservationId: string,
    opts?: {
      recordFailure?: boolean;
      failureReason?: string | null;
      retainOutlayInBudget?: boolean;
      maxConsecutiveFailures?: number;
      cooldownMs?: number;
      nowMs?: number;
    }
  ): boolean;
  recordOriginFailure(
    origin: string,
    opts?: {
      failureReason?: string;
      maxConsecutiveFailures?: number;
      cooldownMs?: number;
      nowMs?: number;
    }
  ): { consecutiveFailures: number; cooldownUntilMs: number; circuitTripped: boolean };
  hasSeenReceipt(receiptHash: string): boolean;
  recordReceipt(receiptHash: string): void;
  snapshot(nowMs?: number): {
    committedSessionAtomic: bigint;
    reservedSessionAtomic: bigint;
    activeSessionAtomic: bigint;
    activeReservations: number;
    trackedReceiptHashes: number;
    origins: Record<string, {
      committedWindowAtomic: bigint;
      reservedAtomic: bigint;
      consecutiveFailures: number;
      cooldownUntilMs: number;
      circuitOpen: boolean;
      lastFailureReason: string | null;
    }>;
  };
}

export function normalizeCaip2NetworkId(rawNet: string): string | null;
export function parseAtomicBigInt(value: AtomicAmountInput, label?: string): bigint;
export function resolveFirewallOrigin(
  rawUrl: string,
  opts?: { allowLoopbackHttp?: boolean }
): { ok: true; origin: string; url: URL } | { ok: false; code: string; reason: string };
export function extractPaymentChallenges(source: unknown): NormalizedPaymentChallenge[];
export function createMemorySpendLedger(options?: {
  windowMs?: number;
  maxTrackedOrigins?: number;
  maxTrackedReceipts?: number;
}): SpendLedger;
export function evaluatePreSignPolicy(
  input: { url: string; challenge?: unknown; response?: unknown; nowMs?: number },
  policy: BuyerFirewallPolicy,
  ledger?: SpendLedger | null
): PreSignDecision;
export function evaluateDeliveryArbiter(
  input: {
    origin?: string;
    reservationId?: string | null;
    challenge?: NormalizedPaymentChallenge | null;
    scheme?: string;
    paymentInfoHash?: string | null;
    request?: { url?: string; method?: string; body?: unknown; bodyBytes?: Uint8Array };
    response?: { status?: number; headers?: unknown };
    body?: unknown;
    bodyBytes?: Uint8Array;
    receipt?: PaxiomReceiptV0 | null;
    receiptHeader?: string;
    settlementProof?: EvmReceiptTrieProof;
    claimProof?: ClaimProofEnvelope;
    rootAttestation?: PaxiomRootAttestationV0;
  },
  options?: {
    ledger?: SpendLedger | null;
    expectedIssuerPublicKeys?: string[] | Set<string>;
    expectedPayTo?: string;
    expectedPayer?: string;
    trustedVerifierPublicKeys?: string[];
    trustedRootPublicKeys?: readonly string[] | ReadonlySet<string>;
    trustedRoots?: TrustedRootsInput;
    allowedFinalityTiers?: readonly RootFinalityTier[];
    settlementProof?: EvmReceiptTrieProof;
    claimProof?: ClaimProofEnvelope;
    rootAttestation?: PaxiomRootAttestationV0;
    requireReceipt?: boolean;
    allowUncheckedSettlementClaim?: boolean;
    strictStandardHeaderOnly?: boolean;
    enforceRequestBinding?: boolean;
    enforcePaymentBinding?: boolean;
    validateContent?: (
      output: unknown,
      ctx: {
        request: unknown;
        response: unknown;
        receipt: PaxiomReceiptV0 | null;
        verification: VerifyResult | null;
        rawBodyBytes: Uint8Array;
      }
    ) => boolean | { ok: boolean; reason?: string; captureAmountAtomic?: AtomicAmountInput } | Promise<boolean | { ok: boolean; reason?: string; captureAmountAtomic?: AtomicAmountInput }>;
    maxResponseBytes?: number;
    maxConsecutiveFailures?: number;
    cooldownMs?: number;
    nowMs?: number;
    crypto?: Crypto;
  }
): Promise<ArbiterDecision>;

export interface GuardedFetchResult {
  ok: boolean;
  stage: 'pre_request' | 'unpaid_pass_through' | 'pre_sign' | 'post_delivery';
  preSign: PreSignDecision | null;
  arbiter: ArbiterDecision | null;
  response: Response | null;
  bodyBytes: Uint8Array;
  data: unknown;
}

export function createGuardedFetch(options: {
  policy: BuyerFirewallPolicy;
  ledger?: SpendLedger;
  signPayment: (ctx: {
    challenge: NormalizedPaymentChallenge;
    preSign: PreSignDecision;
    request: { url: string; method: string; bodyBytes?: Uint8Array };
  }) => string | { paymentSignature?: string; headers?: Record<string, string> } | Promise<string | { paymentSignature?: string; headers?: Record<string, string> }>;
  fetchImpl?: typeof fetch;
  expectedIssuerPublicKeys?: string[] | Set<string> | ((origin: string) => Promise<string[] | Set<string>>);
  trustedVerifierPublicKeys?: string[];
  trustedRootPublicKeys?: readonly string[] | ReadonlySet<string>;
  trustedRoots?: TrustedRootsInput;
  allowedFinalityTiers?: readonly RootFinalityTier[];
  allowUncheckedSettlementClaim?: boolean;
  requireReceipt?: boolean;
  validateContent?: (
    output: unknown,
    ctx: {
      request: unknown;
      response: unknown;
      receipt: PaxiomReceiptV0 | null;
      verification: VerifyResult | null;
      rawBodyBytes: Uint8Array;
    }
  ) => boolean | { ok: boolean; reason?: string; captureAmountAtomic?: AtomicAmountInput } | Promise<boolean | { ok: boolean; reason?: string; captureAmountAtomic?: AtomicAmountInput }>;
  onCapture?: (decision: ArbiterDecision) => unknown | Promise<unknown>;
  onVoid?: (decision: ArbiterDecision) => unknown | Promise<unknown>;
  maxResponseBytes?: number;
  timeoutMs?: number;
  crypto?: Crypto;
}): (urlOrRequest: string | Request, init?: RequestInit, callOverrides?: {
  expectedIssuerPublicKeys?: string[] | Set<string>;
  requireReceipt?: boolean;
  validateContent?: (output: unknown, ctx: unknown) => unknown;
}) => Promise<GuardedFetchResult>;
