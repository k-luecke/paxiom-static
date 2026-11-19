export const ROOT_ATTESTATION_VERSION: 'paxiom.root.v0';
export const ERC8021_MARKER_HEX: '0x80218021802180218021802180218021';
export const EMPTY_TRIE_ROOT_HEX: '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421';
export const EMPTY_CODE_HASH_HEX: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
export const ERC20_TRANSFER_TOPIC0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export type RootFinalityTier =
  | 'l1-sync-finalized'
  | 'l2-sequencer-attested'
  | 'bft-finalized'
  | 'rpc-head';

export const ALLOWED_FINALITY_TIERS: readonly RootFinalityTier[];
export const CANONICAL_USDC_BY_NETWORK: Readonly<Record<string, string>>;

export type RlpInput = Uint8Array | ArrayBufferView | ArrayBuffer | bigint | number | readonly RlpInput[];
export type RlpDecoded = Uint8Array | RlpDecoded[];
export type FlexibleBytesInput = Uint8Array | ArrayBufferView | ArrayBuffer | string;
export type FlexibleUint256Input = bigint | number | string | Uint8Array | ArrayBufferView | ArrayBuffer;

export function keccak256Bytes(input: Uint8Array | ArrayBufferView | ArrayBuffer): Uint8Array;
export function keccak256Hex(input: Uint8Array | ArrayBufferView | ArrayBuffer): string;

export function uintToMinimalBytes(value: bigint | number): Uint8Array;
export function bytesToBigInt(
  bytes: Uint8Array | ArrayBufferView | ArrayBuffer,
  options?: { strictMinimal?: boolean }
): bigint;
export function rlpEncode(item: RlpInput): Uint8Array;
export function rlpDecode(input: FlexibleBytesInput): RlpDecoded;

export function normalizeEvmNetworkId(rawNet: string): string | null;
export function deriveAccountTrieKey(address: FlexibleBytesInput): Uint8Array;
export function deriveStorageTrieKey(slot: FlexibleUint256Input): Uint8Array;
export function computeMappingSlot(key: FlexibleUint256Input, baseSlot: FlexibleUint256Input): string;
export function computeNestedMappingSlot(
  outerKey: FlexibleUint256Input,
  innerKey: FlexibleUint256Input,
  baseSlot: FlexibleUint256Input
): string;
export function computeEip3009AuthStateSlot(
  authorizer: FlexibleBytesInput,
  nonceBytes32: FlexibleBytesInput,
  baseSlot: FlexibleUint256Input
): string;

export interface MptVerifyResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  rootHash: string | null;
  keyHex: string | null;
  value: Uint8Array | null;
}

export function verifyMptProof(options: {
  rootHash: FlexibleBytesInput;
  key: FlexibleBytesInput;
  proof: readonly FlexibleBytesInput[];
  expectedValue?: FlexibleBytesInput | null;
}): MptVerifyResult;

export interface BuiltMptProof {
  rootHash: string;
  keyHex: string;
  value: Uint8Array | null;
  proof: string[];
}

export function buildMptProof(
  entries: ReadonlyArray<{ key: FlexibleBytesInput; value: FlexibleBytesInput }>,
  targetKey: FlexibleBytesInput
): BuiltMptProof;

export interface EvmAccountTuple {
  nonce: bigint;
  balance: bigint;
  storageRoot: string;
  codeHash: string;
}

export function encodeEvmAccount(account?: {
  nonce?: FlexibleUint256Input;
  balance?: FlexibleUint256Input;
  storageRoot?: FlexibleBytesInput;
  storageHash?: FlexibleBytesInput;
  codeHash?: FlexibleBytesInput;
}): Uint8Array;

export function decodeEvmAccount(rawAccountRlp: FlexibleBytesInput): EvmAccountTuple;

export interface AccountProofResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  address: string | null;
  stateRoot: string | null;
  exists: boolean;
  account: EvmAccountTuple | null;
}

export function verifyAccountProof(options: {
  stateRoot: FlexibleBytesInput;
  address: FlexibleBytesInput;
  accountProof: readonly FlexibleBytesInput[];
  expectedAccount?: {
    nonce?: FlexibleUint256Input;
    balance?: FlexibleUint256Input;
    storageRoot?: FlexibleBytesInput;
    storageHash?: FlexibleBytesInput;
    codeHash?: FlexibleBytesInput;
  } | null;
}): AccountProofResult;

export interface StorageProofResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  slotHex: string | null;
  storageRoot: string | null;
  value: bigint | null;
  valueHex: string | null;
  valueHex32: string | null;
}

export function verifyStorageProof(options: {
  storageRoot: FlexibleBytesInput;
  key?: FlexibleUint256Input;
  slot?: FlexibleUint256Input;
  proof?: readonly FlexibleBytesInput[];
  storageProof?: readonly FlexibleBytesInput[];
  expectedValue?: FlexibleUint256Input;
}): StorageProofResult;

export interface Eip1186StorageEntry {
  key?: FlexibleUint256Input;
  slot?: FlexibleUint256Input;
  value: FlexibleUint256Input;
  proof?: readonly FlexibleBytesInput[];
  storage_proof?: readonly FlexibleBytesInput[];
}

export interface Eip1186ProofResponse {
  address: FlexibleBytesInput;
  nonce?: FlexibleUint256Input;
  balance?: FlexibleUint256Input;
  storageHash?: FlexibleBytesInput;
  storageRoot?: FlexibleBytesInput;
  storage_root?: FlexibleBytesInput;
  codeHash?: FlexibleBytesInput;
  code_hash?: FlexibleBytesInput;
  accountProof?: readonly FlexibleBytesInput[];
  account_proof?: readonly FlexibleBytesInput[];
  storageProof?: readonly Eip1186StorageEntry[];
  storage_proof?: readonly Eip1186StorageEntry[];
}

export interface Eip1186VerifyResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  address?: string | null;
  stateRoot?: string | null;
  exists?: boolean;
  account?: EvmAccountTuple | null;
  storage?: StorageProofResult[];
}

export function verifyEip1186Proof(options: {
  stateRoot: FlexibleBytesInput;
  proof: Eip1186ProofResponse;
  expectedStorage?:
    | ReadonlyArray<{ slot?: FlexibleUint256Input; key?: FlexibleUint256Input; value: FlexibleUint256Input }>
    | Record<string, FlexibleUint256Input>;
}): Eip1186VerifyResult;

export interface RpcTransactionLog {
  address: FlexibleBytesInput;
  topics: readonly FlexibleBytesInput[];
  data?: FlexibleBytesInput;
}

export interface RpcTransactionReceipt {
  type?: FlexibleUint256Input;
  status?: FlexibleUint256Input;
  root?: FlexibleBytesInput;
  cumulativeGasUsed: FlexibleUint256Input;
  logsBloom: FlexibleBytesInput;
  logs: readonly RpcTransactionLog[];
  transactionIndex?: FlexibleUint256Input;
  transactionHash?: string;
  blockNumber?: FlexibleUint256Input;
  blockHash?: string;
  depositNonce?: FlexibleUint256Input | null;
  depositReceiptVersion?: FlexibleUint256Input | null;
}

export interface DecodedEvmLog {
  logIndex: number;
  address: string;
  topics: string[];
  data: string;
}

export interface DecodedEvmReceipt {
  txType: number;
  status: number | null;
  postStateRoot?: string;
  cumulativeGasUsed: bigint;
  logsBloom: string;
  logs: DecodedEvmLog[];
  depositNonce?: bigint;
  depositReceiptVersion?: bigint;
}

export function encodeEvmReceipt(rpcReceipt: RpcTransactionReceipt): Uint8Array;
export function decodeEvmReceipt(rawReceiptBytes: FlexibleBytesInput): DecodedEvmReceipt;

export interface EvmReceiptTrieProof {
  type?: 'evm_receipt_trie_v0' | string;
  network?: string;
  blockNumber?: string | number | bigint;
  blockHash?: string;
  receiptsRoot: FlexibleBytesInput;
  transactionIndex: FlexibleUint256Input;
  txIndex?: FlexibleUint256Input;
  transactionHash?: string;
  receiptProof?: readonly FlexibleBytesInput[];
  proof?: readonly FlexibleBytesInput[];
  rootAttestation?: PaxiomRootAttestationV0;
}

export function buildReceiptTrieProof(
  blockReceipts: readonly RpcTransactionReceipt[],
  targetTxHashOrIndex: string | number | bigint,
  extra?: {
    network?: string;
    blockNumber?: FlexibleUint256Input;
    blockHash?: string;
  }
): EvmReceiptTrieProof;

export interface EvmReceiptVerifyResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  receiptsRoot?: string | null;
  transactionIndex?: number;
  receipt?: DecodedEvmReceipt;
}

export function verifyEvmReceiptProof(options: {
  receiptsRoot: FlexibleBytesInput;
  transactionIndex: FlexibleUint256Input;
  receiptProof: readonly FlexibleBytesInput[];
}): EvmReceiptVerifyResult;

export interface TrustedBlockRootEntry {
  network?: string;
  blockNumber?: FlexibleUint256Input;
  blockHash?: string;
  stateRoot?: string;
  receiptsRoot?: string;
}

export type TrustedRootsInput =
  | readonly (string | TrustedBlockRootEntry)[]
  | ReadonlySet<string | TrustedBlockRootEntry>
  | Record<string, string | TrustedBlockRootEntry>
  | TrustedBlockRootEntry;

export interface PaxiomRootAttestationPayload {
  network: string;
  blockNumber: string;
  blockHash: string;
  stateRoot?: string;
  receiptsRoot?: string;
  timestamp?: number;
  finalityTier: RootFinalityTier;
  issuedAt: string;
  expiresAt?: string;
  attester: {
    name: string;
    keyId: string;
    uri?: string;
  };
}

export interface PaxiomRootAttestationV0 {
  attestationVersion: 'paxiom.root.v0';
  payload: PaxiomRootAttestationPayload;
  signature: {
    algorithm: 'ed25519';
    keyId: string;
    publicKey: string;
    value: string;
  };
}

export interface ClaimProofEnvelope {
  network?: string;
  blockNumber?: FlexibleUint256Input;
  blockHash?: string;
  stateRoot?: FlexibleBytesInput;
  proof?: Eip1186ProofResponse;
  expectedStorage?:
    | ReadonlyArray<{ slot?: FlexibleUint256Input; key?: FlexibleUint256Input; value: FlexibleUint256Input }>
    | Record<string, FlexibleUint256Input>;
  rootAttestation?: PaxiomRootAttestationV0;
  allowUnanchoredRoot?: boolean;
}

export interface MatchedErc20Transfer {
  logIndex: number;
  token: string;
  from: string;
  to: string;
  amountAtomic: string;
}

export interface UsdcSettlementVerifyResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  rootAnchored: boolean;
  anchorSource?: string | null;
  network?: string;
  blockNumber?: string | null;
  blockHash?: string | null;
  receiptsRoot?: string | null;
  transactionIndex?: number;
  matchedTransfer?: MatchedErc20Transfer;
  allMatchedTransfers?: MatchedErc20Transfer[];
}

export function verifyUsdcSettlementProofSync(options: {
  settlementProof: EvmReceiptTrieProof;
  network?: string;
  expectedPayTo?: string;
  expectedPayer?: string;
  minAmountAtomic?: FlexibleUint256Input;
  expectedAsset?: string;
  expectedTransactionHash?: string;
  trustedRoots?: TrustedRootsInput | null;
  verifiedRootAttestation?: { ok: boolean; payload: PaxiomRootAttestationPayload } | null;
  allowUnanchoredRoot?: boolean;
}): UsdcSettlementVerifyResult;

export function verifyUsdcSettlementProof(options: {
  settlementProof: EvmReceiptTrieProof;
  network?: string;
  expectedPayTo?: string;
  expectedPayer?: string;
  minAmountAtomic?: FlexibleUint256Input;
  expectedAsset?: string;
  expectedTransactionHash?: string;
  trustedRoots?: TrustedRootsInput | null;
  rootAttestation?: PaxiomRootAttestationV0 | null;
  trustedRootPublicKeys?: readonly string[] | ReadonlySet<string> | null;
  trustedVerifierPublicKeys?: readonly string[] | ReadonlySet<string> | null;
  allowedFinalityTiers?: readonly RootFinalityTier[];
  allowUnanchoredRoot?: boolean;
  now?: number | Date;
  crypto?: Crypto;
}): Promise<UsdcSettlementVerifyResult>;

export function rootAttestationSigningBytes(payload: PaxiomRootAttestationPayload): Uint8Array;
export function validateRootAttestationStructure(attestation: unknown, depth?: number): string[];

export function issueRootAttestation(options: {
  privateKey: string | Uint8Array | Record<string, unknown>;
  network: string;
  blockNumber: FlexibleUint256Input;
  blockHash: FlexibleBytesInput;
  stateRoot?: FlexibleBytesInput;
  receiptsRoot?: FlexibleBytesInput;
  timestamp?: number;
  finalityTier?: RootFinalityTier;
  issuedAt?: string | Date;
  expiresAt?: string | Date;
  attester: { name: string; keyId: string; uri?: string };
  crypto?: Crypto;
}): Promise<PaxiomRootAttestationV0>;

export interface VerifyRootAttestationResult {
  ok: boolean;
  verified: boolean;
  code: string;
  reason: string;
  payload: PaxiomRootAttestationPayload | null;
  signerPublicKey?: string;
}

export function verifyRootAttestation(
  attestation: unknown,
  options?: {
    trustedRootPublicKeys?: readonly string[] | ReadonlySet<string> | null;
    allowedFinalityTiers?: readonly RootFinalityTier[];
    now?: number | Date;
    crypto?: Crypto;
  }
): Promise<VerifyRootAttestationResult>;

export interface Erc8021CustomRegistry {
  address: string;
  chainId: number;
}

export interface Erc8021AttributionSchema0 {
  id?: 0;
  codes: readonly string[];
}

export interface Erc8021AttributionSchema1 {
  id?: 1;
  codes: readonly string[];
  codeRegistry: Erc8021CustomRegistry;
}

export interface Erc8021AttributionSchema2 {
  id?: 2;
  appCode?: string;
  walletCode?: string;
  serviceCodes?: readonly string[];
  registries?: {
    app?: Erc8021CustomRegistry;
    wallet?: Erc8021CustomRegistry;
  };
  metadata?: Record<string, unknown>;
}

export type Erc8021AttributionInput =
  | string
  | readonly string[]
  | Erc8021AttributionSchema0
  | Erc8021AttributionSchema1
  | Erc8021AttributionSchema2;

export interface DecodedErc8021Result {
  ok: boolean;
  present: boolean;
  code: string;
  reason: string;
  schemaId: 0 | 1 | 2 | number | null;
  calldataWithoutSuffix?: string;
  attribution: Erc8021AttributionSchema0 | Erc8021AttributionSchema1 | Erc8021AttributionSchema2 | null;
}

export function encodeErc8021Suffix(attribution: Erc8021AttributionInput): string;
export function appendErc8021Suffix(calldata: FlexibleBytesInput, attribution: Erc8021AttributionInput): string;
export function decodeErc8021Suffix(calldata: FlexibleBytesInput): DecodedErc8021Result;
