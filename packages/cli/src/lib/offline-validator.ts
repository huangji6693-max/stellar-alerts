import * as StellarSdk from 'stellar-sdk';

export interface OfflineOperationSummary {
  index: number;
  type: string;
  source?: string;
  destination?: string;
  amount?: string;
  asset?: string;
  details: Record<string, unknown>;
}

export interface SignerVerificationResult {
  publicKey: string;
  hintHex: string;
  matchedHint: boolean;
  verified: boolean;
}

export interface OfflineValidationOptions {
  /** Stellar network name ('testnet' | 'public' | 'mainnet' | 'futurenet') or raw passphrase */
  network?: string;
  /** Expected signer G... public keys to cryptographically verify against the envelope signatures */
  expectedSigners?: string[];
}

export interface OfflineValidationReport {
  valid: boolean;
  envelopeType: 'Transaction' | 'FeeBumpTransaction';
  networkPassphrase: string;
  txHash: string;
  sourceAccount: string;
  sequence: string;
  fee: string;
  memo: {
    type: string;
    value: string | null;
  };
  timeBounds: {
    minTime: string;
    maxTime: string;
  } | null;
  signatureCount: number;
  signatures: Array<{
    hintHex: string;
    signatureHex: string;
  }>;
  signerVerifications: SignerVerificationResult[];
  operations: OfflineOperationSummary[];
  warnings: string[];
  errors: string[];
}

export function resolveNetworkPassphrase(network?: string): string {
  const normalized = (network ?? 'testnet').trim().toLowerCase();
  if (normalized === 'public' || normalized === 'mainnet') {
    return StellarSdk.Networks.PUBLIC;
  }
  if (normalized === 'testnet') {
    return StellarSdk.Networks.TESTNET;
  }
  if (normalized === 'futurenet') {
    return StellarSdk.Networks.FUTURENET;
  }
  return network!;
}

function formatAsset(asset: unknown): string | undefined {
  if (!asset || typeof asset !== 'object') return undefined;
  const candidate = asset as { isNative?: () => boolean; getCode?: () => string; getIssuer?: () => string };
  if (typeof candidate.isNative === 'function') {
    return candidate.isNative() ? 'XLM (native)' : `${candidate.getCode?.()}:${candidate.getIssuer?.()}`;
  }
  return undefined;
}

function summarizeOperation(op: StellarSdk.Operation, index: number): OfflineOperationSummary {
  const raw = op as unknown as Record<string, unknown>;
  const details: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(raw)) {
    if (key === 'type' || value === undefined) continue;
    const formattedAsset = formatAsset(value);
    if (formattedAsset) {
      details[key] = formattedAsset;
    } else if (Buffer.isBuffer(value)) {
      details[key] = value.toString('hex');
    } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      details[key] = value;
    }
  }

  return {
    index,
    type: op.type,
    source: op.source,
    destination: typeof raw.destination === 'string' ? raw.destination : undefined,
    amount: typeof raw.amount === 'string' ? raw.amount : undefined,
    asset: formatAsset(raw.asset) ?? formatAsset(raw.sendAsset) ?? formatAsset(raw.destAsset),
    details,
  };
}

/**
 * Decodes, inspects, and cryptographically verifies a Stellar TransactionEnvelope XDR
 * completely offline with zero network calls.
 */
export function validateTransactionOffline(
  envelopeXdr: string,
  options: OfflineValidationOptions = {},
): OfflineValidationReport {
  const trimmed = (envelopeXdr ?? '').trim();
  const networkPassphrase = resolveNetworkPassphrase(options.network);
  const warnings: string[] = [];
  const errors: string[] = [];

  if (!trimmed) {
    throw new Error('Transaction envelope XDR cannot be empty');
  }

  let parsed: StellarSdk.Transaction | StellarSdk.FeeBumpTransaction;
  try {
    parsed = StellarSdk.TransactionBuilder.fromXDR(trimmed, networkPassphrase);
  } catch (err) {
    throw new Error(`Invalid TransactionEnvelope XDR: ${(err as Error).message}`);
  }

  const isFeeBump = parsed instanceof StellarSdk.FeeBumpTransaction;
  const innerTx: StellarSdk.Transaction = isFeeBump
    ? (parsed as StellarSdk.FeeBumpTransaction).innerTransaction
    : (parsed as StellarSdk.Transaction);

  const txHashBuffer = parsed.hash();
  const txHash = txHashBuffer.toString('hex');

  const signatures = parsed.signatures.map((sig) => ({
    hintHex: Buffer.from(sig.hint()).toString('hex'),
    signatureHex: Buffer.from(sig.signature()).toString('hex'),
  }));

  if (signatures.length === 0) {
    warnings.push('Envelope contains 0 decorated signatures.');
  }

  const signerVerifications: SignerVerificationResult[] = [];
  for (const pubKey of options.expectedSigners ?? []) {
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(pubKey)) {
      errors.push(`Invalid Stellar Ed25519 public key: ${pubKey}`);
      signerVerifications.push({
        publicKey: pubKey,
        hintHex: '',
        matchedHint: false,
        verified: false,
      });
      continue;
    }

    const keypair = StellarSdk.Keypair.fromPublicKey(pubKey);
    const expectedHint = Buffer.from(keypair.signatureHint());
    const hintHex = expectedHint.toString('hex');

    let matchedHint = false;
    let verified = false;

    for (const decorated of parsed.signatures) {
      const sigHint = Buffer.from(decorated.hint());
      if (sigHint.equals(expectedHint)) {
        matchedHint = true;
      }
      if (keypair.verify(txHashBuffer, Buffer.from(decorated.signature()))) {
        matchedHint = true;
        verified = true;
        break;
      }
    }

    if (!verified) {
      errors.push(`Missing or invalid signature for expected signer ${pubKey}`);
    }

    signerVerifications.push({
      publicKey: pubKey,
      hintHex,
      matchedHint,
      verified,
    });
  }

  const memoType = innerTx.memo?.type ?? 'none';
  let memoValue: string | null = null;
  if (innerTx.memo && innerTx.memo.value !== null && innerTx.memo.value !== undefined) {
    memoValue = Buffer.isBuffer(innerTx.memo.value)
      ? memoType === 'text'
        ? innerTx.memo.value.toString('utf8')
        : innerTx.memo.value.toString('hex')
      : String(innerTx.memo.value);
  }

  const timeBounds = innerTx.timeBounds
    ? {
        minTime: String(innerTx.timeBounds.minTime),
        maxTime: String(innerTx.timeBounds.maxTime),
      }
    : null;

  if (!timeBounds || timeBounds.maxTime === '0') {
    warnings.push('Transaction has no upper timebound (maxTime = 0); consider setting an expiration.');
  }

  const operations = innerTx.operations.map((op, idx) => summarizeOperation(op, idx));

  return {
    valid: errors.length === 0,
    envelopeType: isFeeBump ? 'FeeBumpTransaction' : 'Transaction',
    networkPassphrase,
    txHash,
    sourceAccount: isFeeBump ? (parsed as StellarSdk.FeeBumpTransaction).feeSource : innerTx.source,
    sequence: innerTx.sequence,
    fee: parsed.fee,
    memo: {
      type: String(memoType),
      value: memoValue,
    },
    timeBounds,
    signatureCount: signatures.length,
    signatures,
    signerVerifications,
    operations,
    warnings,
    errors,
  };
}

/**
 * Signs a Base64 TransactionEnvelope XDR completely offline using a Stellar secret key (`S...`)
 * and returns the updated Base64 XDR and transaction hash.
 */
export function signEnvelopeOffline(
  envelopeXdr: string,
  secretKey: string,
  network?: string,
): { signedXdr: string; txHash: string; signerPublicKey: string } {
  if (!StellarSdk.StrKey.isValidEd25519SecretSeed(secretKey)) {
    throw new Error('Invalid Stellar Ed25519 secret key (expected S... seed)');
  }
  const passphrase = resolveNetworkPassphrase(network);
  const keypair = StellarSdk.Keypair.fromSecret(secretKey);
  const tx = StellarSdk.TransactionBuilder.fromXDR(envelopeXdr.trim(), passphrase);
  tx.sign(keypair);

  return {
    signedXdr: tx.toEnvelope().toXDR('base64'),
    txHash: tx.hash().toString('hex'),
    signerPublicKey: keypair.publicKey(),
  };
}
