import * as StellarSdk from 'stellar-sdk';

export const ED25519_SIGNATURE_HEADER = 'Stellar-Ed25519-Signature';

export interface Ed25519WebhookSignatureResult {
  /** Unix timestamp (ms) bound into the signed canonical message */
  timestamp: number;
  /** Hex-encoded 64-byte Ed25519 signature */
  signature: string;
  /** Stellar StrKey Ed25519 public key (G...) */
  publicKey: string;
  /** Formatted header value: t=<timestamp>,s=<hexSig>,pk=<G...publicKey> */
  headerValue: string;
}

export interface WellKnownStellarAlertsConfig {
  webhookSigningPublicKey: string;
  algorithm: 'Ed25519';
  header: typeof ED25519_SIGNATURE_HEADER;
  canonicalFormat: '{timestamp}.{rawBody}';
}

let cachedFallbackKeypair: StellarSdk.Keypair | null = null;

/**
 * Resolves the server's Ed25519 signing keypair from `WEBHOOK_ED25519_SECRET_KEY`
 * (or an explicit `S...` seed), falling back to a process-lifetime generated keypair
 * in development/test environments when the env var is not configured.
 */
export function getEd25519SigningKeypair(secretSeedOverride?: string): StellarSdk.Keypair {
  const seed = (secretSeedOverride ?? process.env.WEBHOOK_ED25519_SECRET_KEY ?? '').trim();
  if (seed) {
    if (!StellarSdk.StrKey.isValidEd25519SecretSeed(seed)) {
      throw new Error('Invalid WEBHOOK_ED25519_SECRET_KEY: expected a valid Stellar S... Ed25519 secret seed');
    }
    return StellarSdk.Keypair.fromSecret(seed);
  }

  if (!cachedFallbackKeypair) {
    cachedFallbackKeypair = StellarSdk.Keypair.random();
  }
  return cachedFallbackKeypair;
}

/**
 * Constructs the canonical byte buffer signed by the Ed25519 webhook signer:
 * `${timestamp}.${rawBody}` encoded as UTF-8.
 */
export function buildCanonicalEd25519Message(rawBody: string, timestamp: number | string): Buffer {
  return Buffer.from(`${timestamp}.${rawBody}`, 'utf8');
}

/**
 * Signs a webhook payload using a Stellar Ed25519 keypair (`S...` private seed -> `G...` public key).
 */
export function signWebhookEd25519(
  rawBody: string,
  options: {
    timestamp?: number;
    secretSeed?: string;
    keypair?: StellarSdk.Keypair;
  } = {},
): Ed25519WebhookSignatureResult {
  const timestamp = options.timestamp ?? Date.now();
  const keypair = options.keypair ?? getEd25519SigningKeypair(options.secretSeed);
  const message = buildCanonicalEd25519Message(rawBody, timestamp);
  const signatureBytes = Buffer.from(keypair.sign(message));
  const signature = signatureBytes.toString('hex');
  const publicKey = keypair.publicKey();
  const headerValue = `t=${timestamp},s=${signature},pk=${publicKey}`;

  return {
    timestamp,
    signature,
    publicKey,
    headerValue,
  };
}

/**
 * Parses a `Stellar-Ed25519-Signature` header (`t=<ts>,s=<hexSig>[,pk=<G...>]`) or a raw
 * 128-character hex signature string.
 */
export function parseEd25519SignatureHeader(
  headerValue: string,
  fallbackTimestamp?: number,
): { timestamp: number; signature: string; publicKey?: string } | null {
  if (!headerValue || typeof headerValue !== 'string') return null;
  const trimmed = headerValue.trim();

  if (/^[0-9a-f]{128}$/i.test(trimmed)) {
    if (fallbackTimestamp === undefined || !Number.isFinite(fallbackTimestamp)) {
      return null;
    }
    return {
      timestamp: fallbackTimestamp,
      signature: trimmed.toLowerCase(),
    };
  }

  const parts = trimmed.split(',').map((part) => part.trim());
  let timestamp: number | undefined;
  let signature: string | undefined;
  let publicKey: string | undefined;

  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key === 't') {
      const parsed = Number(val);
      if (!Number.isFinite(parsed)) return null;
      timestamp = parsed;
    } else if (key === 's') {
      if (!/^[0-9a-f]{128}$/i.test(val)) return null;
      signature = val.toLowerCase();
    } else if (key === 'pk') {
      publicKey = val;
    }
  }

  const resolvedTimestamp = timestamp ?? fallbackTimestamp;
  if (resolvedTimestamp === undefined || !signature) {
    return null;
  }

  return {
    timestamp: resolvedTimestamp,
    signature,
    publicKey,
  };
}

/**
 * Verifies an Ed25519 webhook signature using a Stellar `G...` public key (`Keypair.fromPublicKey(pk).verify(...)`).
 */
export function verifyWebhookEd25519(
  rawBody: string,
  headerOrSignature: string,
  expectedPublicKey?: string,
  options: {
    timestamp?: number;
    toleranceMs?: number;
    nowMs?: number;
  } = {},
): boolean {
  const parsed = parseEd25519SignatureHeader(headerOrSignature, options.timestamp);
  if (!parsed) return false;

  const publicKey = expectedPublicKey ?? parsed.publicKey;
  if (!publicKey || !StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    return false;
  }

  if (options.toleranceMs !== undefined && options.toleranceMs > 0) {
    const now = options.nowMs ?? Date.now();
    if (Math.abs(now - parsed.timestamp) > options.toleranceMs) {
      return false;
    }
  }

  try {
    const verifier = StellarSdk.Keypair.fromPublicKey(publicKey);
    const message = buildCanonicalEd25519Message(rawBody, parsed.timestamp);
    const sigBuffer = Buffer.from(parsed.signature, 'hex');
    if (sigBuffer.length !== 64) return false;
    return verifier.verify(message, sigBuffer);
  } catch {
    return false;
  }
}

/**
 * Returns the public discovery document served at `GET /.well-known/stellar-alerts.json`.
 */
export function getWellKnownStellarAlertsMetadata(
  secretSeedOverride?: string,
): WellKnownStellarAlertsConfig {
  const keypair = getEd25519SigningKeypair(secretSeedOverride);
  return {
    webhookSigningPublicKey: keypair.publicKey(),
    algorithm: 'Ed25519',
    header: ED25519_SIGNATURE_HEADER,
    canonicalFormat: '{timestamp}.{rawBody}',
  };
}
