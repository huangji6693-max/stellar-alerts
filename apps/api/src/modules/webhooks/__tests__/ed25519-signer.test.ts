import { describe, it, expect } from 'vitest';
import * as StellarSdk from 'stellar-sdk';
import {
  ED25519_SIGNATURE_HEADER,
  signWebhookEd25519,
  verifyWebhookEd25519,
  parseEd25519SignatureHeader,
  getWellKnownStellarAlertsMetadata,
  buildCanonicalEd25519Message,
} from '../ed25519-signer';

describe('Native Ed25519 Asymmetric Webhook Signer (#739)', () => {
  it('signs a webhook payload with a Stellar Ed25519 keypair and verifies with the G... public key', () => {
    const keypair = StellarSdk.Keypair.random();
    const payload = JSON.stringify({
      event: 'payment.received',
      amount: '150.0000000',
      asset: 'XLM',
    });
    const timestamp = 1_730_000_000_000;

    const signed = signWebhookEd25519(payload, {
      timestamp,
      keypair,
    });

    expect(signed.publicKey).toBe(keypair.publicKey());
    expect(StellarSdk.StrKey.isValidEd25519PublicKey(signed.publicKey)).toBe(true);
    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(signed.headerValue).toBe(`t=${timestamp},s=${signed.signature},pk=${keypair.publicKey()}`);

    // Verify using the formatted header value and explicit G... public key
    expect(verifyWebhookEd25519(payload, signed.headerValue, keypair.publicKey())).toBe(true);

    // Also verify using raw 128-hex signature + timestamp option
    expect(
      verifyWebhookEd25519(payload, signed.signature, keypair.publicKey(), { timestamp }),
    ).toBe(true);

    // Also verify directly with StellarSdk.Keypair.fromPublicKey().verify()
    const verifier = StellarSdk.Keypair.fromPublicKey(keypair.publicKey());
    const canonicalMsg = buildCanonicalEd25519Message(payload, timestamp);
    expect(verifier.verify(canonicalMsg, Buffer.from(signed.signature, 'hex'))).toBe(true);
  });

  it('rejects tampered payload, tampered timestamp, tampered signature bytes, or wrong G... public key', () => {
    const keypair = StellarSdk.Keypair.random();
    const otherKeypair = StellarSdk.Keypair.random();
    const payload = '{"event":"webhook.ping","data":{"ok":true}}';
    const timestamp = 1_730_000_000_000;

    const signed = signWebhookEd25519(payload, { timestamp, keypair });

    // 1. Tampered payload body
    expect(
      verifyWebhookEd25519('{"event":"webhook.ping","data":{"ok":false}}', signed.headerValue, keypair.publicKey()),
    ).toBe(false);

    // 2. Wrong expected G... public key
    expect(
      verifyWebhookEd25519(payload, signed.headerValue, otherKeypair.publicKey()),
    ).toBe(false);

    // 3. Tampered timestamp in header
    const tamperedTsHeader = `t=${timestamp + 1},s=${signed.signature},pk=${keypair.publicKey()}`;
    expect(verifyWebhookEd25519(payload, tamperedTsHeader, keypair.publicKey())).toBe(false);

    // 4. Tampered signature byte
    const lastChar = signed.signature[signed.signature.length - 1];
    const flippedSig = signed.signature.slice(0, -1) + (lastChar === '0' ? '1' : '0');
    const tamperedSigHeader = `t=${timestamp},s=${flippedSig},pk=${keypair.publicKey()}`;
    expect(verifyWebhookEd25519(payload, tamperedSigHeader, keypair.publicKey())).toBe(false);

    // 5. Expired timestamp outside tolerance window
    expect(
      verifyWebhookEd25519(payload, signed.headerValue, keypair.publicKey(), {
        toleranceMs: 30_000,
        nowMs: timestamp + 60_000,
      }),
    ).toBe(false);
  });

  it('exposes valid Stellar Ed25519 public key discovery metadata for /.well-known/stellar-alerts.json', () => {
    const keypair = StellarSdk.Keypair.random();
    const metadata = getWellKnownStellarAlertsMetadata(keypair.secret());

    expect(metadata).toEqual({
      webhookSigningPublicKey: keypair.publicKey(),
      algorithm: 'Ed25519',
      header: ED25519_SIGNATURE_HEADER,
      canonicalFormat: '{timestamp}.{rawBody}',
    });
    expect(StellarSdk.StrKey.isValidEd25519PublicKey(metadata.webhookSigningPublicKey)).toBe(true);
  });

  it('handles malformed header inputs and invalid secret seeds gracefully', () => {
    expect(parseEd25519SignatureHeader('')).toBeNull();
    expect(parseEd25519SignatureHeader('t=notanumber,s=' + 'a'.repeat(128))).toBeNull();
    expect(parseEd25519SignatureHeader('t=12345,s=short')).toBeNull();
    expect(() => getWellKnownStellarAlertsMetadata('invalid-seed')).toThrow(
      'Invalid WEBHOOK_ED25519_SECRET_KEY',
    );
  });
});
