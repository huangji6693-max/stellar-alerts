import { describe, it, expect, vi } from 'vitest';
import * as StellarSdk from 'stellar-sdk';
import {
  validateTransactionOffline,
  signEnvelopeOffline,
  resolveNetworkPassphrase,
} from '../lib/offline-validator.js';
import { formatOfflineReportText } from './offline-verify.js';

function buildSamplePaymentEnvelope(signer?: StellarSdk.Keypair): {
  xdr: string;
  source: StellarSdk.Keypair;
  destination: StellarSdk.Keypair;
} {
  const source = signer ?? StellarSdk.Keypair.random();
  const destination = StellarSdk.Keypair.random();
  const account = new StellarSdk.Account(source.publicKey(), '100000');

  const tx = new StellarSdk.TransactionBuilder(account, {
    fee: '100',
    networkPassphrase: StellarSdk.Networks.TESTNET,
  })
    .addOperation(
      StellarSdk.Operation.payment({
        destination: destination.publicKey(),
        asset: StellarSdk.Asset.native(),
        amount: '25.5000000',
      }),
    )
    .addMemo(StellarSdk.Memo.text('airgapped-audit'))
    .setTimeout(3600)
    .build();

  if (signer) {
    tx.sign(signer);
  }

  return {
    xdr: tx.toEnvelope().toXDR('base64'),
    source,
    destination,
  };
}

describe('offline-verify CLI & offline-validator (#750)', () => {
  it('decodes and validates a signed payment envelope completely offline without network calls', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const signer = StellarSdk.Keypair.random();
    const { xdr, destination } = buildSamplePaymentEnvelope(signer);

    const report = validateTransactionOffline(xdr, {
      network: 'testnet',
      expectedSigners: [signer.publicKey()],
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(report.valid).toBe(true);
    expect(report.envelopeType).toBe('Transaction');
    expect(report.sourceAccount).toBe(signer.publicKey());
    expect(report.sequence).toBe('100001');
    expect(report.fee).toBe('100');
    expect(report.memo).toEqual({ type: 'text', value: 'airgapped-audit' });
    expect(report.operations).toHaveLength(1);
    expect(report.operations[0]).toMatchObject({
      index: 0,
      type: 'payment',
      destination: destination.publicKey(),
      amount: '25.5000000',
      asset: 'XLM (native)',
    });
    expect(report.signerVerifications).toEqual([
      expect.objectContaining({
        publicKey: signer.publicKey(),
        matchedHint: true,
        verified: true,
      }),
    ]);

    const text = formatOfflineReportText(report);
    expect(text).toContain('VALID');
    expect(text).toContain(signer.publicKey());
    fetchSpy.mockRestore();
  });

  it('detects missing or invalid Ed25519 signatures for an expected signer', () => {
    const actualSigner = StellarSdk.Keypair.random();
    const wrongSigner = StellarSdk.Keypair.random();
    const { xdr } = buildSamplePaymentEnvelope(actualSigner);

    const report = validateTransactionOffline(xdr, {
      network: 'testnet',
      expectedSigners: [wrongSigner.publicKey()],
    });

    expect(report.valid).toBe(false);
    expect(report.signerVerifications[0].verified).toBe(false);
    expect(report.errors[0]).toContain(`Missing or invalid signature for expected signer ${wrongSigner.publicKey()}`);
  });

  it('rejects a signature signed under a different network passphrase (domain separation)', () => {
    const signer = StellarSdk.Keypair.random();
    const { xdr } = buildSamplePaymentEnvelope(signer);

    // Validating a TESTNET-signed envelope against PUBLIC network passphrase must fail verification
    const report = validateTransactionOffline(xdr, {
      network: 'public',
      expectedSigners: [signer.publicKey()],
    });

    expect(report.valid).toBe(false);
    expect(report.signerVerifications[0].matchedHint).toBe(true);
    expect(report.signerVerifications[0].verified).toBe(false);
  });

  it('supports offline signing of an unsigned XDR envelope and subsequent verification', () => {
    const signer = StellarSdk.Keypair.random();
    const { xdr: unsignedXdr } = buildSamplePaymentEnvelope(undefined);

    const unsignedReport = validateTransactionOffline(unsignedXdr, { network: 'testnet' });
    expect(unsignedReport.signatureCount).toBe(0);
    expect(unsignedReport.warnings).toContain('Envelope contains 0 decorated signatures.');

    const { signedXdr, signerPublicKey } = signEnvelopeOffline(unsignedXdr, signer.secret(), 'testnet');
    expect(signerPublicKey).toBe(signer.publicKey());

    const signedReport = validateTransactionOffline(signedXdr, {
      network: 'testnet',
      expectedSigners: [signer.publicKey()],
    });
    expect(signedReport.valid).toBe(true);
    expect(signedReport.signatureCount).toBe(1);
    expect(signedReport.signerVerifications[0].verified).toBe(true);
  });

  it('throws descriptive errors on malformed XDR or invalid secret seeds', () => {
    expect(() => validateTransactionOffline('')).toThrow('Transaction envelope XDR cannot be empty');
    expect(() => validateTransactionOffline('not-valid-xdr-base64!!!')).toThrow('Invalid TransactionEnvelope XDR');
    expect(() => signEnvelopeOffline('AAAA', 'not-a-secret-seed')).toThrow('Invalid Stellar Ed25519 secret key');
    expect(resolveNetworkPassphrase('mainnet')).toBe(StellarSdk.Networks.PUBLIC);
    expect(resolveNetworkPassphrase('futurenet')).toBe(StellarSdk.Networks.FUTURENET);
  });
});
