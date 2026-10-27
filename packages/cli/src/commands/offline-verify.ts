import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import {
  validateTransactionOffline,
  signEnvelopeOffline,
  type OfflineValidationReport,
} from '../lib/offline-validator.js';

export interface OfflineVerifyCommandOptions {
  xdr?: string;
  file?: string;
  network?: string;
  signer?: string[];
  signWith?: string;
  json?: boolean;
}

function readEnvelopeInput(xdrArg: string | undefined, opts: OfflineVerifyCommandOptions): string {
  if (opts.file) {
    return fs.readFileSync(opts.file, 'utf8').trim();
  }
  if (opts.xdr) {
    return opts.xdr.trim();
  }
  if (xdrArg) {
    return xdrArg.trim();
  }
  throw new Error('Provide a Base64 TransactionEnvelope XDR via argument, --xdr <base64>, or --file <path>');
}

export function formatOfflineReportText(report: OfflineValidationReport): string {
  const lines: string[] = [];
  const statusBadge = report.valid ? chalk.green('VALID') : chalk.red('INVALID');
  lines.push(`${chalk.bold('Offline Transaction Verification:')} ${statusBadge}`);
  lines.push(`  Envelope Type : ${report.envelopeType}`);
  lines.push(`  Network       : ${report.networkPassphrase}`);
  lines.push(`  Tx Hash       : ${report.txHash}`);
  lines.push(`  Source Account: ${report.sourceAccount}`);
  lines.push(`  Sequence      : ${report.sequence}`);
  lines.push(`  Fee (stroops) : ${report.fee}`);
  lines.push(`  Memo          : ${report.memo.type}${report.memo.value ? ` (${report.memo.value})` : ''}`);
  lines.push(
    `  TimeBounds    : ${
      report.timeBounds ? `${report.timeBounds.minTime} .. ${report.timeBounds.maxTime}` : 'none'
    }`,
  );
  lines.push(`  Operations    : ${report.operations.length}`);

  for (const op of report.operations) {
    const summaryParts = [`#${op.index} ${op.type}`];
    if (op.destination) summaryParts.push(`-> ${op.destination}`);
    if (op.amount) summaryParts.push(`amount=${op.amount}`);
    if (op.asset) summaryParts.push(`asset=${op.asset}`);
    lines.push(`    - ${summaryParts.join(' ')}`);
  }

  lines.push(`  Signatures    : ${report.signatureCount}`);
  for (const v of report.signerVerifications) {
    const icon = v.verified ? chalk.green('✓') : chalk.red('✗');
    lines.push(`    ${icon} ${v.publicKey} (hint=${v.hintHex || 'n/a'})`);
  }

  for (const warning of report.warnings) {
    lines.push(chalk.yellow(`  Warning: ${warning}`));
  }
  for (const error of report.errors) {
    lines.push(chalk.red(`  Error: ${error}`));
  }

  return lines.join('\n');
}

export function registerOfflineVerifyCommand(program: Command): void {
  program
    .command('offline-verify [xdr]')
    .description(
      'Decode, inspect, and cryptographically verify (or sign) a Stellar TransactionEnvelope XDR completely offline',
    )
    .option('--xdr <base64>', 'Base64-encoded TransactionEnvelope XDR')
    .option('-f, --file <path>', 'Read Base64-encoded TransactionEnvelope XDR from file')
    .option('-n, --network <network>', 'Network (testnet | public | futurenet | passphrase)', 'testnet')
    .option(
      '-s, --signer <publicKey...>',
      'Expected Stellar Ed25519 public key(s) (G...) to verify against envelope signatures',
    )
    .option('--sign-with <secretKey>', 'Optional Stellar secret key (S...) to sign the envelope offline before verifying')
    .option('--json', 'Output machine-readable JSON report', false)
    .action((xdrArg: string | undefined, opts: OfflineVerifyCommandOptions) => {
      try {
        let envelopeXdr = readEnvelopeInput(xdrArg, opts);
        let signedResult: { signedXdr: string; txHash: string; signerPublicKey: string } | undefined;

        if (opts.signWith) {
          signedResult = signEnvelopeOffline(envelopeXdr, opts.signWith, opts.network);
          envelopeXdr = signedResult.signedXdr;
        }

        const expectedSigners = [...(opts.signer ?? [])];
        if (signedResult && !expectedSigners.includes(signedResult.signerPublicKey)) {
          expectedSigners.push(signedResult.signerPublicKey);
        }

        const report = validateTransactionOffline(envelopeXdr, {
          network: opts.network,
          expectedSigners,
        });

        if (opts.json) {
          console.log(
            JSON.stringify(
              signedResult ? { ...report, signedXdr: signedResult.signedXdr } : report,
              null,
              2,
            ),
          );
        } else {
          console.log(formatOfflineReportText(report));
          if (signedResult) {
            console.log(chalk.cyan(`\nSigned Envelope XDR:\n${signedResult.signedXdr}`));
          }
        }

        if (!report.valid) {
          process.exit(1);
        }
      } catch (err) {
        if (opts.json) {
          console.error(JSON.stringify({ valid: false, error: (err as Error).message }));
        } else {
          console.error(chalk.red(`❌ ${(err as Error).message}`));
        }
        process.exit(1);
      }
    });
}
