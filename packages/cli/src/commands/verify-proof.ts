import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import {
  verifyMerkleInclusionOffline,
  type MerkleProofStep,
  type OfflineMerkleVerificationResult,
} from '../lib/merkle-verifier.js';

export interface VerifyProofCommandOptions {
  data?: string;
  dataHex?: string;
  leafHash?: string;
  proof: string;
  root?: string;
  json?: boolean;
}

interface ParsedProofInput {
  leafHash?: string;
  expectedRoot?: string;
  path: MerkleProofStep[];
}

export function parseProofArgument(rawProofArg: string): ParsedProofInput {
  const trimmed = rawProofArg.trim();
  let jsonText = trimmed;
  if (!trimmed.startsWith('[') && !trimmed.startsWith('{') && fs.existsSync(trimmed)) {
    jsonText = fs.readFileSync(trimmed, 'utf8').trim();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new Error(`Failed to parse Merkle proof JSON: ${(err as Error).message}`);
  }

  if (Array.isArray(parsed)) {
    return { path: parsed as MerkleProofStep[] };
  }

  if (parsed && typeof parsed === 'object') {
    const obj = parsed as Record<string, unknown>;
    const path = (obj.path ?? obj.proof) as MerkleProofStep[] | undefined;
    if (!Array.isArray(path)) {
      throw new Error('Proof JSON object must contain a "path" or "proof" array of steps');
    }
    return {
      leafHash: typeof obj.leafHash === 'string' ? obj.leafHash : undefined,
      expectedRoot: typeof obj.root === 'string' ? obj.root : typeof obj.expectedRoot === 'string' ? obj.expectedRoot : undefined,
      path,
    };
  }

  throw new Error('Proof JSON must be an array of steps or an object containing { path, leafHash?, root? }');
}

export function formatMerkleVerificationText(result: OfflineMerkleVerificationResult): string {
  const lines: string[] = [];
  const badge = result.valid ? chalk.green('VERIFIED') : chalk.red('FAILED');
  lines.push(`${chalk.bold('Offline Merkle Proof Verification:')} ${badge}`);
  lines.push(`  Leaf Hash    : ${result.leafHash || 'n/a'}`);
  lines.push(`  Hops         : ${result.hops}`);

  for (const step of result.steps) {
    lines.push(
      `    Hop #${step.hop} [${step.direction.toUpperCase()} sibling ${step.siblingHash.slice(0, 16)}...] -> ${step.resultingHash}`,
    );
  }

  lines.push(`  Computed Root: ${result.computedRoot ?? 'n/a'}`);
  lines.push(`  Expected Root: ${result.expectedRoot || 'n/a'}`);

  if (result.error) {
    lines.push(chalk.red(`  Error        : ${result.error}`));
  }

  return lines.join('\n');
}

export function registerVerifyProofCommand(program: Command): void {
  program
    .command('verify-proof')
    .description(
      'Cryptographically verify a Merkle inclusion proof against a root hash completely offline',
    )
    .option('-d, --data <string>', 'Raw UTF-8 leaf payload to hash and verify')
    .option('--data-hex <hex>', 'Hex-encoded raw leaf payload bytes to hash and verify')
    .option('-l, --leaf-hash <hex>', 'Pre-hashed 32-byte hex leaf hash')
    .requiredOption(
      '-p, --proof <jsonOrFile>',
      'JSON array/object of Merkle proof steps ([{ "siblingHash": "...", "direction": "left"|"right" }]) or path to JSON file',
    )
    .option('-r, --root <hex>', 'Expected 32-byte hex Merkle root hash')
    .option('--json', 'Output machine-readable JSON result', false)
    .action((opts: VerifyProofCommandOptions) => {
      try {
        const parsedProof = parseProofArgument(opts.proof);
        const expectedRoot = opts.root ?? parsedProof.expectedRoot ?? '';
        const data =
          opts.dataHex !== undefined
            ? Buffer.from(opts.dataHex.trim(), 'hex')
            : opts.data;

        const result = verifyMerkleInclusionOffline({
          data,
          leafHash: opts.leafHash ?? parsedProof.leafHash,
          path: parsedProof.path,
          expectedRoot,
        });

        if (opts.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(formatMerkleVerificationText(result));
        }

        if (!result.valid) {
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
