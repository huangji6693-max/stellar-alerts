import {
  hashMerkleLeaf,
  hashMerkleNode,
  computeMerkleRoot,
  verifyMerkleProof,
  buildMerkleTree,
  generateMerkleProof,
  type MerkleProof,
  type MerkleProofStep,
  type MerkleProofDirection,
  type MerkleTree,
} from '@stellar-alerts/shared';

export {
  hashMerkleLeaf,
  hashMerkleNode,
  computeMerkleRoot,
  verifyMerkleProof,
  buildMerkleTree,
  generateMerkleProof,
  type MerkleProof,
  type MerkleProofStep,
  type MerkleProofDirection,
  type MerkleTree,
};

export interface MerkleHopTrace {
  hop: number;
  direction: MerkleProofDirection;
  siblingHash: string;
  resultingHash: string;
}

export interface OfflineMerkleVerificationInput {
  /** Raw UTF-8 or Buffer payload for the leaf (hashed with domain-separated 0x00 prefix) */
  data?: string | Buffer;
  /** Optional pre-computed 32-byte hex leaf hash (if `data` is not supplied) */
  leafHash?: string;
  /** Ordered sibling steps from leaf to root */
  path: MerkleProofStep[];
  /** Expected 32-byte hex Merkle root commitment */
  expectedRoot: string;
}

export interface OfflineMerkleVerificationResult {
  valid: boolean;
  leafHash: string;
  computedRoot: string | null;
  expectedRoot: string;
  hops: number;
  steps: MerkleHopTrace[];
  error?: string;
}

const HEX_64 = /^[0-9a-f]{64}$/i;

function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX_64.test(value);
}

/**
 * Verifies a Merkle inclusion proof completely offline and produces a hop-by-hop
 * audit trace from the leaf hash up to the root commitment.
 */
export function verifyMerkleInclusionOffline(
  input: OfflineMerkleVerificationInput,
): OfflineMerkleVerificationResult {
  const expectedRoot = (input.expectedRoot ?? '').trim().toLowerCase();

  let leafHash: string;
  if (input.data !== undefined) {
    const buf = Buffer.isBuffer(input.data) ? input.data : Buffer.from(String(input.data), 'utf8');
    leafHash = hashMerkleLeaf(buf);
  } else if (input.leafHash !== undefined) {
    leafHash = input.leafHash.trim().toLowerCase();
  } else {
    return {
      valid: false,
      leafHash: '',
      computedRoot: null,
      expectedRoot,
      hops: 0,
      steps: [],
      error: 'Either raw leaf data or a 32-byte hex leafHash must be provided',
    };
  }

  if (!isHex64(leafHash)) {
    return {
      valid: false,
      leafHash,
      computedRoot: null,
      expectedRoot,
      hops: 0,
      steps: [],
      error: `Invalid leaf hash: expected 64-character hex string, got "${leafHash}"`,
    };
  }

  if (!isHex64(expectedRoot)) {
    return {
      valid: false,
      leafHash,
      computedRoot: null,
      expectedRoot,
      hops: 0,
      steps: [],
      error: `Invalid expected root hash: expected 64-character hex string, got "${input.expectedRoot}"`,
    };
  }

  if (!Array.isArray(input.path)) {
    return {
      valid: false,
      leafHash,
      computedRoot: null,
      expectedRoot,
      hops: 0,
      steps: [],
      error: 'Proof path must be an array of { siblingHash, direction } steps',
    };
  }

  const steps: MerkleHopTrace[] = [];
  let current = Buffer.from(leafHash, 'hex');

  for (let i = 0; i < input.path.length; i++) {
    const step = input.path[i];
    if (!step || !isHex64(step.siblingHash)) {
      return {
        valid: false,
        leafHash,
        computedRoot: null,
        expectedRoot,
        hops: steps.length,
        steps,
        error: `Invalid sibling hash at hop ${i + 1}: "${step?.siblingHash}"`,
      };
    }
    if (step.direction !== 'left' && step.direction !== 'right') {
      return {
        valid: false,
        leafHash,
        computedRoot: null,
        expectedRoot,
        hops: steps.length,
        steps,
        error: `Invalid direction at hop ${i + 1}: expected "left" or "right", got "${String(step.direction)}"`,
      };
    }

    const sibling = Buffer.from(step.siblingHash, 'hex');
    const parentHex =
      step.direction === 'left'
        ? hashMerkleNode(sibling, current)
        : hashMerkleNode(current, sibling);

    steps.push({
      hop: i + 1,
      direction: step.direction,
      siblingHash: step.siblingHash.toLowerCase(),
      resultingHash: parentHex,
    });

    current = Buffer.from(parentHex, 'hex');
  }

  const computedRoot = current.toString('hex').toLowerCase();
  const valid =
    computedRoot === expectedRoot &&
    verifyMerkleProof({ leafHash, path: input.path }, expectedRoot);

  return {
    valid,
    leafHash,
    computedRoot,
    expectedRoot,
    hops: steps.length,
    steps,
    ...(valid
      ? {}
      : {
          error: `Merkle root mismatch: computed ${computedRoot}, expected ${expectedRoot}`,
        }),
  };
}
