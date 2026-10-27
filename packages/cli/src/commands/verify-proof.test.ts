import { describe, it, expect, vi } from 'vitest';
import {
  buildMerkleTree,
  generateMerkleProof,
  hashMerkleLeaf,
  verifyMerkleInclusionOffline,
} from '../lib/merkle-verifier.js';
import {
  parseProofArgument,
  formatMerkleVerificationText,
} from './verify-proof.js';

function flipHexLastNibble(hex: string): string {
  const last = hex[hex.length - 1].toLowerCase();
  const replacement = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + replacement;
}

describe('verify-proof CLI & merkle-verifier (#733)', () => {
  it('verifies a 4-hop (16-leaf) Merkle inclusion proof completely offline', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const leaves = Array.from({ length: 16 }, (_, idx) =>
      Buffer.from(`stellar-tx-record-${idx}`, 'utf8'),
    );
    const tree = buildMerkleTree(leaves);

    // Prove leaf #9
    const targetIndex = 9;
    const path = generateMerkleProof(tree, targetIndex);
    const expectedLeafHash = hashMerkleLeaf(leaves[targetIndex]);
    expect(path).toHaveLength(4);

    const result = verifyMerkleInclusionOffline({
      data: `stellar-tx-record-${targetIndex}`,
      path,
      expectedRoot: tree.root,
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.valid).toBe(true);
    expect(result.hops).toBe(4);
    expect(result.leafHash).toBe(expectedLeafHash);
    expect(result.computedRoot).toBe(tree.root);
    expect(result.steps).toHaveLength(4);
    expect(result.steps[3].resultingHash).toBe(tree.root);

    const formatted = formatMerkleVerificationText(result);
    expect(formatted).toContain('VERIFIED');
    expect(formatted).toContain(tree.root);
    fetchSpy.mockRestore();
  });

  it('verifies an 8-hop (256-leaf) Merkle inclusion proof for every boundary leaf', () => {
    const leaves = Array.from({ length: 256 }, (_, idx) =>
      Buffer.from(JSON.stringify({ ledger: 500_000 + idx, txCount: idx % 17 }), 'utf8'),
    );
    const tree = buildMerkleTree(leaves);

    for (const targetIndex of [0, 1, 127, 128, 254, 255]) {
      const path = generateMerkleProof(tree, targetIndex);
      expect(path).toHaveLength(8);

      const result = verifyMerkleInclusionOffline({
        data: leaves[targetIndex],
        path,
        expectedRoot: tree.root,
      });

      expect(result.valid).toBe(true);
      expect(result.hops).toBe(8);
      expect(result.computedRoot).toBe(tree.root);
    }
  });

  it('rejects a single bit-flip in leaf data, sibling hash, direction, or root commitment', () => {
    const leaves = Array.from({ length: 16 }, (_, idx) =>
      Buffer.from(`audit-entry-${idx}`, 'utf8'),
    );
    const tree = buildMerkleTree(leaves);
    const path = generateMerkleProof(tree, 5);
    const leafHash = hashMerkleLeaf(leaves[5]);

    // 1. Tampered leaf payload
    const tamperedData = verifyMerkleInclusionOffline({
      data: 'audit-entry-5-tampered',
      path,
      expectedRoot: tree.root,
    });
    expect(tamperedData.valid).toBe(false);
    expect(tamperedData.error).toContain('Merkle root mismatch');

    // 2. Single nibble flip in a middle sibling hash (hop #2)
    const tamperedPath = path.map((step, i) =>
      i === 1 ? { ...step, siblingHash: flipHexLastNibble(step.siblingHash) } : step,
    );
    const tamperedSibling = verifyMerkleInclusionOffline({
      leafHash,
      path: tamperedPath,
      expectedRoot: tree.root,
    });
    expect(tamperedSibling.valid).toBe(false);
    expect(tamperedSibling.computedRoot).not.toBe(tree.root);

    // 3. Flipped direction at hop #1
    const flippedDirectionPath = path.map((step, i) =>
      i === 0
        ? { ...step, direction: step.direction === 'left' ? ('right' as const) : ('left' as const) }
        : step,
    );
    const tamperedDirection = verifyMerkleInclusionOffline({
      leafHash,
      path: flippedDirectionPath,
      expectedRoot: tree.root,
    });
    expect(tamperedDirection.valid).toBe(false);

    // 4. Single nibble flip in expectedRoot
    const tamperedRoot = verifyMerkleInclusionOffline({
      leafHash,
      path,
      expectedRoot: flipHexLastNibble(tree.root),
    });
    expect(tamperedRoot.valid).toBe(false);
  });

  it('parses both array and object JSON proof formats and rejects malformed inputs cleanly', () => {
    const step = {
      siblingHash: 'a'.repeat(64),
      direction: 'left' as const,
    };

    const fromArray = parseProofArgument(JSON.stringify([step]));
    expect(fromArray.path).toEqual([step]);

    const fromObject = parseProofArgument(
      JSON.stringify({
        leafHash: 'b'.repeat(64),
        root: 'c'.repeat(64),
        path: [step],
      }),
    );
    expect(fromObject.leafHash).toBe('b'.repeat(64));
    expect(fromObject.expectedRoot).toBe('c'.repeat(64));
    expect(fromObject.path).toEqual([step]);

    const missingData = verifyMerkleInclusionOffline({
      path: [step],
      expectedRoot: 'c'.repeat(64),
    });
    expect(missingData.valid).toBe(false);
    expect(missingData.error).toContain('Either raw leaf data or a 32-byte hex leafHash');
  });
});
