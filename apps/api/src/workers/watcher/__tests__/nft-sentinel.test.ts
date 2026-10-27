import { describe, expect, it } from 'vitest';
import {
  NftSentinel,
  NftXdrBuilder,
  parseSorobanNftEvent,
} from '../nft-sentinel';
import {
  NftRuleEvaluator,
  type AlertRuleLike,
} from '../../../modules/alerts/rules/nft.rule';

const NFT_CONTRACT = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
const WALLET_ALICE = 'GALICE11111111111111111111111111111111111111111111111111';
const WALLET_BOB = 'GBOB2222222222222222222222222222222222222222222222222222';

describe('NftSentinel & SEP-0041 Event Decoder (#737)', () => {
  it('decodes SEP-0041 transfer event with base64 XDR ScVal topics and u128 token ID', () => {
    const rawEvent = {
      contractId: NFT_CONTRACT,
      topic: [
        NftXdrBuilder.symbol('transfer'),
        NftXdrBuilder.string(WALLET_ALICE),
        NftXdrBuilder.string(WALLET_BOB),
      ],
      value: NftXdrBuilder.u128(4201n),
      txHash: 'abc123def456',
      ledger: 91020,
    };

    const parsed = parseSorobanNftEvent(rawEvent);
    expect(parsed).not.toBeNull();
    expect(parsed?.eventType).toBe('transfer');
    expect(parsed?.contractId).toBe(NFT_CONTRACT);
    expect(parsed?.from).toBe(WALLET_ALICE);
    expect(parsed?.to).toBe(WALLET_BOB);
    expect(parsed?.tokenId).toBe('4201');
    expect(parsed?.tokenIdNumeric).toBe(4201n);
    expect(parsed?.explorerContractUrl).toBe(
      `https://stellar.expert/explorer/public/contract/${NFT_CONTRACT}`,
    );
    expect(parsed?.explorerTxUrl).toBe(
      'https://stellar.expert/explorer/public/tx/abc123def456',
    );
  });

  it('decodes SEP-0041 mint and burn events with u32 and i128 token IDs', () => {
    const mintEvent = parseSorobanNftEvent({
      contractId: NFT_CONTRACT,
      topic: [NftXdrBuilder.symbol('mint'), NftXdrBuilder.string(WALLET_ALICE)],
      value: NftXdrBuilder.u32(77),
      txHash: 'tx-mint-77',
      ledger: 91021,
    });
    expect(mintEvent?.eventType).toBe('mint');
    expect(mintEvent?.to).toBe(WALLET_ALICE);
    expect(mintEvent?.tokenId).toBe('77');

    const burnEvent = parseSorobanNftEvent({
      contractId: NFT_CONTRACT,
      topic: [NftXdrBuilder.symbol('burn'), NftXdrBuilder.string(WALLET_ALICE)],
      value: NftXdrBuilder.i128(77n),
      txHash: 'tx-burn-77',
      ledger: 91022,
    });
    expect(burnEvent?.eventType).toBe('burn');
    expect(burnEvent?.from).toBe(WALLET_ALICE);
    expect(burnEvent?.tokenId).toBe('77');
  });

  it('resolves metadata URI via NftSentinel and formats explorer links', async () => {
    const sentinel = new NftSentinel({
      metadataResolver: async (_contractId, tokenId) =>
        `ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/${tokenId}.json`,
    });

    const notifications = await sentinel.processEventBatch([
      {
        contractId: NFT_CONTRACT,
        topic: [NftXdrBuilder.symbol('mint'), NftXdrBuilder.string(WALLET_BOB)],
        value: NftXdrBuilder.u64(999n),
        txHash: 'tx-mint-999',
        ledger: 92000,
      },
    ]);

    expect(notifications).toHaveLength(1);
    const notif = notifications[0]!;
    expect(notif.event.metadataUri).toContain('/999.json');
    expect(notif.headline).toContain('NFT #999 Minted');
    expect(notif.message).toContain(NFT_CONTRACT);
    expect(notif.explorerLinks.token).toContain('token=999');
  });
});

describe('NftRuleEvaluator (#737)', () => {
  const evaluator = new NftRuleEvaluator();

  function makeRule(overrides: Partial<AlertRuleLike> = {}): AlertRuleLike {
    return {
      id: 'rule-nft-1',
      userId: 'user-collector-1',
      isActive: true,
      conditions: {
        nft: {
          contractIds: [NFT_CONTRACT],
          walletAddress: WALLET_BOB,
          eventTypes: ['transfer', 'mint'],
        },
      },
      ...overrides,
    };
  }

  it('dispatches alert when monitored wallet receives an NFT via transfer', () => {
    const rawEvent = {
      contractId: NFT_CONTRACT,
      topic: [
        NftXdrBuilder.symbol('transfer'),
        NftXdrBuilder.string(WALLET_ALICE),
        NftXdrBuilder.string(WALLET_BOB),
      ],
      value: NftXdrBuilder.u128(105n),
      txHash: 'tx-nft-105',
      ledger: 93001,
    };

    const result = evaluator.evaluate(rawEvent, makeRule());
    expect(result.matched).toBe(true);
    expect(result.deliveryPayload?.event).toBe('soroban.nft_event');
    expect(result.deliveryPayload?.tokenId).toBe('105');
    expect(result.deliveryPayload?.from).toBe(WALLET_ALICE);
    expect(result.deliveryPayload?.to).toBe(WALLET_BOB);
    expect(result.deliveryPayload?.explorerLinks.contract).toContain(NFT_CONTRACT);
  });

  it('dispatches alert when monitored wallet transfers an NFT out', () => {
    const rawEvent = {
      contractId: NFT_CONTRACT,
      topic: [
        NftXdrBuilder.symbol('transfer'),
        NftXdrBuilder.string(WALLET_BOB),
        NftXdrBuilder.string(WALLET_ALICE),
      ],
      value: NftXdrBuilder.u128(105n),
      txHash: 'tx-nft-out',
      ledger: 93002,
    };

    const result = evaluator.evaluate(rawEvent, makeRule());
    expect(result.matched).toBe(true);
    expect(result.deliveryPayload?.from).toBe(WALLET_BOB);
  });

  it('does not trigger when event involves unrelated wallets or non-NFT topics', () => {
    const unrelatedTransfer = {
      contractId: NFT_CONTRACT,
      topic: [
        NftXdrBuilder.symbol('transfer'),
        NftXdrBuilder.string(WALLET_ALICE),
        NftXdrBuilder.string('GOTHER33333333333333333333333333333333333333333333333333'),
      ],
      value: NftXdrBuilder.u128(105n),
    };
    expect(evaluator.evaluate(unrelatedTransfer, makeRule()).matched).toBe(false);

    const swapEvent = {
      contractId: NFT_CONTRACT,
      topic: [NftXdrBuilder.symbol('swap')],
      value: NftXdrBuilder.u128(105n),
    };
    expect(evaluator.evaluate(swapEvent, makeRule()).matched).toBe(false);
  });
});
