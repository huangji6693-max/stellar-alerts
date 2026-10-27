import {
  NftAlertNotification,
  NftEventType,
  NftSentinel,
  RawSorobanNftEvent,
  nftSentinel,
  parseSorobanNftEvent,
} from '../../../workers/watcher/nft-sentinel';

export interface NftRuleConfig {
  /** Monitored NFT contract ID(s). Matches any NFT contract if omitted. */
  contractIds?: string[];
  /** Single monitored NFT contract ID shorthand. */
  contractId?: string;
  /** Monitored wallet address (matches `from` or `to`). */
  walletAddress?: string;
  /** Allowed NFT event types (default all: transfer, mint, burn, metadata_update). */
  eventTypes?: NftEventType[];
  /** Optional specific token IDs to filter on. */
  tokenIds?: Array<string | number>;
}

export interface AlertRuleLike {
  id: string;
  userId: string;
  walletId?: string | null;
  name?: string | null;
  isActive: boolean;
  conditions?: unknown;
}

export interface NftRuleMatchResult {
  matched: boolean;
  ruleId?: string;
  deliveryPayload?: {
    event: 'soroban.nft_event';
    ruleId: string;
    userId: string;
    eventType: NftEventType;
    contractId: string;
    tokenId: string;
    from: string | null;
    to: string | null;
    metadataUri: string | null;
    headline: string;
    message: string;
    explorerLinks: NftAlertNotification['explorerLinks'];
    metadata: {
      tokenIdNumeric: string | null;
      ledgerSeq: number;
      txHash?: string;
      timestamp: string;
    };
  };
}

/**
 * Evaluates raw Soroban NFT (`transfer`, `mint`, `burn`, `metadata_update`)
 * events against user alert rules and formats delivery payloads with token
 * identifiers and explorer links (#737).
 */
export class NftRuleEvaluator {
  private readonly sentinel: NftSentinel;

  constructor(sentinel?: NftSentinel) {
    this.sentinel = sentinel ?? nftSentinel;
  }

  public evaluate(
    rawEvent: RawSorobanNftEvent,
    rule: AlertRuleLike,
  ): NftRuleMatchResult {
    if (!rule.isActive) {
      return { matched: false };
    }

    const config = this.extractRuleConfig(rule);
    if (!config) {
      return { matched: false };
    }

    const parsed = parseSorobanNftEvent(rawEvent);
    if (!parsed) {
      return { matched: false };
    }

    // Filter by contractId / contractIds
    const allowedContracts = [
      ...(config.contractIds ?? []),
      ...(config.contractId ? [config.contractId] : []),
    ]
      .map((c) => c.trim().toLowerCase())
      .filter(Boolean);

    if (
      allowedContracts.length > 0 &&
      !allowedContracts.includes(parsed.contractId.toLowerCase())
    ) {
      return { matched: false };
    }

    // Filter by eventTypes
    if (
      config.eventTypes &&
      config.eventTypes.length > 0 &&
      !config.eventTypes.includes(parsed.eventType)
    ) {
      return { matched: false };
    }

    // Filter by walletAddress (matches sender or receiver)
    if (config.walletAddress) {
      const targetWallet = config.walletAddress.trim().toLowerCase();
      const fromMatch = parsed.from?.toLowerCase() === targetWallet;
      const toMatch = parsed.to?.toLowerCase() === targetWallet;
      if (!fromMatch && !toMatch) {
        return { matched: false };
      }
    }

    // Filter by specific tokenIds
    if (config.tokenIds && config.tokenIds.length > 0) {
      const allowedTokens = config.tokenIds.map((id) => String(id).trim());
      if (!allowedTokens.includes(parsed.tokenId)) {
        return { matched: false };
      }
    }

    const notification = this.sentinel.formatNotification(parsed);

    return {
      matched: true,
      ruleId: rule.id,
      deliveryPayload: {
        event: 'soroban.nft_event',
        ruleId: rule.id,
        userId: rule.userId,
        eventType: parsed.eventType,
        contractId: parsed.contractId,
        tokenId: parsed.tokenId,
        from: parsed.from,
        to: parsed.to,
        metadataUri: parsed.metadataUri ?? null,
        headline: notification.headline,
        message: notification.message,
        explorerLinks: notification.explorerLinks,
        metadata: {
          tokenIdNumeric:
            parsed.tokenIdNumeric !== null
              ? parsed.tokenIdNumeric.toString()
              : null,
          ledgerSeq: parsed.ledgerSeq,
          txHash: parsed.txHash,
          timestamp: parsed.timestamp,
        },
      },
    };
  }

  private extractRuleConfig(rule: AlertRuleLike): NftRuleConfig | null {
    if (!rule.conditions || typeof rule.conditions !== 'object') return null;

    const cond = rule.conditions as Record<string, any>;
    if (cond.nft && typeof cond.nft === 'object') {
      return cond.nft as NftRuleConfig;
    }
    if (
      cond.eventTypes !== undefined ||
      cond.tokenIds !== undefined ||
      cond.walletAddress !== undefined ||
      cond.contractIds !== undefined ||
      cond.contractId !== undefined
    ) {
      return cond as NftRuleConfig;
    }
    return null;
  }
}

export const nftRuleEvaluator = new NftRuleEvaluator();
