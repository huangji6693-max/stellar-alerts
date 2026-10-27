import {
  CounterpartyRiskAssessment,
  CounterpartyRiskService,
  CounterpartyRiskSeverity,
  CounterpartyTransferEdge,
  FlaggedAddressEntry,
  counterpartyRiskService,
} from '../../analytics/counterparty-risk.service';

export interface RiskScoreRuleConfig {
  /** Minimum composite risk score (0-100) that triggers an alert (default 40). */
  minRiskScore?: number;
  /** Minimum severity level to match (default WARNING). */
  minSeverity?: CounterpartyRiskSeverity;
  /** Maximum hop distance to consider (1 or 2, default 2). */
  maxHops?: 1 | 2;
  /** Optional rule-scoped flagged address overrides. */
  flaggedAddresses?: FlaggedAddressEntry[];
}

export interface AlertRuleLike {
  id: string;
  userId: string;
  walletId?: string | null;
  name?: string | null;
  isActive: boolean;
  conditions?: unknown;
}

export interface RiskScoreMatchResult {
  matched: boolean;
  ruleId?: string;
  deliveryPayload?: {
    event: 'security.counterparty_risk_alert';
    ruleId: string;
    userId: string;
    targetAddress: string;
    riskScore: number;
    severity: CounterpartyRiskSeverity;
    hasDirectMaliciousLink: boolean;
    hasIndirectMaliciousLink: boolean;
    message: string;
    metadata: {
      directFlaggedCount: number;
      indirectFlaggedCount: number;
      directExposedVolume: number;
      indirectExposedVolume: number;
      totalInboundVolume: number;
      exposures: CounterpartyRiskAssessment['exposures'];
      clusters: CounterpartyRiskAssessment['clusters'];
    };
  };
}

/**
 * Evaluates a target wallet's 1-hop and 2-hop counterparty transaction graph
 * against an alert rule and emits a security warning payload when direct or
 * indirect exposure to a known malicious/sanctioned entity crosses the
 * configured threshold (#738).
 */
export class RiskScoreRuleEvaluator {
  private readonly service: CounterpartyRiskService;

  constructor(service?: CounterpartyRiskService) {
    this.service = service ?? counterpartyRiskService;
  }

  public evaluate(
    targetAddress: string,
    edges: CounterpartyTransferEdge[],
    rule: AlertRuleLike,
  ): RiskScoreMatchResult {
    if (!rule.isActive) {
      return { matched: false };
    }

    const config = this.extractRuleConfig(rule);
    if (!config) {
      return { matched: false };
    }

    const activeService =
      config.flaggedAddresses && config.flaggedAddresses.length > 0
        ? new CounterpartyRiskService({
            flaggedAddresses: config.flaggedAddresses,
            warningThreshold: this.service.warningThreshold,
            criticalThreshold: this.service.criticalThreshold,
            secondHopDecay: this.service.secondHopDecay,
          })
        : this.service;

    const rawAssessment = activeService.evaluateGraph(targetAddress, edges);

    const maxHops = config.maxHops ?? 2;
    const filteredExposures =
      maxHops === 1
        ? rawAssessment.exposures.filter((e) => e.hopDistance === 1)
        : rawAssessment.exposures;

    if (filteredExposures.length === 0) {
      return { matched: false };
    }

    const effectiveRiskScore =
      maxHops === 1
        ? filteredExposures[0]!.pathRiskScore
        : rawAssessment.riskScore;
    const effectiveSeverity: CounterpartyRiskSeverity =
      rawAssessment.hasDirectMaliciousLink ||
      effectiveRiskScore >= activeService.criticalThreshold
        ? 'CRITICAL'
        : activeService.classify(effectiveRiskScore);

    const minRiskScore = config.minRiskScore ?? activeService.warningThreshold;
    if (effectiveRiskScore < minRiskScore) {
      return { matched: false };
    }

    const minSeverity = config.minSeverity ?? 'WARNING';
    if (!this.meetsSeverityThreshold(effectiveSeverity, minSeverity)) {
      return { matched: false };
    }

    return {
      matched: true,
      ruleId: rule.id,
      deliveryPayload: {
        event: 'security.counterparty_risk_alert',
        ruleId: rule.id,
        userId: rule.userId,
        targetAddress: rawAssessment.targetAddress,
        riskScore: effectiveRiskScore,
        severity: effectiveSeverity,
        hasDirectMaliciousLink: rawAssessment.hasDirectMaliciousLink,
        hasIndirectMaliciousLink:
          maxHops === 2 && rawAssessment.hasIndirectMaliciousLink,
        message: rawAssessment.summary,
        metadata: {
          directFlaggedCount: rawAssessment.directFlaggedCount,
          indirectFlaggedCount:
            maxHops === 2 ? rawAssessment.indirectFlaggedCount : 0,
          directExposedVolume: rawAssessment.directExposedVolume,
          indirectExposedVolume:
            maxHops === 2 ? rawAssessment.indirectExposedVolume : 0,
          totalInboundVolume: rawAssessment.totalInboundVolume,
          exposures: filteredExposures,
          clusters: rawAssessment.clusters,
        },
      },
    };
  }

  public meetsSeverityThreshold(
    severity: CounterpartyRiskSeverity,
    minSeverity: CounterpartyRiskSeverity,
  ): boolean {
    const order: CounterpartyRiskSeverity[] = ['OK', 'WARNING', 'CRITICAL'];
    return order.indexOf(severity) >= order.indexOf(minSeverity);
  }

  private extractRuleConfig(rule: AlertRuleLike): RiskScoreRuleConfig | null {
    if (!rule.conditions || typeof rule.conditions !== 'object') return null;

    const cond = rule.conditions as Record<string, any>;
    if (cond.riskScore && typeof cond.riskScore === 'object') {
      return cond.riskScore as RiskScoreRuleConfig;
    }
    if (cond.counterpartyRisk && typeof cond.counterpartyRisk === 'object') {
      return cond.counterpartyRisk as RiskScoreRuleConfig;
    }
    if (
      cond.minRiskScore !== undefined ||
      cond.flaggedAddresses !== undefined ||
      cond.maxHops !== undefined
    ) {
      return cond as RiskScoreRuleConfig;
    }
    return null;
  }
}

export const riskScoreRuleEvaluator = new RiskScoreRuleEvaluator();
