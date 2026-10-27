import { describe, expect, it } from 'vitest';
import {
  CounterpartyRiskService,
  CounterpartyTransferEdge,
  FlaggedAddressEntry,
} from '../counterparty-risk.service';
import {
  RiskScoreRuleEvaluator,
  type AlertRuleLike,
} from '../../alerts/rules/risk-score.rule';

const FLAGGED_SANCTIONED = 'GSANCTIONED111111111111111111111111111111111111111111111';
const FLAGGED_EXPLOIT = 'GEXPLOIT222222222222222222222222222222222222222222222222';
const FLAGGED_MIXER = 'GMIXER33333333333333333333333333333333333333333333333333';
const INTERMEDIARY_A = 'GINTERMEDIARYA111111111111111111111111111111111111111111';
const INTERMEDIARY_B = 'GINTERMEDIARYB222222222222222222222222222222222222222222';
const CLEAN_SENDER = 'GCLEANSENDER11111111111111111111111111111111111111111111';
const TARGET_WALLET = 'GTARGETWALLET1111111111111111111111111111111111111111111';

const FLAGGED_LIST: FlaggedAddressEntry[] = [
  {
    address: FLAGGED_SANCTIONED,
    category: 'SANCTIONED',
    baseRiskScore: 100,
    label: 'OFAC Sanctioned Entity',
  },
  {
    address: FLAGGED_EXPLOIT,
    category: 'EXPLOIT',
    baseRiskScore: 100,
    label: 'Bridge Exploit Drainer',
  },
  {
    address: FLAGGED_MIXER,
    category: 'MIXER',
    baseRiskScore: 80,
    label: 'High-Risk Obfuscation Mixer',
  },
];

describe('CounterpartyRiskService (#738)', () => {
  it('returns 0 risk score when all 1-hop and 2-hop counterparties are clean', () => {
    const service = new CounterpartyRiskService({ flaggedAddresses: FLAGGED_LIST });
    const edges: CounterpartyTransferEdge[] = [
      { from: CLEAN_SENDER, to: INTERMEDIARY_A, amount: 500 },
      { from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 500 },
    ];

    const result = service.evaluateGraph(TARGET_WALLET, edges);
    expect(result.riskScore).toBe(0);
    expect(result.severity).toBe('OK');
    expect(result.exposures).toHaveLength(0);
    expect(result.hasDirectMaliciousLink).toBe(false);
    expect(result.hasIndirectMaliciousLink).toBe(false);
  });

  it('scores direct 1-hop exposure to a sanctioned wallet as CRITICAL (deterministic benchmark)', () => {
    const service = new CounterpartyRiskService({ flaggedAddresses: FLAGGED_LIST });
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_SANCTIONED, to: TARGET_WALLET, amount: 600 },
      { from: CLEAN_SENDER, to: TARGET_WALLET, amount: 400 },
    ];

    const result = service.evaluateGraph(TARGET_WALLET, edges);
    // volumeShare = 600 / 1000 = 0.6 -> pathRiskScore = 100 * (0.75 + 0.25 * 0.6) = 90
    expect(result.riskScore).toBe(90);
    expect(result.severity).toBe('CRITICAL');
    expect(result.directFlaggedCount).toBe(1);
    expect(result.directExposedVolume).toBe(600);
    expect(result.hasDirectMaliciousLink).toBe(true);
    expect(result.exposures[0]?.path).toEqual([FLAGGED_SANCTIONED, TARGET_WALLET]);
  });

  it('traverses 2-hop transaction graph and detects indirect exploit exposure via intermediary', () => {
    const service = new CounterpartyRiskService({ flaggedAddresses: FLAGGED_LIST });
    const edges: CounterpartyTransferEdge[] = [
      // Hop 1 into intermediary: exploit wallet sends 800 XLM to INTERMEDIARY_A
      { from: FLAGGED_EXPLOIT, to: INTERMEDIARY_A, amount: 800 },
      // Hop 2 into target: INTERMEDIARY_A forwards 500 XLM to TARGET_WALLET
      { from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 500 },
      // Clean sender also sends 500 XLM to TARGET_WALLET (total inbound = 1000)
      { from: CLEAN_SENDER, to: TARGET_WALLET, amount: 500 },
    ];

    const result = service.evaluateGraph(TARGET_WALLET, edges);
    // exposedVolume = min(800, 500) = 500; volumeShare = 500 / 1000 = 0.5
    // pathRiskScore = 100 * 0.6 * (0.65 + 0.35 * 0.5) = 60 * 0.825 = 49.5
    // cluster has 2 non-target members (FLAGGED_EXPLOIT, INTERMEDIARY_A) -> +3 clusterBonus = 52.5
    expect(result.hasDirectMaliciousLink).toBe(false);
    expect(result.hasIndirectMaliciousLink).toBe(true);
    expect(result.indirectFlaggedCount).toBe(1);
    expect(result.indirectExposedVolume).toBe(500);
    expect(result.exposures[0]?.hopDistance).toBe(2);
    expect(result.exposures[0]?.path).toEqual([
      FLAGGED_EXPLOIT,
      INTERMEDIARY_A,
      TARGET_WALLET,
    ]);
    expect(result.exposures[0]?.pathRiskScore).toBe(49.5);
    expect(result.riskScore).toBe(52.5);
    expect(result.severity).toBe('WARNING');
  });

  it('clusters multiple intermediaries funded by the same flagged source and elevates cluster risk', () => {
    const service = new CounterpartyRiskService({ flaggedAddresses: FLAGGED_LIST });
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_EXPLOIT, to: INTERMEDIARY_A, amount: 400 },
      { from: FLAGGED_EXPLOIT, to: INTERMEDIARY_B, amount: 400 },
      { from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 400 },
      { from: INTERMEDIARY_B, to: TARGET_WALLET, amount: 400 },
    ];

    const result = service.evaluateGraph(TARGET_WALLET, edges);
    expect(result.clusters).toHaveLength(1);
    expect(result.clusters[0]?.anchorAddress).toBe(FLAGGED_EXPLOIT);
    expect(result.clusters[0]?.members).toEqual(
      [FLAGGED_EXPLOIT, INTERMEDIARY_A, INTERMEDIARY_B].sort(),
    );
    expect(result.clusters[0]?.totalVolume).toBe(800);
    expect(result.riskScore).toBeGreaterThan(60);
  });

  it('queries 2-hop history via CounterpartyGraphRepository in assessWalletFromHistory', async () => {
    const mockRepo = {
      getInboundTransfers: async (recipients: string[]) => {
        if (recipients.includes(TARGET_WALLET)) {
          return [{ from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 1000 }];
        }
        if (recipients.includes(INTERMEDIARY_A)) {
          return [{ from: FLAGGED_SANCTIONED, to: INTERMEDIARY_A, amount: 1000 }];
        }
        return [];
      },
    };

    const service = new CounterpartyRiskService({
      flaggedAddresses: FLAGGED_LIST,
      repository: mockRepo,
    });

    const assessment = await service.assessWalletFromHistory(TARGET_WALLET);
    expect(assessment.hasIndirectMaliciousLink).toBe(true);
    expect(assessment.exposures[0]?.flaggedAddress).toBe(FLAGGED_SANCTIONED);
    expect(assessment.riskScore).toBe(63);
  });
});

describe('RiskScoreRuleEvaluator (#738)', () => {
  const service = new CounterpartyRiskService({ flaggedAddresses: FLAGGED_LIST });
  const evaluator = new RiskScoreRuleEvaluator(service);

  function makeRule(overrides: Partial<AlertRuleLike> = {}): AlertRuleLike {
    return {
      id: 'rule-risk-1',
      userId: 'user-compliance-1',
      isActive: true,
      conditions: {
        riskScore: {
          minRiskScore: 40,
          minSeverity: 'WARNING',
          maxHops: 2,
        },
      },
      ...overrides,
    };
  }

  it('dispatches critical security warning on direct link to known malicious entity', () => {
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_EXPLOIT, to: TARGET_WALLET, amount: 250 },
      { from: CLEAN_SENDER, to: TARGET_WALLET, amount: 750 },
    ];

    const res = evaluator.evaluate(TARGET_WALLET, edges, makeRule());
    expect(res.matched).toBe(true);
    expect(res.deliveryPayload?.event).toBe('security.counterparty_risk_alert');
    expect(res.deliveryPayload?.severity).toBe('CRITICAL');
    expect(res.deliveryPayload?.hasDirectMaliciousLink).toBe(true);
  });

  it('dispatches security warning on 2-hop indirect link to known exploit wallet', () => {
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_EXPLOIT, to: INTERMEDIARY_A, amount: 500 },
      { from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 500 },
    ];

    const res = evaluator.evaluate(TARGET_WALLET, edges, makeRule());
    expect(res.matched).toBe(true);
    expect(res.deliveryPayload?.hasIndirectMaliciousLink).toBe(true);
    expect(res.deliveryPayload?.metadata.exposures[0]?.hopDistance).toBe(2);
  });

  it('respects maxHops: 1 when rule only monitors direct counterparties', () => {
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_EXPLOIT, to: INTERMEDIARY_A, amount: 500 },
      { from: INTERMEDIARY_A, to: TARGET_WALLET, amount: 500 },
    ];

    const res = evaluator.evaluate(
      TARGET_WALLET,
      edges,
      makeRule({
        conditions: { riskScore: { minRiskScore: 40, maxHops: 1 } },
      }),
    );
    expect(res.matched).toBe(false);
  });

  it('returns matched: false when rule is inactive', () => {
    const edges: CounterpartyTransferEdge[] = [
      { from: FLAGGED_SANCTIONED, to: TARGET_WALLET, amount: 1000 },
    ];
    expect(
      evaluator.evaluate(TARGET_WALLET, edges, makeRule({ isActive: false })).matched,
    ).toBe(false);
  });
});
