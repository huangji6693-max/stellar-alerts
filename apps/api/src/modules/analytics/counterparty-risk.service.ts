/**
 * Multi-Hop Counterparty Risk Scoring & Graph Neighbor Clustering (#738).
 *
 * Traverses a 2-hop payment counterparty graph to quantify a recipient wallet's
 * direct (1-hop) and indirect (2-hop) exposure to sanctioned, exploit, or
 * high-risk Stellar accounts, and clusters graph neighbors by shared exposure.
 */

export type CounterpartyRiskSeverity = 'OK' | 'WARNING' | 'CRITICAL';

export type FlaggedCategory =
  | 'SANCTIONED'
  | 'EXPLOIT'
  | 'PHISHING'
  | 'MIXER'
  | 'HIGH_RISK';

export interface FlaggedAddressEntry {
  address: string;
  category: FlaggedCategory;
  /** Base risk weight in [0, 100]. Defaults to 100 for SANCTIONED/EXPLOIT, 85 otherwise. */
  baseRiskScore?: number;
  label?: string;
}

export interface CounterpartyTransferEdge {
  txHash?: string;
  from: string;
  to: string;
  /** Transfer amount in asset units (or common numeraire). */
  amount: number;
  assetCode?: string;
  timestamp?: string | Date;
}

export interface ExposurePath {
  flaggedAddress: string;
  category: FlaggedCategory;
  label?: string;
  /** 1 for direct counterparty (flagged -> target), 2 for 1-intermediary hop (flagged -> intermediary -> target). */
  hopDistance: 1 | 2;
  /** Ordered path from flagged source to target wallet: [flagged, target] or [flagged, intermediary, target]. */
  path: string[];
  /** Volume flowing along the final leg into the target (or min volume along the path for 2-hop). */
  exposedVolume: number;
  /** Fraction of total incoming volume represented by this exposure path, in [0, 1]. */
  volumeShare: number;
  /** Individual risk contribution (0-100) before aggregation cap. */
  pathRiskScore: number;
}

export interface NeighborCluster {
  clusterId: string;
  /** Shared flagged root address or intermediary hub anchoring the cluster. */
  anchorAddress: string;
  members: string[];
  flaggedConnections: string[];
  totalVolume: number;
  clusterRiskScore: number;
}

export interface CounterpartyRiskAssessment {
  targetAddress: string;
  /** Composite risk score bounded to [0, 100]. */
  riskScore: number;
  severity: CounterpartyRiskSeverity;
  directFlaggedCount: number;
  indirectFlaggedCount: number;
  totalInboundVolume: number;
  directExposedVolume: number;
  indirectExposedVolume: number;
  exposures: ExposurePath[];
  clusters: NeighborCluster[];
  hasDirectMaliciousLink: boolean;
  hasIndirectMaliciousLink: boolean;
  summary: string;
}

export interface CounterpartyGraphRepository {
  /**
   * Fetches inbound transfer edges for the given recipient addresses.
   */
  getInboundTransfers(
    recipientAddresses: string[],
    lookbackLimit?: number,
  ): Promise<CounterpartyTransferEdge[]>;
}

export class PrismaCounterpartyGraphRepository implements CounterpartyGraphRepository {
  private readonly prismaClient?: any;

  constructor(prismaClient?: any) {
    this.prismaClient = prismaClient;
  }

  public async getInboundTransfers(
    recipientAddresses: string[],
    lookbackLimit = 500,
  ): Promise<CounterpartyTransferEdge[]> {
    if (recipientAddresses.length === 0) return [];

    let client = this.prismaClient;
    if (!client) {
      const mod = await import('../../lib/prisma');
      client = mod.prisma;
    }

    const rows = await client?.payment?.findMany?.({
      where: {
        toAddress: { in: recipientAddresses },
      },
      orderBy: { createdAt: 'desc' },
      take: lookbackLimit,
    });

    if (!Array.isArray(rows)) return [];

    return rows.map((row: any) => ({
      txHash: row.txHash ?? row.id,
      from: String(row.fromAddress ?? row.from ?? ''),
      to: String(row.toAddress ?? row.to ?? ''),
      amount: Number(row.amount ?? 0),
      assetCode: row.assetCode ?? 'XLM',
      timestamp: row.createdAt,
    }));
  }
}

export interface CounterpartyRiskServiceOptions {
  flaggedAddresses?: FlaggedAddressEntry[];
  /** Risk score threshold for WARNING classification (default 40). */
  warningThreshold?: number;
  /** Risk score threshold for CRITICAL classification (default 75). */
  criticalThreshold?: number;
  /** Distance attenuation factor for 2-hop exposure (default 0.6). */
  secondHopDecay?: number;
  repository?: CounterpartyGraphRepository;
}

const DEFAULT_CATEGORY_SCORES: Record<FlaggedCategory, number> = {
  SANCTIONED: 100,
  EXPLOIT: 100,
  PHISHING: 85,
  MIXER: 80,
  HIGH_RISK: 70,
};

export class CounterpartyRiskService {
  readonly warningThreshold: number;
  readonly criticalThreshold: number;
  readonly secondHopDecay: number;
  private readonly flaggedMap: Map<string, FlaggedAddressEntry> = new Map();
  private readonly repository: CounterpartyGraphRepository;

  constructor(options: CounterpartyRiskServiceOptions = {}) {
    this.warningThreshold = options.warningThreshold ?? 40;
    this.criticalThreshold = options.criticalThreshold ?? 75;
    this.secondHopDecay = options.secondHopDecay ?? 0.6;
    this.repository = options.repository ?? new PrismaCounterpartyGraphRepository();

    for (const entry of options.flaggedAddresses ?? []) {
      this.registerFlaggedAddress(entry);
    }
  }

  public registerFlaggedAddress(entry: FlaggedAddressEntry): void {
    const normalized = entry.address.trim();
    if (!normalized) return;
    this.flaggedMap.set(normalized, {
      ...entry,
      address: normalized,
      baseRiskScore:
        entry.baseRiskScore ?? DEFAULT_CATEGORY_SCORES[entry.category] ?? 80,
    });
  }

  public isFlagged(address: string): boolean {
    return this.flaggedMap.has(address.trim());
  }

  public getFlaggedEntry(address: string): FlaggedAddressEntry | undefined {
    return this.flaggedMap.get(address.trim());
  }

  /**
   * Evaluates a target wallet's 1-hop and 2-hop counterparty exposure from a
   * dataset of transfer edges.
   */
  public evaluateGraph(
    targetAddress: string,
    edges: CounterpartyTransferEdge[],
  ): CounterpartyRiskAssessment {
    const target = targetAddress.trim();

    // 1-hop inbound transfers: u -> target
    const hop1Edges = edges.filter(
      (e) => e.to === target && e.from && e.from !== target && e.amount > 0,
    );

    const totalInboundVolume = hop1Edges.reduce((sum, e) => sum + e.amount, 0);

    // Aggregate 1-hop inbound volume per direct sender
    const hop1VolumeBySender = new Map<string, number>();
    for (const edge of hop1Edges) {
      hop1VolumeBySender.set(
        edge.from,
        (hop1VolumeBySender.get(edge.from) ?? 0) + edge.amount,
      );
    }

    const exposures: ExposurePath[] = [];
    let directExposedVolume = 0;
    let indirectExposedVolume = 0;

    // Evaluate 1-hop direct exposure
    for (const [sender, volume] of hop1VolumeBySender.entries()) {
      const flagged = this.flaggedMap.get(sender);
      if (!flagged) continue;

      directExposedVolume += volume;
      const volumeShare =
        totalInboundVolume > 0 ? Math.min(1, volume / totalInboundVolume) : 1;
      const baseScore =
        flagged.baseRiskScore ?? DEFAULT_CATEGORY_SCORES[flagged.category];
      // Direct link carries at least 75% of baseScore and scales to 100% with volume share
      const pathRiskScore = round(baseScore * (0.75 + 0.25 * volumeShare), 2);

      exposures.push({
        flaggedAddress: sender,
        category: flagged.category,
        label: flagged.label,
        hopDistance: 1,
        path: [sender, target],
        exposedVolume: round(volume, 6),
        volumeShare: round(volumeShare, 6),
        pathRiskScore,
      });
    }

    // Evaluate 2-hop indirect exposure: v -> u -> target (where u is not itself target)
    const intermediaries = Array.from(hop1VolumeBySender.keys()).filter(
      (u) => !this.flaggedMap.has(u),
    );

    const hop2EdgesByIntermediary = new Map<string, Map<string, number>>();
    for (const intermediary of intermediaries) {
      const inboundToIntermediary = edges.filter(
        (e) =>
          e.to === intermediary &&
          e.from &&
          e.from !== intermediary &&
          e.from !== target &&
          e.amount > 0,
      );
      const byOrigin = new Map<string, number>();
      for (const edge of inboundToIntermediary) {
        byOrigin.set(edge.from, (byOrigin.get(edge.from) ?? 0) + edge.amount);
      }
      hop2EdgesByIntermediary.set(intermediary, byOrigin);
    }

    for (const [intermediary, origins] of hop2EdgesByIntermediary.entries()) {
      const hop1Vol = hop1VolumeBySender.get(intermediary) ?? 0;
      for (const [origin, hop2Vol] of origins.entries()) {
        const flagged = this.flaggedMap.get(origin);
        if (!flagged) continue;

        // Effective flow through the 2-hop conduit is bounded by min(v->u, u->target)
        const exposedVolume = Math.min(hop1Vol, hop2Vol);
        indirectExposedVolume += exposedVolume;

        const volumeShare =
          totalInboundVolume > 0
            ? Math.min(1, exposedVolume / totalInboundVolume)
            : 0;
        const baseScore =
          flagged.baseRiskScore ?? DEFAULT_CATEGORY_SCORES[flagged.category];
        const pathRiskScore = round(
          baseScore * this.secondHopDecay * (0.65 + 0.35 * volumeShare),
          2,
        );

        exposures.push({
          flaggedAddress: origin,
          category: flagged.category,
          label: flagged.label,
          hopDistance: 2,
          path: [origin, intermediary, target],
          exposedVolume: round(exposedVolume, 6),
          volumeShare: round(volumeShare, 6),
          pathRiskScore,
        });
      }
    }

    // Sort exposures highest risk first for deterministic output
    exposures.sort(
      (a, b) =>
        b.pathRiskScore - a.pathRiskScore ||
        a.hopDistance - b.hopDistance ||
        a.flaggedAddress.localeCompare(b.flaggedAddress),
    );

    const clusters = this.buildNeighborClusters(target, edges, exposures);

    const riskScore = this.computeCompositeRiskScore(exposures, clusters);
    const severity = this.classify(riskScore);

    const directFlaggedCount = new Set(
      exposures.filter((e) => e.hopDistance === 1).map((e) => e.flaggedAddress),
    ).size;
    const indirectFlaggedCount = new Set(
      exposures.filter((e) => e.hopDistance === 2).map((e) => e.flaggedAddress),
    ).size;

    const hasDirectMaliciousLink = directFlaggedCount > 0;
    const hasIndirectMaliciousLink = indirectFlaggedCount > 0;

    return {
      targetAddress: target,
      riskScore,
      severity,
      directFlaggedCount,
      indirectFlaggedCount,
      totalInboundVolume: round(totalInboundVolume, 6),
      directExposedVolume: round(directExposedVolume, 6),
      indirectExposedVolume: round(indirectExposedVolume, 6),
      exposures,
      clusters,
      hasDirectMaliciousLink,
      hasIndirectMaliciousLink,
      summary: this.formatSummary(
        target,
        riskScore,
        severity,
        directFlaggedCount,
        indirectFlaggedCount,
      ),
    };
  }

  /**
   * Queries 2-hop transaction history from the configured repository (PostgreSQL
   * by default) and evaluates counterparty risk for `targetAddress`.
   */
  public async assessWalletFromHistory(
    targetAddress: string,
    lookbackLimit = 500,
  ): Promise<CounterpartyRiskAssessment> {
    const hop1Edges = await this.repository.getInboundTransfers(
      [targetAddress],
      lookbackLimit,
    );
    const intermediaries = Array.from(
      new Set(hop1Edges.map((e) => e.from).filter((a) => a && a !== targetAddress)),
    );
    const hop2Edges =
      intermediaries.length > 0
        ? await this.repository.getInboundTransfers(intermediaries, lookbackLimit)
        : [];

    return this.evaluateGraph(targetAddress, [...hop1Edges, ...hop2Edges]);
  }

  /**
   * Groups 1-hop and 2-hop neighbors into clusters anchored around shared
   * flagged sources or shared intermediaries.
   */
  public buildNeighborClusters(
    targetAddress: string,
    edges: CounterpartyTransferEdge[],
    exposures: ExposurePath[],
  ): NeighborCluster[] {
    const byFlaggedAnchor = new Map<
      string,
      { members: Set<string>; volume: number; maxPathRisk: number }
    >();

    for (const exp of exposures) {
      const entry = byFlaggedAnchor.get(exp.flaggedAddress) ?? {
        members: new Set<string>(),
        volume: 0,
        maxPathRisk: 0,
      };
      for (const node of exp.path) {
        if (node !== targetAddress) entry.members.add(node);
      }
      entry.volume += exp.exposedVolume;
      entry.maxPathRisk = Math.max(entry.maxPathRisk, exp.pathRiskScore);
      byFlaggedAnchor.set(exp.flaggedAddress, entry);
    }

    // Also include additional neighbors that transacted directly with the same flagged anchor
    for (const edge of edges) {
      const cluster = byFlaggedAnchor.get(edge.from);
      if (cluster && edge.to !== targetAddress) {
        cluster.members.add(edge.to);
      }
    }

    const clusters: NeighborCluster[] = [];
    let idx = 1;
    for (const [anchor, data] of Array.from(byFlaggedAnchor.entries()).sort((a, b) =>
      a[0].localeCompare(b[0]),
    )) {
      const members = Array.from(data.members).sort();
      const densityBonus = Math.min(15, Math.max(0, (members.length - 1) * 5));
      const clusterRiskScore = round(
        Math.min(100, data.maxPathRisk + densityBonus),
        2,
      );
      clusters.push({
        clusterId: `cluster-${idx++}`,
        anchorAddress: anchor,
        members,
        flaggedConnections: [anchor],
        totalVolume: round(data.volume, 6),
        clusterRiskScore,
      });
    }

    return clusters;
  }

  private computeCompositeRiskScore(
    exposures: ExposurePath[],
    clusters: NeighborCluster[],
  ): number {
    if (exposures.length === 0) return 0;

    const maxPathScore = exposures[0]!.pathRiskScore;
    // Diminishing-returns boost from multiple distinct exposure paths
    const additionalBoost = exposures
      .slice(1)
      .reduce((sum, exp, i) => sum + exp.pathRiskScore * Math.pow(0.25, i + 1), 0);

    const clusterBonus =
      clusters.length > 0
        ? Math.min(
            10,
            clusters.reduce((max, c) => Math.max(max, c.members.length - 1), 0) * 3,
          )
        : 0;

    return round(Math.min(100, maxPathScore + additionalBoost + clusterBonus), 2);
  }

  public classify(riskScore: number): CounterpartyRiskSeverity {
    if (riskScore >= this.criticalThreshold) return 'CRITICAL';
    if (riskScore >= this.warningThreshold) return 'WARNING';
    return 'OK';
  }

  private formatSummary(
    target: string,
    riskScore: number,
    severity: CounterpartyRiskSeverity,
    directCount: number,
    indirectCount: number,
  ): string {
    if (directCount === 0 && indirectCount === 0) {
      return `No direct or 2-hop flagged counterparty exposure detected for ${target} (score 0/100).`;
    }
    return (
      `Counterparty risk [${severity}] for ${target}: score ${riskScore}/100 ` +
      `(${directCount} direct 1-hop, ${indirectCount} indirect 2-hop flagged link(s)).`
    );
  }
}

function round(value: number, dp: number): number {
  if (!Number.isFinite(value)) return 0;
  const factor = 10 ** dp;
  return Math.round(value * factor) / factor;
}

export const counterpartyRiskService = new CounterpartyRiskService();
