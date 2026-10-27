/**
 * #725: Cross-Contract Invocation Call Graph & Sub-Invocation Tracer.
 *
 * Extracts and reconstructs hierarchical parent-child call trees of nested
 * Soroban cross-contract invocations from diagnostic event streams (`fn_call` /
 * `fn_return` pairs, base64 XDR `ScVal` topics/values, or nested sub-invocation
 * descriptors) and attributes CPU instructions, read/write bytes, and fee
 * costs to each node and sub-contract.
 */

export type CallInvocationStatus = 'success' | 'reverted' | 'error';

export interface CallNodeResources {
  /** Self CPU instructions consumed directly by this contract hop. */
  cpuInstructions: number;
  /** Self ledger read bytes attributed to this hop. */
  readBytes: number;
  /** Self ledger write bytes attributed to this hop. */
  writeBytes: number;
  /** Estimated fee in stroops attributed to this hop. */
  feeStroops: number;
}

export interface CallGraphNode {
  nodeId: string;
  /** 0 for root contract invocation, 1+ for nested sub-invocations. */
  depth: number;
  callerContractId: string | null;
  contractId: string;
  functionName: string;
  args: unknown[];
  returnValue?: unknown;
  status: CallInvocationStatus;
  errorMessage?: string;
  /** Self resource consumption of this node alone. */
  selfResources: CallNodeResources;
  /** Inclusive resource consumption of this node plus all descendant sub-calls. */
  totalResources: CallNodeResources;
  children: CallGraphNode[];
}

export interface ContractResourceBreakdown {
  contractId: string;
  invocationCount: number;
  selfCpuInstructions: number;
  totalCpuInstructions: number;
  selfReadBytes: number;
  selfWriteBytes: number;
  selfFeeStroops: number;
  cpuSharePct: number;
}

export interface CallGraphEdge {
  fromContractId: string;
  toContractId: string;
  functionName: string;
  depth: number;
  status: CallInvocationStatus;
}

export interface CallGraphTraceResult {
  txHash?: string;
  ledgerSeq?: number;
  roots: CallGraphNode[];
  edges: CallGraphEdge[];
  maxDepth: number;
  totalInvocations: number;
  involvedContracts: string[];
  hasFailedSubInvocation: boolean;
  totalResources: CallNodeResources;
  contractAttribution: ContractResourceBreakdown[];
}

/**
 * Input representation of a Soroban diagnostic event (`fn_call` or `fn_return`
 * or `contract_error`) or a nested sub-invocation frame.
 */
export interface DiagnosticInvocationEvent {
  /** `'fn_call' | 'fn_return' | 'error'` or inferred from `topic[0]`. */
  type?: 'fn_call' | 'fn_return' | 'error' | 'diagnostic';
  contractId?: string;
  callerContractId?: string | null;
  functionName?: string;
  topic?: unknown[];
  value?: unknown;
  args?: unknown[];
  returnValue?: unknown;
  inSuccessfulContractCall?: boolean;
  status?: CallInvocationStatus;
  errorMessage?: string;
  cpuInstructions?: number;
  readBytes?: number;
  writeBytes?: number;
  feeStroops?: number;
  subInvocations?: DiagnosticInvocationEvent[];
}

export interface CallGraphEnvelopeInput {
  txHash?: string;
  ledgerSeq?: number;
  /** Diagnostic event list (`fn_call` / `fn_return` stack events) or hierarchical frames. */
  diagnosticEvents?: DiagnosticInvocationEvent[];
  /** Optional root invocation trees (`Auth` / `HostFunction` sub-invocations). */
  invocations?: DiagnosticInvocationEvent[];
}

/**
 * Helper to encode/decode base64 XDR `ScVal` primitives used in Soroban
 * `fn_call` / `fn_return` diagnostic events without requiring native bindings.
 */
export const CallGraphXdr = {
  symbol(sym: string): string {
    return encodeTextScVal(14, sym);
  },
  string(str: string): string {
    return encodeTextScVal(13, str);
  },
  u32(val: number): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(3, 0);
    buf.writeUInt32BE(val >>> 0, 4);
    return buf.toString('base64');
  },
  i32(val: number): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(4, 0);
    buf.writeInt32BE(val | 0, 4);
    return buf.toString('base64');
  },
  u64(val: bigint | number): string {
    const buf = Buffer.alloc(12);
    buf.writeUInt32BE(5, 0);
    buf.writeBigUInt64BE(BigInt(val), 4);
    return buf.toString('base64');
  },
  vec(encodedItems: string[]): string {
    const itemBuffers = encodedItems.map((b64) => Buffer.from(b64, 'base64'));
    const header = Buffer.alloc(12);
    header.writeUInt32BE(15, 0); // SCV_VEC
    header.writeUInt32BE(1, 4); // present = 1
    header.writeUInt32BE(itemBuffers.length, 8);
    return Buffer.concat([header, ...itemBuffers]).toString('base64');
  },
};

function encodeTextScVal(disc: number, str: string): string {
  const bytes = Buffer.from(str, 'utf8');
  const padded = Math.ceil(bytes.length / 4) * 4;
  const buf = Buffer.alloc(8 + padded);
  buf.writeUInt32BE(disc, 0);
  buf.writeUInt32BE(bytes.length, 4);
  bytes.copy(buf, 8);
  return buf.toString('base64');
}

export function decodeDiagnosticScVal(input: unknown): any {
  if (input === null || input === undefined) return null;
  if (typeof input === 'number' || typeof input === 'boolean') return input;
  if (typeof input === 'bigint') return input.toString();

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return '';
    if (/^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length >= 8 && trimmed.length % 4 === 0) {
      const parsed = tryParseXdrScVal(trimmed);
      if (parsed !== undefined) return parsed;
    }
    return trimmed;
  }

  if (Array.isArray(input)) {
    return input.map((item) => decodeDiagnosticScVal(item));
  }

  if (typeof input === 'object') {
    const obj = input as Record<string, any>;
    if ('symbol' in obj && typeof obj.symbol === 'string') return obj.symbol;
    if ('string' in obj && typeof obj.string === 'string') return obj.string;
    if ('address' in obj && typeof obj.address === 'string') return obj.address;
    if ('u32' in obj) return Number(obj.u32);
    if ('i32' in obj) return Number(obj.i32);
    if ('u64' in obj) return String(obj.u64);
    if ('i64' in obj) return String(obj.i64);
    if ('u128' in obj) return String(obj.u128);
    if ('i128' in obj) return String(obj.i128);
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = decodeDiagnosticScVal(v);
    }
    return out;
  }

  return input;
}

function tryParseXdrScVal(b64: string): any {
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    return undefined;
  }
  if (buf.length < 4 || buf.length % 4 !== 0) return undefined;
  const res = readXdrScVal(buf, 0);
  if (!res || res.nextOffset !== buf.length) return undefined;
  return res.value;
}

function readXdrScVal(
  buf: Buffer,
  offset: number,
): { value: any; nextOffset: number } | undefined {
  if (offset + 4 > buf.length) return undefined;
  const disc = buf.readUInt32BE(offset);
  let pos = offset + 4;

  switch (disc) {
    case 0:
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readUInt32BE(pos) !== 0, nextOffset: pos + 4 };
    case 1:
      return { value: null, nextOffset: pos };
    case 3:
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readUInt32BE(pos), nextOffset: pos + 4 };
    case 4:
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readInt32BE(pos), nextOffset: pos + 4 };
    case 5:
    case 7:
    case 8:
      if (pos + 8 > buf.length) return undefined;
      return { value: buf.readBigUInt64BE(pos).toString(), nextOffset: pos + 8 };
    case 6:
      if (pos + 8 > buf.length) return undefined;
      return { value: buf.readBigInt64BE(pos).toString(), nextOffset: pos + 8 };
    case 13:
    case 14: {
      if (pos + 4 > buf.length) return undefined;
      const len = buf.readUInt32BE(pos);
      pos += 4;
      const padded = Math.ceil(len / 4) * 4;
      if (pos + padded > buf.length) return undefined;
      for (let i = len; i < padded; i++) {
        if (buf[pos + i] !== 0) return undefined;
      }
      return {
        value: buf.subarray(pos, pos + len).toString('utf8'),
        nextOffset: pos + padded,
      };
    }
    case 15: {
      if (pos + 4 > buf.length) return undefined;
      const present = buf.readUInt32BE(pos);
      pos += 4;
      if (present === 0) return { value: [], nextOffset: pos };
      if (pos + 4 > buf.length) return undefined;
      const count = buf.readUInt32BE(pos);
      pos += 4;
      const arr: any[] = [];
      for (let i = 0; i < count; i++) {
        const elem = readXdrScVal(buf, pos);
        if (!elem) return undefined;
        arr.push(elem.value);
        pos = elem.nextOffset;
      }
      return { value: arr, nextOffset: pos };
    }
    default:
      return undefined;
  }
}

export class CallGraphTracer {
  private readonly stroopsPerTenThousandCpu: number;
  private readonly stroopsPerKilobyteIo: number;

  constructor(options?: {
    stroopsPerTenThousandCpu?: number;
    stroopsPerKilobyteIo?: number;
  }) {
    this.stroopsPerTenThousandCpu = options?.stroopsPerTenThousandCpu ?? 25;
    this.stroopsPerKilobyteIo = options?.stroopsPerKilobyteIo ?? 10;
  }

  /**
   * Reconstructs the hierarchical call graph and resource attribution from a
   * Soroban transaction envelope's diagnostic events or nested invocation frames.
   */
  public trace(envelope: CallGraphEnvelopeInput): CallGraphTraceResult {
    let nodeCounter = 0;
    const nextNodeId = () => `call-${++nodeCounter}`;

    let roots: CallGraphNode[] = [];

    if (Array.isArray(envelope.invocations) && envelope.invocations.length > 0) {
      roots = envelope.invocations.map((inv) =>
        this.buildFromNestedFrame(inv, 0, null, nextNodeId),
      );
    } else if (
      Array.isArray(envelope.diagnosticEvents) &&
      envelope.diagnosticEvents.length > 0
    ) {
      roots = this.buildFromDiagnosticStream(envelope.diagnosticEvents, nextNodeId);
    }

    // Roll up inclusive resources bottom-up
    for (const root of roots) {
      this.computeInclusiveResources(root);
    }

    const edges: CallGraphEdge[] = [];
    const contractMap = new Map<
      string,
      {
        invocationCount: number;
        selfCpu: number;
        totalCpu: number;
        selfRead: number;
        selfWrite: number;
        selfFee: number;
      }
    >();

    let maxDepth = 0;
    let totalInvocations = 0;
    let hasFailedSubInvocation = false;

    const visit = (node: CallGraphNode) => {
      totalInvocations++;
      if (node.depth > maxDepth) maxDepth = node.depth;
      if (node.status !== 'success') hasFailedSubInvocation = true;

      if (node.callerContractId) {
        edges.push({
          fromContractId: node.callerContractId,
          toContractId: node.contractId,
          functionName: node.functionName,
          depth: node.depth,
          status: node.status,
        });
      }

      const existing = contractMap.get(node.contractId) ?? {
        invocationCount: 0,
        selfCpu: 0,
        totalCpu: 0,
        selfRead: 0,
        selfWrite: 0,
        selfFee: 0,
      };
      existing.invocationCount += 1;
      existing.selfCpu += node.selfResources.cpuInstructions;
      existing.totalCpu += node.totalResources.cpuInstructions;
      existing.selfRead += node.selfResources.readBytes;
      existing.selfWrite += node.selfResources.writeBytes;
      existing.selfFee += node.selfResources.feeStroops;
      contractMap.set(node.contractId, existing);

      for (const child of node.children) {
        visit(child);
      }
    };

    for (const root of roots) {
      visit(root);
    }

    const totalResources = roots.reduce<CallNodeResources>(
      (acc, r) => ({
        cpuInstructions: acc.cpuInstructions + r.totalResources.cpuInstructions,
        readBytes: acc.readBytes + r.totalResources.readBytes,
        writeBytes: acc.writeBytes + r.totalResources.writeBytes,
        feeStroops: acc.feeStroops + r.totalResources.feeStroops,
      }),
      { cpuInstructions: 0, readBytes: 0, writeBytes: 0, feeStroops: 0 },
    );

    const contractAttribution: ContractResourceBreakdown[] = Array.from(
      contractMap.entries(),
    )
      .map(([contractId, data]) => ({
        contractId,
        invocationCount: data.invocationCount,
        selfCpuInstructions: data.selfCpu,
        totalCpuInstructions: data.totalCpu,
        selfReadBytes: data.selfRead,
        selfWriteBytes: data.selfWrite,
        selfFeeStroops: data.selfFee,
        cpuSharePct:
          totalResources.cpuInstructions > 0
            ? Math.round((data.selfCpu / totalResources.cpuInstructions) * 10000) / 100
            : 0,
      }))
      .sort((a, b) => b.selfCpuInstructions - a.selfCpuInstructions);

    return {
      txHash: envelope.txHash,
      ledgerSeq: envelope.ledgerSeq,
      roots,
      edges,
      maxDepth,
      totalInvocations,
      involvedContracts: contractAttribution.map((c) => c.contractId),
      hasFailedSubInvocation,
      totalResources,
      contractAttribution,
    };
  }

  /**
   * Formats a compact alert metadata block for developer webhook/notification payloads.
   */
  public formatAlertMetadata(traceResult: CallGraphTraceResult): Record<string, any> {
    return {
      txHash: traceResult.txHash ?? null,
      ledgerSeq: traceResult.ledgerSeq ?? null,
      maxDepth: traceResult.maxDepth,
      totalInvocations: traceResult.totalInvocations,
      involvedContracts: traceResult.involvedContracts,
      hasFailedSubInvocation: traceResult.hasFailedSubInvocation,
      totalResources: traceResult.totalResources,
      contractAttribution: traceResult.contractAttribution,
      callGraph: traceResult.roots,
      edges: traceResult.edges,
    };
  }

  private buildFromNestedFrame(
    frame: DiagnosticInvocationEvent,
    depth: number,
    parentContractId: string | null,
    nextNodeId: () => string,
  ): CallGraphNode {
    const contractId = (frame.contractId ?? 'UNKNOWN_CONTRACT').trim();
    const functionName = (frame.functionName ?? 'unknown_fn').trim();
    const args = Array.isArray(frame.args)
      ? frame.args.map((a) => decodeDiagnosticScVal(a))
      : [];
    const returnValue =
      frame.returnValue !== undefined
        ? decodeDiagnosticScVal(frame.returnValue)
        : undefined;
    const status: CallInvocationStatus =
      frame.status ??
      (frame.inSuccessfulContractCall === false ? 'reverted' : 'success');

    const selfResources = this.normalizeResources(frame);
    const children = (frame.subInvocations ?? []).map((sub) =>
      this.buildFromNestedFrame(sub, depth + 1, contractId, nextNodeId),
    );

    return {
      nodeId: nextNodeId(),
      depth,
      callerContractId: frame.callerContractId ?? parentContractId,
      contractId,
      functionName,
      args,
      returnValue,
      status,
      errorMessage: frame.errorMessage,
      selfResources,
      totalResources: { ...selfResources },
      children,
    };
  }

  /**
   * Reconstructs the call stack from Soroban diagnostic event sequences:
   * - `fn_call`: topics `['fn_call', targetContractBytesOrId, functionSymbol]`, value: `args[]`
   * - `fn_return`: topics `['fn_return', functionSymbol]`, value: `returnVal`
   * - `error`: topics `['error', ...]`, value: `errorMsg`
   */
  private buildFromDiagnosticStream(
    events: DiagnosticInvocationEvent[],
    nextNodeId: () => string,
  ): CallGraphNode[] {
    const roots: CallGraphNode[] = [];
    const stack: CallGraphNode[] = [];

    for (const raw of events) {
      const decodedTopics = Array.isArray(raw.topic)
        ? raw.topic.map((t) => decodeDiagnosticScVal(t))
        : [];
      const decodedVal = decodeDiagnosticScVal(raw.value);
      const leadSymbol = String(
        raw.type && raw.type !== 'diagnostic'
          ? raw.type
          : decodedTopics[0] ?? '',
      ).toLowerCase();

      if (leadSymbol === 'fn_call') {
        // In Soroban diagnostic events:
        // topic[0] = 'fn_call', topic[1] = target contract ID (or raw.contractId), topic[2] = fn name
        const targetContractId = String(
          (decodedTopics.length >= 3 ? decodedTopics[1] : raw.contractId) ??
            raw.contractId ??
            'UNKNOWN_CONTRACT',
        );
        const fnName = String(
          raw.functionName ??
            (decodedTopics.length >= 3 ? decodedTopics[2] : decodedTopics[1]) ??
            'unknown_fn',
        );
        const args = Array.isArray(raw.args)
          ? raw.args.map((a) => decodeDiagnosticScVal(a))
          : Array.isArray(decodedVal)
            ? decodedVal
            : decodedVal !== null && decodedVal !== undefined
              ? [decodedVal]
              : [];

        const parent = stack.length > 0 ? stack[stack.length - 1]! : null;
        const status: CallInvocationStatus =
          raw.status ??
          (raw.inSuccessfulContractCall === false ? 'reverted' : 'success');
        const selfResources = this.normalizeResources(raw);

        const node: CallGraphNode = {
          nodeId: nextNodeId(),
          depth: stack.length,
          callerContractId:
            raw.callerContractId ?? (parent ? parent.contractId : null),
          contractId: targetContractId,
          functionName: fnName,
          args,
          returnValue:
            raw.returnValue !== undefined
              ? decodeDiagnosticScVal(raw.returnValue)
              : undefined,
          status,
          errorMessage: raw.errorMessage,
          selfResources,
          totalResources: { ...selfResources },
          children: [],
        };

        // If this `fn_call` also includes nested `subInvocations`, attach them and do not leave on stack
        if (Array.isArray(raw.subInvocations) && raw.subInvocations.length > 0) {
          node.children = raw.subInvocations.map((sub) =>
            this.buildFromNestedFrame(
              sub,
              node.depth + 1,
              node.contractId,
              nextNodeId,
            ),
          );
          if (parent) {
            parent.children.push(node);
          } else {
            roots.push(node);
          }
          continue;
        }

        if (parent) {
          parent.children.push(node);
        } else {
          roots.push(node);
        }
        stack.push(node);
      } else if (leadSymbol === 'fn_return') {
        const active = stack.pop();
        if (active) {
          active.returnValue =
            raw.returnValue !== undefined
              ? decodeDiagnosticScVal(raw.returnValue)
              : decodedVal;
          if (raw.inSuccessfulContractCall === false || raw.status === 'reverted') {
            active.status = 'reverted';
          }
          const returnRes = this.normalizeResources(raw);
          active.selfResources.cpuInstructions += returnRes.cpuInstructions;
          active.selfResources.readBytes += returnRes.readBytes;
          active.selfResources.writeBytes += returnRes.writeBytes;
          active.selfResources.feeStroops = this.estimateFeeStroops(
            active.selfResources.cpuInstructions,
            active.selfResources.readBytes,
            active.selfResources.writeBytes,
            raw.feeStroops !== undefined
              ? active.selfResources.feeStroops + returnRes.feeStroops
              : undefined,
          );
        }
      } else if (leadSymbol === 'error' || leadSymbol === 'contract_error') {
        const active = stack.pop();
        if (active) {
          active.status = raw.status ?? 'error';
          active.errorMessage =
            raw.errorMessage ??
            (typeof decodedVal === 'string'
              ? decodedVal
              : JSON.stringify(decodedVal));
        }
      }
    }

    return roots;
  }

  private computeInclusiveResources(node: CallGraphNode): CallNodeResources {
    let cpu = node.selfResources.cpuInstructions;
    let read = node.selfResources.readBytes;
    let write = node.selfResources.writeBytes;
    let fee = node.selfResources.feeStroops;

    for (const child of node.children) {
      const childTotal = this.computeInclusiveResources(child);
      cpu += childTotal.cpuInstructions;
      read += childTotal.readBytes;
      write += childTotal.writeBytes;
      fee += childTotal.feeStroops;
    }

    node.totalResources = {
      cpuInstructions: cpu,
      readBytes: read,
      writeBytes: write,
      feeStroops: fee,
    };
    return node.totalResources;
  }

  private normalizeResources(event: DiagnosticInvocationEvent): CallNodeResources {
    const cpuInstructions = Math.max(0, Number(event.cpuInstructions ?? 0));
    const readBytes = Math.max(0, Number(event.readBytes ?? 0));
    const writeBytes = Math.max(0, Number(event.writeBytes ?? 0));
    const feeStroops = this.estimateFeeStroops(
      cpuInstructions,
      readBytes,
      writeBytes,
      event.feeStroops,
    );
    return {
      cpuInstructions,
      readBytes,
      writeBytes,
      feeStroops,
    };
  }

  private estimateFeeStroops(
    cpuInstructions: number,
    readBytes: number,
    writeBytes: number,
    explicitFee?: number,
  ): number {
    if (explicitFee !== undefined && Number.isFinite(explicitFee)) {
      return Math.max(0, Math.round(explicitFee));
    }
    const cpuFee = (cpuInstructions / 10_000) * this.stroopsPerTenThousandCpu;
    const ioFee = ((readBytes + writeBytes) / 1024) * this.stroopsPerKilobyteIo;
    return Math.round(cpuFee + ioFee);
  }
}

export const callGraphTracer = new CallGraphTracer();
