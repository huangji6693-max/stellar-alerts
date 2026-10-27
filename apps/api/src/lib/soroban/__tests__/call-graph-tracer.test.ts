import { describe, expect, it } from 'vitest';
import {
  CallGraphTracer,
  CallGraphXdr,
  DiagnosticInvocationEvent,
} from '../call-graph-tracer';

const ROUTER_CONTRACT = 'CROUTER1111111111111111111111111111111111111111111111111';
const POOL_CONTRACT = 'CPOOL222222222222222222222222222222222222222222222222222';
const TOKEN_A_CONTRACT = 'CTOKENA3333333333333333333333333333333333333333333333333';
const ORACLE_CONTRACT = 'CORACLE4444444444444444444444444444444444444444444444444';

describe('CallGraphTracer (#725)', () => {
  const tracer = new CallGraphTracer();

  it('reconstructs hierarchical 3-level call tree from Soroban diagnostic XDR event stream', () => {
    // Execution trace:
    // Router.swap_exact_tokens_for_tokens(1000, 950)
    //   ├─ Oracle.get_twap("XLM/USDC") -> 1050000
    //   └─ Pool.swap(1000)
    //        └─ TokenA.transfer("GALICE", POOL_CONTRACT, 1000) -> true
    //        -> returns 985
    // -> returns 985
    const diagnosticEvents: DiagnosticInvocationEvent[] = [
      {
        topic: [
          CallGraphXdr.symbol('fn_call'),
          CallGraphXdr.string(ROUTER_CONTRACT),
          CallGraphXdr.symbol('swap_exact_tokens_for_tokens'),
        ],
        value: CallGraphXdr.vec([CallGraphXdr.u64(1000n), CallGraphXdr.u64(950n)]),
        cpuInstructions: 120_000,
        readBytes: 2048,
        writeBytes: 512,
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_call'),
          CallGraphXdr.string(ORACLE_CONTRACT),
          CallGraphXdr.symbol('get_twap'),
        ],
        value: CallGraphXdr.vec([CallGraphXdr.string('XLM/USDC')]),
        cpuInstructions: 80_000,
        readBytes: 1024,
        writeBytes: 0,
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_return'),
          CallGraphXdr.symbol('get_twap'),
        ],
        value: CallGraphXdr.u64(1050000n),
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_call'),
          CallGraphXdr.string(POOL_CONTRACT),
          CallGraphXdr.symbol('swap'),
        ],
        value: CallGraphXdr.vec([CallGraphXdr.u64(1000n)]),
        cpuInstructions: 200_000,
        readBytes: 4096,
        writeBytes: 2048,
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_call'),
          CallGraphXdr.string(TOKEN_A_CONTRACT),
          CallGraphXdr.symbol('transfer'),
        ],
        value: CallGraphXdr.vec([
          CallGraphXdr.string('GALICE'),
          CallGraphXdr.string(POOL_CONTRACT),
          CallGraphXdr.u64(1000n),
        ]),
        cpuInstructions: 100_000,
        readBytes: 1024,
        writeBytes: 1024,
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_return'),
          CallGraphXdr.symbol('transfer'),
        ],
        value: true,
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_return'),
          CallGraphXdr.symbol('swap'),
        ],
        value: CallGraphXdr.u64(985n),
      },
      {
        topic: [
          CallGraphXdr.symbol('fn_return'),
          CallGraphXdr.symbol('swap_exact_tokens_for_tokens'),
        ],
        value: CallGraphXdr.u64(985n),
      },
    ];

    const trace = tracer.trace({
      txHash: '0xcallgraph725',
      ledgerSeq: 55100,
      diagnosticEvents,
    });

    expect(trace.roots).toHaveLength(1);
    expect(trace.totalInvocations).toBe(4);
    expect(trace.maxDepth).toBe(2);
    expect(trace.hasFailedSubInvocation).toBe(false);

    const root = trace.roots[0]!;
    expect(root.contractId).toBe(ROUTER_CONTRACT);
    expect(root.functionName).toBe('swap_exact_tokens_for_tokens');
    expect(root.args).toEqual(['1000', '950']);
    expect(root.returnValue).toBe('985');
    expect(root.children).toHaveLength(2);

    const [oracleCall, poolCall] = root.children;
    expect(oracleCall?.contractId).toBe(ORACLE_CONTRACT);
    expect(oracleCall?.functionName).toBe('get_twap');
    expect(oracleCall?.returnValue).toBe('1050000');

    expect(poolCall?.contractId).toBe(POOL_CONTRACT);
    expect(poolCall?.children).toHaveLength(1);
    expect(poolCall?.children[0]?.contractId).toBe(TOKEN_A_CONTRACT);
    expect(poolCall?.children[0]?.functionName).toBe('transfer');
    expect(poolCall?.children[0]?.depth).toBe(2);

    // Verify accurate gas/resource attribution per sub-contract and inclusive rollups
    // Total CPU = 120k (Router) + 80k (Oracle) + 200k (Pool) + 100k (TokenA) = 500k
    expect(trace.totalResources.cpuInstructions).toBe(500_000);
    expect(root.totalResources.cpuInstructions).toBe(500_000);
    expect(poolCall?.totalResources.cpuInstructions).toBe(300_000); // 200k self + 100k TokenA

    const poolAttr = trace.contractAttribution.find(
      (c) => c.contractId === POOL_CONTRACT,
    );
    expect(poolAttr?.selfCpuInstructions).toBe(200_000);
    expect(poolAttr?.totalCpuInstructions).toBe(300_000);
    expect(poolAttr?.cpuSharePct).toBe(40); // 200k / 500k = 40%
  });

  it('tracks reverted/error sub-invocations and formats structured alert metadata', () => {
    const trace = tracer.trace({
      txHash: '0xfailedsubcall',
      ledgerSeq: 55101,
      invocations: [
        {
          contractId: ROUTER_CONTRACT,
          functionName: 'execute_batch',
          args: ['batch-1'],
          cpuInstructions: 50_000,
          subInvocations: [
            {
              contractId: POOL_CONTRACT,
              functionName: 'flash_swap',
              args: [5000],
              status: 'reverted',
              errorMessage: 'HostError: slippage exceeded',
              cpuInstructions: 150_000,
            },
          ],
        },
      ],
    });

    expect(trace.hasFailedSubInvocation).toBe(true);
    expect(trace.edges).toEqual([
      {
        fromContractId: ROUTER_CONTRACT,
        toContractId: POOL_CONTRACT,
        functionName: 'flash_swap',
        depth: 1,
        status: 'reverted',
      },
    ]);

    const metadata = tracer.formatAlertMetadata(trace);
    expect(metadata.txHash).toBe('0xfailedsubcall');
    expect(metadata.hasFailedSubInvocation).toBe(true);
    expect(metadata.involvedContracts).toEqual([POOL_CONTRACT, ROUTER_CONTRACT]);
    expect(metadata.callGraph[0].children[0].errorMessage).toContain(
      'slippage exceeded',
    );
  });
});
