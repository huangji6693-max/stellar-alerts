import { Keypair, nativeToScVal, xdr } from 'stellar-sdk';
import { describe, expect, it } from 'vitest';
import { jsToScVal, scValToJs } from './scval-parser';

describe('Soroban ScVal conversion', () => {
  it.each([
    [42, 'u32', 42],
    [-42, 'i32', -42],
    [42n, 'u64', 42n],
    [-42n, 'i64', -42n],
    [2n ** 100n, 'u128', 2n ** 100n],
    [-(2n ** 100n), 'i128', -(2n ** 100n)],
    ['hello', 'string', 'hello'],
    ['hello', 'symbol', 'hello'],
    [true, undefined, true],
  ] as const)('decodes %s as %s', (value, type, expected) => {
    const scVal = nativeToScVal(value, type ? { type } : undefined);
    expect(scValToJs(scVal)).toEqual(expected);
  });

  it('decodes addresses, vectors, and maps recursively', () => {
    const address = Keypair.random().publicKey();
    const value = {
      owner: address,
      values: [1n, 'two', 2n ** 100n],
      enabled: true,
    };
    const scVal = nativeToScVal({
      owner: nativeToScVal(address, { type: 'address' }),
      values: [1, 'two', 2n ** 100n],
      enabled: true,
    });
    expect(scValToJs(scVal)).toEqual(value);
  });

  it('decodes base64 XDR and roundtrips nested values', () => {
    const input = { amount: 2n ** 100n, tags: ['one', 'two'], active: false };
    const encoded = jsToScVal(input);
    const decodedFromXdr = scValToJs(encoded.toXDR('base64'));
    expect(decodedFromXdr).toEqual(input);
    expect(scValToJs(jsToScVal(decodedFromXdr as typeof input))).toEqual(input);
  });

  it('accepts prebuilt ScVal objects without changing them', () => {
    const value = xdr.ScVal.scvBool(true);
    expect(jsToScVal(value)).toBe(value);
    expect(scValToJs(value)).toBe(true);
  });

  it('preserves the requested integer type while encoding', () => {
    const encoded = jsToScVal(7, { type: 'u32' });
    expect(encoded.switch()).toEqual(xdr.ScValType.scvU32());
    expect(scValToJs(encoded)).toBe(7);
  });
});
