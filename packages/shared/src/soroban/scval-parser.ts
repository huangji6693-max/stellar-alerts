import { nativeToScVal, scValToNative, xdr } from 'stellar-sdk';

/** Values supported by Stellar's native ScVal encoder. */
export type ScValInput =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | ScValInput[]
  | { [key: string]: ScValInput }
  | xdr.ScVal;

/** SDK hints for choosing a specific ScVal encoding (for example `u128`). */
export type ScValEncodeOptions = Parameters<typeof nativeToScVal>[1];

/**
 * Decode an ScVal instance or its base64 XDR representation to JavaScript.
 * The Stellar SDK preserves 64/128/256-bit integers as bigint and recursively
 * converts vectors and maps, avoiding JavaScript number precision loss.
 */
export function scValToJs(value: xdr.ScVal | string): unknown {
  const scVal = typeof value === 'string' ? xdr.ScVal.fromXDR(value, 'base64') : value;
  return scValToNative(scVal);
}

/** Encode a supported JavaScript value as a Soroban ScVal. */
export function jsToScVal(value: ScValInput, options?: ScValEncodeOptions): xdr.ScVal {
  return nativeToScVal(value, options);
}
