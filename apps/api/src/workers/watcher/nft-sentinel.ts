/**
 * #737: NFT & Non-Fungible Token Transfer and Minting Event Sentinel.
 *
 * Monitors Soroban NFT smart contracts (SEP-0041 / non-fungible token interface),
 * decoding `transfer`, `mint`, `burn`, and `metadata_update` (`uri` / `token_uri`)
 * events, extracting integer/string token IDs and sender/receiver addresses,
 * resolving token metadata URIs, and formatting notifications with explorer links.
 */

export type NftEventType = 'transfer' | 'mint' | 'burn' | 'metadata_update';

export interface RawSorobanNftEvent {
  id?: string;
  contractId?: string;
  topic?: unknown[];
  value?: unknown;
  txHash?: string;
  ledger?: number;
  ledgerSeq?: number;
  ledgerClosedAt?: string;
}

export interface ParsedNftEvent {
  eventType: NftEventType;
  contractId: string;
  tokenId: string;
  tokenIdNumeric: bigint | null;
  from: string | null;
  to: string | null;
  metadataUri?: string | null;
  txHash?: string;
  ledgerSeq: number;
  timestamp: string;
  explorerContractUrl: string;
  explorerTxUrl?: string;
}

export interface NftAlertNotification {
  event: ParsedNftEvent;
  headline: string;
  message: string;
  explorerLinks: {
    contract: string;
    transaction?: string;
    token?: string;
  };
}

export type NftMetadataResolver = (
  contractId: string,
  tokenId: string,
) => Promise<string | null> | string | null;

export interface NftSentinelOptions {
  /** Base explorer URL (default `https://stellar.expert/explorer/public`). */
  explorerBaseUrl?: string;
  /** Optional resolver to look up `token_uri(token_id)` metadata URI. */
  metadataResolver?: NftMetadataResolver;
  /** Optional watched contract allowlist. */
  watchedContractIds?: string[];
}

const DEFAULT_EXPLORER_BASE = 'https://stellar.expert/explorer/public';

/**
 * Decodes an XDR base64 string or structured ScVal-like value into a primitive JS value.
 */
export function decodeNftScVal(input: unknown): any {
  if (input === null || input === undefined) return null;
  if (typeof input === 'number' || typeof input === 'bigint' || typeof input === 'boolean') {
    return input;
  }

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return '';
    // Attempt base64 XDR decoding if it looks like base64 XDR (multiple of 4 chars)
    if (/^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length >= 8 && trimmed.length % 4 === 0) {
      const xdrDecoded = tryDecodeBase64ScVal(trimmed);
      if (xdrDecoded !== undefined) {
        return xdrDecoded;
      }
    }
    return trimmed;
  }

  if (Array.isArray(input)) {
    return input.map((item) => decodeNftScVal(item));
  }

  if (typeof input === 'object') {
    const obj = input as Record<string, any>;
    // Native stellar-sdk ScVal instance with `.switch()`
    if (typeof obj.switch === 'function') {
      try {
        const b64 = typeof obj.toXDR === 'function' ? obj.toXDR('base64') : null;
        if (b64) {
          const decoded = tryDecodeBase64ScVal(b64);
          if (decoded !== undefined) return decoded;
        }
      } catch {
        // Fall through to structured object handling
      }
    }
    if ('symbol' in obj && typeof obj.symbol === 'string') return obj.symbol;
    if ('string' in obj && typeof obj.string === 'string') return obj.string;
    if ('address' in obj && typeof obj.address === 'string') return obj.address;
    if ('u32' in obj) return Number(obj.u32);
    if ('i32' in obj) return Number(obj.i32);
    if ('u64' in obj) return BigInt(obj.u64);
    if ('i64' in obj) return BigInt(obj.i64);
    if ('u128' in obj) return BigInt(obj.u128);
    if ('i128' in obj) return BigInt(obj.i128);
    if ('value' in obj && Object.keys(obj).length <= 2 && 'type' in obj) {
      return decodeNftScVal(obj.value);
    }
    const result: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = decodeNftScVal(v);
    }
    return result;
  }

  return input;
}

/**
 * Encodes a helper ScVal to base64 XDR for tests and deterministic event fixtures.
 */
export const NftXdrBuilder = {
  symbol(sym: string): string {
    return encodeAsciiScVal(14, sym);
  },
  string(str: string): string {
    return encodeAsciiScVal(13, str);
  },
  u32(val: number): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(3, 0);
    buf.writeUInt32BE(val >>> 0, 4);
    return buf.toString('base64');
  },
  u64(val: bigint | number): string {
    const buf = Buffer.alloc(12);
    buf.writeUInt32BE(5, 0);
    buf.writeBigUInt64BE(BigInt(val), 4);
    return buf.toString('base64');
  },
  u128(val: bigint | number): string {
    const big = BigInt(val);
    const hi = (big >> 64n) & 0xffffffffffffffffn;
    const lo = big & 0xffffffffffffffffn;
    const buf = Buffer.alloc(20);
    buf.writeUInt32BE(9, 0);
    buf.writeBigUInt64BE(hi, 4);
    buf.writeBigUInt64BE(lo, 12);
    return buf.toString('base64');
  },
  i128(val: bigint | number): string {
    const big = BigInt(val);
    const hi = BigInt.asIntN(64, big >> 64n);
    const lo = big & 0xffffffffffffffffn;
    const buf = Buffer.alloc(20);
    buf.writeUInt32BE(10, 0);
    buf.writeBigInt64BE(hi, 4);
    buf.writeBigUInt64BE(lo, 12);
    return buf.toString('base64');
  },
};

function encodeAsciiScVal(discriminant: number, text: string): string {
  const bytes = Buffer.from(text, 'utf8');
  const paddedLen = Math.ceil(bytes.length / 4) * 4;
  const buf = Buffer.alloc(8 + paddedLen);
  buf.writeUInt32BE(discriminant, 0);
  buf.writeUInt32BE(bytes.length, 4);
  bytes.copy(buf, 8);
  return buf.toString('base64');
}

function tryDecodeBase64ScVal(b64: string): any {
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    return undefined;
  }
  if (buf.length < 4 || buf.length % 4 !== 0) return undefined;

  const parsed = readScValFromBuffer(buf, 0);
  if (!parsed || parsed.nextOffset !== buf.length) return undefined;
  return parsed.value;
}

function readScValFromBuffer(
  buf: Buffer,
  offset: number,
): { value: any; nextOffset: number } | undefined {
  if (offset + 4 > buf.length) return undefined;
  const disc = buf.readUInt32BE(offset);
  let pos = offset + 4;

  switch (disc) {
    case 0: {
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readUInt32BE(pos) !== 0, nextOffset: pos + 4 };
    }
    case 1:
      return { value: null, nextOffset: pos };
    case 3: {
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readUInt32BE(pos), nextOffset: pos + 4 };
    }
    case 4: {
      if (pos + 4 > buf.length) return undefined;
      return { value: buf.readInt32BE(pos), nextOffset: pos + 4 };
    }
    case 5:
    case 7:
    case 8: {
      if (pos + 8 > buf.length) return undefined;
      return { value: buf.readBigUInt64BE(pos), nextOffset: pos + 8 };
    }
    case 6: {
      if (pos + 8 > buf.length) return undefined;
      return { value: buf.readBigInt64BE(pos), nextOffset: pos + 8 };
    }
    case 9: {
      if (pos + 16 > buf.length) return undefined;
      const hi = buf.readBigUInt64BE(pos);
      const lo = buf.readBigUInt64BE(pos + 8);
      return { value: (hi << 64n) | lo, nextOffset: pos + 16 };
    }
    case 10: {
      if (pos + 16 > buf.length) return undefined;
      const hi = buf.readBigInt64BE(pos);
      const lo = buf.readBigUInt64BE(pos + 8);
      return { value: (hi << 64n) | lo, nextOffset: pos + 16 };
    }
    case 13:
    case 14: {
      if (pos + 4 > buf.length) return undefined;
      const len = buf.readUInt32BE(pos);
      pos += 4;
      const padded = Math.ceil(len / 4) * 4;
      if (pos + padded > buf.length) return undefined;
      // Validate padded zero bytes so plain strings like "transfer" (8 chars) are not misidentified as XDR
      for (let i = len; i < padded; i++) {
        if (buf[pos + i] !== 0) return undefined;
      }
      const str = buf.subarray(pos, pos + len).toString('utf8');
      return { value: str, nextOffset: pos + padded };
    }
    case 15: {
      if (pos + 4 > buf.length) return undefined;
      const present = buf.readUInt32BE(pos);
      pos += 4;
      if (present === 0) return { value: [], nextOffset: pos };
      if (pos + 4 > buf.length) return undefined;
      const count = buf.readUInt32BE(pos);
      pos += 4;
      const items: any[] = [];
      for (let i = 0; i < count; i++) {
        const elem = readScValFromBuffer(buf, pos);
        if (!elem) return undefined;
        items.push(elem.value);
        pos = elem.nextOffset;
      }
      return { value: items, nextOffset: pos };
    }
    case 16: {
      if (pos + 4 > buf.length) return undefined;
      const present = buf.readUInt32BE(pos);
      pos += 4;
      if (present === 0) return { value: {}, nextOffset: pos };
      if (pos + 4 > buf.length) return undefined;
      const count = buf.readUInt32BE(pos);
      pos += 4;
      const mapObj: Record<string, any> = {};
      for (let i = 0; i < count; i++) {
        const k = readScValFromBuffer(buf, pos);
        if (!k) return undefined;
        const v = readScValFromBuffer(buf, k.nextOffset);
        if (!v) return undefined;
        mapObj[String(k.value)] = v.value;
        pos = v.nextOffset;
      }
      return { value: mapObj, nextOffset: pos };
    }
    default:
      return undefined;
  }
}

function parseTokenId(raw: unknown): { tokenId: string; tokenIdNumeric: bigint | null } | null {
  const decoded = decodeNftScVal(raw);
  if (decoded === null || decoded === undefined || decoded === '') return null;

  if (typeof decoded === 'bigint') {
    return { tokenId: decoded.toString(), tokenIdNumeric: decoded };
  }
  if (typeof decoded === 'number' && Number.isFinite(decoded)) {
    const big = BigInt(Math.trunc(decoded));
    return { tokenId: big.toString(), tokenIdNumeric: big };
  }
  if (typeof decoded === 'string') {
    const trimmed = decoded.trim();
    if (!trimmed) return null;
    if (/^-?\d+$/.test(trimmed)) {
      return { tokenId: trimmed, tokenIdNumeric: BigInt(trimmed) };
    }
    return { tokenId: trimmed, tokenIdNumeric: null };
  }
  if (typeof decoded === 'object' && decoded !== null) {
    const obj = decoded as Record<string, any>;
    const candidate = obj.token_id ?? obj.tokenId ?? obj.id;
    if (candidate !== undefined) return parseTokenId(candidate);
  }
  return null;
}

/**
 * Decodes a raw Soroban RPC event into a structured SEP-0041 `ParsedNftEvent`
 * if it matches `transfer`, `mint`, `burn`, or `metadata_update` (`uri` / `token_uri`).
 */
export function parseSorobanNftEvent(
  rawEvent: RawSorobanNftEvent,
  explorerBaseUrl = DEFAULT_EXPLORER_BASE,
): ParsedNftEvent | null {
  if (!rawEvent || !Array.isArray(rawEvent.topic) || rawEvent.topic.length === 0) {
    return null;
  }

  const contractId = (rawEvent.contractId ?? '').trim();
  if (!contractId) return null;

  const decodedTopics = rawEvent.topic.map((t) => decodeNftScVal(t));
  const decodedValue = decodeNftScVal(rawEvent.value);

  const leadTopic = String(decodedTopics[0] ?? '').toLowerCase();
  let eventType: NftEventType | null = null;
  if (leadTopic === 'transfer' || leadTopic === 'nft_transfer') {
    eventType = 'transfer';
  } else if (leadTopic === 'mint' || leadTopic === 'nft_mint') {
    eventType = 'mint';
  } else if (leadTopic === 'burn' || leadTopic === 'nft_burn') {
    eventType = 'burn';
  } else if (
    leadTopic === 'metadata_update' ||
    leadTopic === 'token_uri' ||
    leadTopic === 'set_token_uri' ||
    leadTopic === 'uri_update'
  ) {
    eventType = 'metadata_update';
  }

  if (!eventType) return null;

  let from: string | null = null;
  let to: string | null = null;
  let tokenParsed: { tokenId: string; tokenIdNumeric: bigint | null } | null = null;
  let metadataUri: string | null = null;

  if (eventType === 'transfer') {
    // SEP-0041 NFT transfer layouts:
    // 1) topics: ['transfer', from, to], value: token_id (or { token_id, metadata_uri })
    // 2) topics: ['transfer', from, to, token_id]
    from = decodedTopics[1] ? String(decodedTopics[1]) : null;
    to = decodedTopics[2] ? String(decodedTopics[2]) : null;
    tokenParsed =
      (decodedTopics.length >= 4 ? parseTokenId(decodedTopics[3]) : null) ??
      parseTokenId(decodedValue);
  } else if (eventType === 'mint') {
    // SEP-0041 NFT mint layouts:
    // 1) topics: ['mint', to] (or ['mint', admin, to]), value: token_id
    // 2) topics: ['mint', to, token_id], value: metadata_uri
    if (decodedTopics.length >= 3 && typeof decodedTopics[2] === 'string' && decodedTopics[2].startsWith('G')) {
      from = decodedTopics[1] ? String(decodedTopics[1]) : null;
      to = String(decodedTopics[2]);
      tokenParsed = parseTokenId(decodedTopics[3]) ?? parseTokenId(decodedValue);
    } else {
      to = decodedTopics[1] ? String(decodedTopics[1]) : null;
      tokenParsed =
        (decodedTopics.length >= 3 ? parseTokenId(decodedTopics[2]) : null) ??
        parseTokenId(decodedValue);
    }
  } else if (eventType === 'burn') {
    // SEP-0041 NFT burn layouts:
    // topics: ['burn', from] (or ['burn', from, token_id]), value: token_id
    from = decodedTopics[1] ? String(decodedTopics[1]) : null;
    tokenParsed =
      (decodedTopics.length >= 3 ? parseTokenId(decodedTopics[2]) : null) ??
      parseTokenId(decodedValue);
  } else if (eventType === 'metadata_update') {
    // topics: ['metadata_update', token_id], value: uri (or { token_id, uri })
    tokenParsed = parseTokenId(decodedTopics[1]) ?? parseTokenId(decodedValue);
    if (typeof decodedValue === 'string') {
      metadataUri = decodedValue;
    }
  }

  if (decodedValue && typeof decodedValue === 'object' && !Array.isArray(decodedValue)) {
    const valObj = decodedValue as Record<string, any>;
    if (!from && typeof valObj.from === 'string') from = valObj.from;
    if (!to && typeof valObj.to === 'string') to = valObj.to;
    if (!metadataUri) {
      const uriCandidate = valObj.metadata_uri ?? valObj.token_uri ?? valObj.uri;
      if (typeof uriCandidate === 'string') metadataUri = uriCandidate;
    }
  }

  if (!tokenParsed) return null;

  const base = explorerBaseUrl.replace(/\/+$/, '');
  const explorerContractUrl = `${base}/contract/${contractId}`;
  const explorerTxUrl = rawEvent.txHash ? `${base}/tx/${rawEvent.txHash}` : undefined;
  const ledgerSeq = Number(rawEvent.ledgerSeq ?? rawEvent.ledger ?? 0);
  const timestamp = rawEvent.ledgerClosedAt ?? new Date().toISOString();

  return {
    eventType,
    contractId,
    tokenId: tokenParsed.tokenId,
    tokenIdNumeric: tokenParsed.tokenIdNumeric,
    from,
    to,
    metadataUri,
    txHash: rawEvent.txHash,
    ledgerSeq,
    timestamp,
    explorerContractUrl,
    explorerTxUrl,
  };
}

export class NftSentinel {
  private readonly explorerBaseUrl: string;
  private readonly metadataResolver?: NftMetadataResolver;
  private readonly watchedContracts: Set<string>;

  constructor(options: NftSentinelOptions = {}) {
    this.explorerBaseUrl = (options.explorerBaseUrl ?? DEFAULT_EXPLORER_BASE).replace(
      /\/+$/,
      '',
    );
    this.metadataResolver = options.metadataResolver;
    this.watchedContracts = new Set(
      (options.watchedContractIds ?? []).map((c) => c.trim()).filter(Boolean),
    );
  }

  public isContractWatched(contractId: string): boolean {
    if (this.watchedContracts.size === 0) return true;
    return this.watchedContracts.has(contractId.trim());
  }

  /**
   * Decodes a raw Soroban event and optionally resolves the NFT metadata URI.
   */
  public async inspectEvent(rawEvent: RawSorobanNftEvent): Promise<ParsedNftEvent | null> {
    const parsed = parseSorobanNftEvent(rawEvent, this.explorerBaseUrl);
    if (!parsed) return null;
    if (!this.isContractWatched(parsed.contractId)) return null;

    if (!parsed.metadataUri && this.metadataResolver) {
      try {
        const resolved = await this.metadataResolver(parsed.contractId, parsed.tokenId);
        if (resolved) parsed.metadataUri = resolved;
      } catch {
        // Non-fatal metadata resolution failure
      }
    }

    return parsed;
  }

  /**
   * Formats a rich human-readable NFT notification with token ID and explorer links.
   */
  public formatNotification(event: ParsedNftEvent): NftAlertNotification {
    const shortContract =
      event.contractId.length > 12
        ? `${event.contractId.slice(0, 6)}...${event.contractId.slice(-4)}`
        : event.contractId;

    let headline: string;
    let actionSummary: string;

    switch (event.eventType) {
      case 'mint':
        headline = `NFT #${event.tokenId} Minted on ${shortContract}`;
        actionSummary = `Minted token #${event.tokenId} to ${event.to ?? 'unknown recipient'}`;
        break;
      case 'burn':
        headline = `NFT #${event.tokenId} Burned on ${shortContract}`;
        actionSummary = `Burned token #${event.tokenId} from ${event.from ?? 'unknown holder'}`;
        break;
      case 'metadata_update':
        headline = `NFT #${event.tokenId} Metadata Updated on ${shortContract}`;
        actionSummary = `Updated metadata URI for token #${event.tokenId}${
          event.metadataUri ? ` -> ${event.metadataUri}` : ''
        }`;
        break;
      case 'transfer':
      default:
        headline = `NFT #${event.tokenId} Transferred on ${shortContract}`;
        actionSummary = `Transferred token #${event.tokenId} from ${
          event.from ?? 'unknown'
        } to ${event.to ?? 'unknown'}`;
        break;
    }

    const explorerLinks = {
      contract: event.explorerContractUrl,
      transaction: event.explorerTxUrl,
      token: `${event.explorerContractUrl}?token=${encodeURIComponent(event.tokenId)}`,
    };

    const messageParts = [
      `${actionSummary}.`,
      `Contract: ${event.explorerContractUrl}`,
    ];
    if (event.explorerTxUrl) {
      messageParts.push(`Tx: ${event.explorerTxUrl}`);
    }
    if (event.metadataUri) {
      messageParts.push(`Metadata URI: ${event.metadataUri}`);
    }

    return {
      event,
      headline,
      message: messageParts.join(' | '),
      explorerLinks,
    };
  }

  /**
   * Processes a batch of raw Soroban events and returns formatted notifications.
   */
  public async processEventBatch(
    rawEvents: RawSorobanNftEvent[],
  ): Promise<NftAlertNotification[]> {
    const notifications: NftAlertNotification[] = [];
    for (const raw of rawEvents) {
      const parsed = await this.inspectEvent(raw);
      if (parsed) {
        notifications.push(this.formatNotification(parsed));
      }
    }
    return notifications;
  }
}

export const nftSentinel = new NftSentinel();
