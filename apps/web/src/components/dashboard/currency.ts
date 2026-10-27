export type FiatCurrencyCode = 'USD' | 'EUR' | 'GBP';
export type CurrencyCode = 'XLM' | FiatCurrencyCode;
export type TrackedAssetCode = 'XLM' | 'USDC' | 'EURC';

export interface CurrencyOption {
  code: CurrencyCode;
  label: string;
  symbol: string;
}

export const CURRENCY_OPTIONS: CurrencyOption[] = [
  { code: 'XLM', label: 'Native (XLM)', symbol: 'XLM' },
  { code: 'USD', label: 'USD', symbol: '$' },
  { code: 'EUR', label: 'EUR', symbol: '€' },
  { code: 'GBP', label: 'GBP', symbol: '£' },
];

export const FALLBACK_XLM_RATES: Record<CurrencyCode, number> = {
  XLM: 1,
  USD: 0.12,
  EUR: 0.11,
  GBP: 0.095,
};

export type AssetFiatRates = Record<TrackedAssetCode, Record<FiatCurrencyCode, number>>;

export const FALLBACK_ASSET_RATES: AssetFiatRates = {
  XLM: { USD: 0.12, EUR: 0.11, GBP: 0.095 },
  USDC: { USD: 1, EUR: 0.92, GBP: 0.79 },
  EURC: { USD: 1.08, EUR: 1, GBP: 0.86 },
};

export const RATE_CACHE_TTL_MS = 5 * 60 * 1000;

type CoinGeckoSimplePrice = Record<
  'stellar' | 'usd-coin' | 'euro-coin',
  Partial<Record<Lowercase<FiatCurrencyCode>, number>> | undefined
>;

function normalizeRate(value: unknown, fallback: number): number {
  const rate = Number(value);
  return Number.isFinite(rate) && rate > 0 ? rate : fallback;
}

export async function fetchXlmFiatRates(
  fetcher: typeof fetch = fetch
): Promise<Record<CurrencyCode, number>> {
  const assets = await fetchAssetFiatRates(fetcher);

  return { XLM: 1, ...assets.XLM };
}

const cachedRates = new WeakMap<typeof fetch, { value: AssetFiatRates; fetchedAt: number }>();
const pendingRates = new WeakMap<typeof fetch, Promise<AssetFiatRates>>();

/** Fetch prices for supported Stellar assets and cache them for five minutes. */
export async function fetchAssetFiatRates(
  fetcher: typeof fetch = fetch,
  now: () => number = Date.now,
): Promise<AssetFiatRates> {
  const cached = cachedRates.get(fetcher);
  if (cached && now() - cached.fetchedAt < RATE_CACHE_TTL_MS) return cached.value;
  const pending = pendingRates.get(fetcher);
  if (pending) return pending;

  const request = async (): Promise<AssetFiatRates> => {
    const response = await fetcher(
      'https://api.coingecko.com/api/v3/simple/price?ids=stellar,usd-coin,euro-coin&vs_currencies=usd,eur,gbp'
    );
    if (!response.ok) throw new Error(`CoinGecko rate request failed with ${response.status}`);

    const data = (await response.json()) as CoinGeckoSimplePrice;
    return {
      XLM: {
        USD: normalizeRate(data.stellar?.usd, FALLBACK_ASSET_RATES.XLM.USD),
        EUR: normalizeRate(data.stellar?.eur, FALLBACK_ASSET_RATES.XLM.EUR),
        GBP: normalizeRate(data.stellar?.gbp, FALLBACK_ASSET_RATES.XLM.GBP),
      },
      USDC: {
        USD: normalizeRate(data['usd-coin']?.usd, FALLBACK_ASSET_RATES.USDC.USD),
        EUR: normalizeRate(data['usd-coin']?.eur, FALLBACK_ASSET_RATES.USDC.EUR),
        GBP: normalizeRate(data['usd-coin']?.gbp, FALLBACK_ASSET_RATES.USDC.GBP),
      },
      EURC: {
        USD: normalizeRate(data['euro-coin']?.usd, FALLBACK_ASSET_RATES.EURC.USD),
        EUR: normalizeRate(data['euro-coin']?.eur, FALLBACK_ASSET_RATES.EURC.EUR),
        GBP: normalizeRate(data['euro-coin']?.gbp, FALLBACK_ASSET_RATES.EURC.GBP),
      },
    };
  };

  const result = request();
  pendingRates.set(fetcher, result);
  try {
    const value = await result;
    cachedRates.set(fetcher, { value, fetchedAt: now() });
    return value;
  } finally {
    pendingRates.delete(fetcher);
  }
}

export function convertAssetAmount(
  amount: number,
  asset: string | null | undefined,
  currency: CurrencyCode,
  rates: AssetFiatRates = FALLBACK_ASSET_RATES,
): number | null {
  const code = (asset ?? 'XLM').toUpperCase();
  if (currency === 'XLM') return code === 'XLM' ? amount : null;
  if (code !== 'XLM' && code !== 'USDC' && code !== 'EURC') return null;
  const value = amount * rates[code][currency];
  return Math.round(value * 100) / 100;
}

export function formatAssetAmount(
  amount: number,
  asset: string | null | undefined,
  currency: CurrencyCode,
  rates: AssetFiatRates = FALLBACK_ASSET_RATES,
): string {
  const converted = convertAssetAmount(amount, asset, currency, rates);
  if (converted !== null) return formatCurrencyAmount(converted, currency);
  return `${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${(asset ?? 'XLM').toUpperCase()}`;
}

export function convertXlmAmount(
  amountXlm: number,
  currency: CurrencyCode,
  rates: Record<CurrencyCode, number> = FALLBACK_XLM_RATES
): number {
  const rate = rates[currency] ?? FALLBACK_XLM_RATES[currency] ?? 1;
  const converted = amountXlm * rate;
  return Math.round(converted * 100) / 100;
}

export function formatCurrencyAmount(amount: number, currency: CurrencyCode): string {
  if (currency === 'XLM') {
    return `${amount.toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })} XLM`;
  }

  return new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
}
