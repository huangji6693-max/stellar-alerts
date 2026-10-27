import { describe, expect, it } from 'vitest';
import {
  FALLBACK_XLM_RATES,
  FALLBACK_ASSET_RATES,
  convertXlmAmount,
  convertAssetAmount,
  formatAssetAmount,
  fetchXlmFiatRates,
  fetchAssetFiatRates,
  formatCurrencyAmount,
} from './currency';

describe('currency helpers', () => {
  it('converts XLM amounts into the selected fiat currency', () => {
    const rates = { ...FALLBACK_XLM_RATES, USD: 0.1234, EUR: 0.1, GBP: 0.08 };

    expect(convertXlmAmount(250, 'USD', rates)).toBe(30.85);
    expect(convertXlmAmount(250, 'EUR', rates)).toBe(25);
    expect(convertXlmAmount(250, 'XLM', rates)).toBe(250);
  });

  it('formats fiat and XLM display values', () => {
    expect(formatCurrencyAmount(1200.5, 'XLM')).toContain('1,200.50 XLM');
    expect(formatCurrencyAmount(12.3, 'USD')).toBe('$12.30');
  });

  it('normalizes CoinGecko simple price responses', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stellar: { usd: 0.2, eur: 0.18, gbp: 0.16 },
        'usd-coin': { usd: 1, eur: 0.91, gbp: 0.79 },
        'euro-coin': { usd: 1.08, eur: 1, gbp: 0.86 },
      }),
    });

    await expect(fetchXlmFiatRates(fetcher as unknown as typeof fetch)).resolves.toEqual({
      XLM: 1,
      USD: 0.2,
      EUR: 0.18,
      GBP: 0.16,
    });
  });

  it('fetches and converts XLM, USDC, and EURC with per-asset quotes', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stellar: { usd: 0.2, eur: 0.18, gbp: 0.16 },
        'usd-coin': { usd: 1, eur: 0.91, gbp: 0.79 },
        'euro-coin': { usd: 1.08, eur: 1, gbp: 0.86 },
      }),
    });
    const rates = await fetchAssetFiatRates(fetcher as unknown as typeof fetch);

    expect(fetcher).toHaveBeenCalledWith(expect.stringContaining('ids=stellar,usd-coin,euro-coin'));
    expect(convertAssetAmount(12.5, 'XLM', 'EUR', rates)).toBe(2.25);
    expect(convertAssetAmount(12.5, 'USDC', 'GBP', rates)).toBe(9.88);
    expect(convertAssetAmount(12.5, 'EURC', 'USD', rates)).toBe(13.5);
    expect(convertAssetAmount(12.5, 'UNKNOWN', 'USD', rates)).toBeNull();
    expect(formatAssetAmount(12.5, 'USDC', 'GBP', rates)).toBe('£9.88');
    expect(formatAssetAmount(12.5, 'UNKNOWN', 'USD', rates)).toBe('12.50 UNKNOWN');
    expect(FALLBACK_ASSET_RATES.USDC.USD).toBe(1);
  });

  it('uses fallback quotes when an asset is missing from a valid response', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ stellar: { usd: 0.2 } }),
    });
    const rates = await fetchAssetFiatRates(fetcher as unknown as typeof fetch);
    expect(rates.USDC).toEqual(FALLBACK_ASSET_RATES.USDC);
    expect(rates.EURC).toEqual(FALLBACK_ASSET_RATES.EURC);
  });

  it('caches live rates for five minutes and refreshes after the TTL', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stellar: { usd: 0.2, eur: 0.18, gbp: 0.16 },
        'usd-coin': { usd: 1, eur: 0.91, gbp: 0.79 },
        'euro-coin': { usd: 1.08, eur: 1, gbp: 0.86 },
      }),
    });
    let now = 1000;
    const clock = () => now;

    await fetchAssetFiatRates(fetcher as unknown as typeof fetch, clock);
    await fetchAssetFiatRates(fetcher as unknown as typeof fetch, clock);
    expect(fetcher).toHaveBeenCalledTimes(1);

    now += 5 * 60 * 1000 + 1;
    await fetchAssetFiatRates(fetcher as unknown as typeof fetch, clock);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
