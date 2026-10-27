'use client';

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  FALLBACK_ASSET_RATES,
  type AssetFiatRates,
  type CurrencyCode,
  fetchAssetFiatRates,
} from './currency';

const STORAGE_KEY = 'stellar-alerts.display-currency';

interface CurrencyPreferenceValue {
  currency: CurrencyCode;
  setCurrency: (currency: CurrencyCode) => void;
  rates: AssetFiatRates;
  rateStatus: 'loading' | 'live' | 'fallback';
}

const defaultValue: CurrencyPreferenceValue = {
  currency: 'XLM',
  setCurrency: () => undefined,
  rates: FALLBACK_ASSET_RATES,
  rateStatus: 'loading',
};

const CurrencyPreferenceContext = createContext(defaultValue);

export function CurrencyPreferenceProvider({ children }: { children: React.ReactNode }) {
  const [currency, setCurrencyState] = useState<CurrencyCode>('XLM');
  const [rates, setRates] = useState<AssetFiatRates>(FALLBACK_ASSET_RATES);
  const [rateStatus, setRateStatus] = useState<CurrencyPreferenceValue['rateStatus']>('loading');

  useEffect(() => {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === 'XLM' || saved === 'USD' || saved === 'EUR' || saved === 'GBP') {
      setCurrencyState(saved);
    }

    let active = true;
    fetchAssetFiatRates()
      .then((nextRates) => {
        if (!active) return;
        setRates(nextRates);
        setRateStatus('live');
      })
      .catch(() => {
        if (active) setRateStatus('fallback');
      });
    return () => {
      active = false;
    };
  }, []);

  const setCurrency = useCallback((next: CurrencyCode) => {
    setCurrencyState(next);
    window.localStorage.setItem(STORAGE_KEY, next);
  }, []);

  const value = useMemo(() => ({ currency, setCurrency, rates, rateStatus }), [currency, setCurrency, rates, rateStatus]);
  return <CurrencyPreferenceContext.Provider value={value}>{children}</CurrencyPreferenceContext.Provider>;
}

export function useCurrencyPreference() {
  return useContext(CurrencyPreferenceContext);
}
