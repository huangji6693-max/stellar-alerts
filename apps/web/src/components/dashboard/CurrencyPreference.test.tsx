import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { CurrencyPreferenceProvider } from './CurrencyPreference';
import { DashboardHeader } from './DashboardHeader';
import { SummaryStats } from './SummaryStats';

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

describe('dashboard currency preference', () => {
  it('shares the header choice with dashboard cards and persists it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    render(
      <CurrencyPreferenceProvider>
        <DashboardHeader />
        <SummaryStats totalPaymentsCount={2} totalVolumeXLM={10} activeWalletsCount={1} />
      </CurrencyPreferenceProvider>,
    );

    const picker = screen.getByRole('combobox', { name: 'Display currency' });
    fireEvent.change(picker, { target: { value: 'GBP' } });
    expect(picker).toHaveValue('GBP');
    expect(window.localStorage.getItem('stellar-alerts.display-currency')).toBe('GBP');
    expect(await screen.findByText('£0.95')).toBeInTheDocument();
    expect(await screen.findByText('Fallback rates')).toBeInTheDocument();
  });

  it('restores a supported saved currency when mounted', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    window.localStorage.setItem('stellar-alerts.display-currency', 'EUR');
    render(
      <CurrencyPreferenceProvider>
        <DashboardHeader />
      </CurrencyPreferenceProvider>,
    );

    expect(await screen.findByRole('combobox', { name: 'Display currency' })).toHaveValue('EUR');
  });
});
