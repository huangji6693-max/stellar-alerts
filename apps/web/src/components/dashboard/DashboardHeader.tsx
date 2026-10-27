import React from 'react';
import { CURRENCY_OPTIONS } from './currency';
import { useCurrencyPreference } from './CurrencyPreference';

/** Hero banner shown at the top of the dashboard. */
export const DashboardHeader: React.FC = () => {
  const { currency, setCurrency } = useCurrencyPreference();
  return (
    <div className="p-5 sm:p-8 rounded-3xl bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-purple-950/20 border border-cyan-500/20 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative overflow-hidden">
      <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl -mr-32 -mt-32 pointer-events-none"></div>
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold mb-3">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          Watcher Service Active
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Your Real-Time Wallet Dashboard</h1>
        <p className="text-gray-400 text-sm mt-1 max-w-xl">
          Monitor connected Stellar Testnet addresses, track live incoming transactions, and export recorded payment history.
        </p>
      </div>
      <label className="flex items-center gap-3 text-sm font-medium text-slate-300">
        <span>Display currency</span>
        <select
          aria-label="Display currency"
          data-testid="dashboard-currency-select"
          value={currency}
          onChange={(event) => setCurrency(event.target.value as typeof currency)}
          className="rounded-lg border border-cyan-500/30 bg-slate-950/80 px-3 py-2 text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
        >
          {CURRENCY_OPTIONS.map((option) => (
            <option key={option.code} value={option.code}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
};
