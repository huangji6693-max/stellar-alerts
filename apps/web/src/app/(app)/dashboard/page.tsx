'use client';

import { useCallback } from 'react';
import NetworkVisualizer3D from '@/components/dashboard/NetworkVisualizer3D';
import AuditWorkspace from '@/components/dashboard/AuditWorkspace';
import { useSession } from 'next-auth/react';
import type { PathPaymentFlow } from '@/components/dashboard';
import { WatcherForm } from '@/components/WatcherForm';
import {
  DashboardGrid,
  DashboardHeader,
  DeliveryToast,
  SummaryStats,
  VolumeChart,
  WebhookSandbox,
  WalletList,
  EmptyWatchersState,
  PaymentTable,
  ActivityHeatmap,
  EmailTemplatePreview,
  SankeyFlowDiagram,
} from '@/components/dashboard';
import { useDashboardData } from '@/hooks/useDashboardData';
import { useLiveDashboardStream } from '@/hooks/useLiveDashboardStream';
import { useEmailTemplatePreference } from '@/hooks/useEmailTemplatePreference';
import { CurrencyPreferenceProvider } from '@/components/dashboard/CurrencyPreference';

// Multi-hop path payment routes. The ingestion worker does not yet record
// path_payment_* offer chains, so this stays empty until a path-flows feed
// is available; the Sankey card renders its own empty state meanwhile.
const PATH_PAYMENT_FLOWS: PathPaymentFlow[] = [];

export default function DashboardPage() {
  const { data: session } = useSession();
  const {
    wallets,
    payments,
    selectedWalletId,
    setSelectedWalletId,
    isLoadingPayments,
    hasLoadedPortfolio,
    totalPaymentsCount,
    totalVolumeXLM,
    applyLivePayment,
    refreshAfterMutation,
    removeWallet,
  } = useDashboardData();
  const { isStreamConnected, latestDelivery } = useLiveDashboardStream(
    session?.accessToken,
    selectedWalletId,
    applyLivePayment,
  );
  const {
    template: savedEmailTemplate,
    saveTemplate: saveEmailTemplate,
  } = useEmailTemplatePreference(session?.accessToken);

  // The Add Wallet flow is the watcher form below the grid, not a modal, so
  // "open it" means scroll it into view and put the cursor in its first field.
  const openAddWalletForm = useCallback(() => {
    const section = document.getElementById('add-wallet-section');
    if (!section) return;
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    section.querySelector<HTMLInputElement>('#address')?.focus({ preventScroll: true });
  }, []);

  return (
    <CurrencyPreferenceProvider>
    <div className="min-w-0 space-y-8">
      <DeliveryToast delivery={latestDelivery} />

      <DashboardHeader />

      {/* Onboarding card: renders only while the user has no wallets. */}
      {hasLoadedPortfolio && (
        <EmptyWatchersState walletCount={wallets.length} onAddWallet={openAddWalletForm} />
      )}

      {/* Customizable Dashboard Grid */}
      <DashboardGrid
        items={[
          {
            id: 'summary',
            label: 'Summary Overview',
            content: (
              <SummaryStats
                totalPaymentsCount={totalPaymentsCount}
                totalVolumeXLM={totalVolumeXLM}
                activeWalletsCount={wallets.length}
              />
            ),
          },
          {
            id: 'volume-chart',
            label: 'Currency Volume',
            content: (
              <VolumeChart
                payments={payments}
                totalVolumeXLM={totalVolumeXLM}
              />
            ),
          },
          {
            id: 'activity-heatmap',
            label: 'Activity Heatmap',
            content: <ActivityHeatmap payments={payments} />,
          },
          {
            id: 'email-template-preview',
            label: 'Email Receipt Template',
            content: (
              <EmailTemplatePreview
                initialTemplate={savedEmailTemplate ?? undefined}
                onSaveTemplate={saveEmailTemplate}
              />
            ),
          },
          {
            id: 'webhook-sandbox',
            label: 'Webhook Sandbox',
            content: <WebhookSandbox />,
          },
          // Hidden at zero wallets: the onboarding card above already explains
          // the empty table, so showing both would be two competing CTAs.
          ...(wallets.length > 0
            ? [
                {
                  id: 'wallets',
                  label: 'Monitored Wallets',
                  content: (
                    <WalletList
                      wallets={wallets}
                      selectedWalletId={selectedWalletId}
                      onSelectWallet={setSelectedWalletId}
                      onRemoveWallet={removeWallet}
                      onOpenAddModal={openAddWalletForm}
                    />
                  ),
                },
              ]
            : []),
          {
            id: 'watcher-and-payments',
            label: 'Watcher & Payment Ledger',
            content: (
              <div id="add-wallet-section" className="min-w-0 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                <div className="min-w-0 lg:col-span-4 bg-[#0c0c14]/80 backdrop-blur-md rounded-3xl border border-white/10 p-7 shadow-2xl hover:border-cyan-500/30 transition-all duration-500">
                  <WatcherForm onWalletAdded={refreshAfterMutation} isStreamConnected={isStreamConnected} />
                </div>
                <div className="min-w-0 lg:col-span-8">
                  <PaymentTable payments={payments} isLoading={isLoadingPayments} />
                </div>
              </div>
            ),
          },
          {
            id: 'network-visualizer',
            label: 'Live Payment Stream Network',
            content: <NetworkVisualizer3D payments={payments} />,
          },
          {
            id: 'audit-workspace',
            label: 'Collaborative Audit Workspace',
            content: (
              <AuditWorkspace
                payments={payments}
                currentUser={{
                  id: session?.user?.id || session?.user?.email || 'anonymous',
                  name: session?.user?.name || session?.user?.email || 'Auditor',
                }}
              />
            ),
          },
          {
            id: 'sankey-flows',
            label: 'Multi-Hop Payment Flows',
            content: <SankeyFlowDiagram flows={PATH_PAYMENT_FLOWS} />,
          },
        ]}
      />
    </div>
    </CurrencyPreferenceProvider>
  );
}
