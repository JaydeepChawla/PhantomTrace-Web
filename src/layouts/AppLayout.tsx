import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/layout/Sidebar';
import { Header } from '../components/layout/Header';
import { useThreatData } from '../hooks/useThreatData';

export const AppLayout: React.FC = () => {
  const { overview, refreshData, loading } = useThreatData();

  return (
    <div className="pt-app-layout">
      {/* Desktop & Collapsed Sidebar */}
      <Sidebar threatAlertsCount={overview?.threatAlertsCount ?? 6} />

      {/* Main Content Area */}
      <div className="pt-main-content-wrapper">
        <Header onRefresh={refreshData} isRefreshing={loading} />

        <main className="pt-page-body">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
