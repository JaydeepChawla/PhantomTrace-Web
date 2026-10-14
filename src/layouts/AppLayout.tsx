import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/layout/Sidebar';
import { Header } from '../components/layout/Header';
import { useThreatData } from '../hooks/useThreatData';

export const AppLayout: React.FC = () => {
  const { overview, refreshData, loading } = useThreatData();
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  return (
    <div className="pt-app-layout">
      {/* Universal Skip-to-Content Link for Keyboard Accessibility (WCAG 2.2 AA) */}
      <a href="#main-content" className="pt-skip-link">
        Skip to main content
      </a>

      {/* Mobile Sidebar Backdrop Overlay */}
      {isMobileNavOpen && (
        <div
          className="pt-sidebar-backdrop"
          onClick={() => setIsMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Primary Sidebar Navigation (Desktop, Tablet Rail & Mobile Drawer) */}
      <Sidebar
        threatAlertsCount={overview?.threatAlertsCount ?? 6}
        isOpenMobile={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />

      {/* Main Content Area */}
      <div className="pt-main-content-wrapper">
        <Header
          onRefresh={refreshData}
          isRefreshing={loading}
          isMobileNavOpen={isMobileNavOpen}
          onToggleMobileNav={() => setIsMobileNavOpen((prev) => !prev)}
        />

        <main id="main-content" className="pt-page-body" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default AppLayout;
