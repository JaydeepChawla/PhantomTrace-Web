import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { ThreatAlertsPage } from './pages/ThreatAlertsPage';
import { AlertInvestigationPage } from './pages/AlertInvestigationPage';
import { ProcessesPage } from './pages/ProcessesPage';
import { ProcessDetailsPage } from './pages/ProcessDetailsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing Page Route */}
        <Route path="/" element={<LandingPage />} />

        {/* Core Operations Console Routes with Sidebar & Header Layout */}
        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/alerts" element={<ThreatAlertsPage />} />
          <Route path="/alerts/:id" element={<AlertInvestigationPage />} />
          <Route path="/processes" element={<ProcessesPage />} />
          <Route path="/processes/:pid" element={<ProcessDetailsPage />} />
          <Route path="/history" element={<ScanHistoryPage />} />
          <Route path="/scan-history" element={<ScanHistoryPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        {/* Fallback route */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
