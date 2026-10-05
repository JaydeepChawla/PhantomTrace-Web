import { useState, useEffect, useCallback } from 'react';
import { dataService } from '../services';
import type { ScanOverview, ThreatAlert, ScanHistory, Report } from '../types';

const TELEMETRY_REFRESH_EVENT = 'phantomtrace:telemetry-refresh';

export function useThreatData() {
  const [overview, setOverview] = useState<ScanOverview | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [activityTimeline, setActivityTimeline] = useState<
    Array<{ time: string; totalInspected: number; elevatedThreats: number; avgScore: number }>
  >([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTelemetry = useCallback(async (isInitial = false) => {
    if (isInitial) {
      setLoading(true);
    }
    try {
      const [overviewData, alertsData, historyData, reportsData, timelineData] = await Promise.all([
        dataService.getScanOverview ? dataService.getScanOverview() : null,
        dataService.getThreatAlerts(),
        dataService.getScanHistory(),
        dataService.getReports(),
        dataService.getThreatActivityTimeline ? dataService.getThreatActivityTimeline() : [],
      ]);

      setError(null);

      if (overviewData) setOverview(overviewData as ScanOverview);
      setAlerts(alertsData);
      setHistory(historyData);
      setReports(reportsData);
      if (timelineData) setActivityTimeline(timelineData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch security telemetry');
    } finally {
      if (isInitial) {
        setLoading(false);
      }
    }
  }, []);

  const refreshData = useCallback(async () => {
    await fetchTelemetry(false);
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(TELEMETRY_REFRESH_EVENT));
    }
  }, [fetchTelemetry]);

  useEffect(() => {
    let active = true;

    // Initial telemetry fetch (loading is already true by default)
    fetchTelemetry(false);

    // Cross-component synchronizer (Sync button in Header, etc.)
    const handleGlobalRefresh = () => {
      if (active) {
        fetchTelemetry(false);
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener(TELEMETRY_REFRESH_EVENT, handleGlobalRefresh);
    }

    // Lightweight automatic polling every 45 seconds while dashboard is open
    const pollTimer = window.setInterval(() => {
      if (active && typeof document !== 'undefined' && document.visibilityState !== 'hidden') {
        fetchTelemetry(false);
      }
    }, 45000);

    return () => {
      active = false;
      window.clearInterval(pollTimer);
      if (typeof window !== 'undefined') {
        window.removeEventListener(TELEMETRY_REFRESH_EVENT, handleGlobalRefresh);
      }
    };
  }, [fetchTelemetry]);

  return {
    overview,
    alerts,
    history,
    reports,
    activityTimeline,
    loading,
    error,
    refreshData,
  };
}
