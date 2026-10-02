import { useState, useEffect, useCallback } from 'react';
import { dataService } from '../services';
import type { ScanOverview, ThreatAlert, ScanHistory, Report } from '../types';

export function useThreatData() {
  const [overview, setOverview] = useState<ScanOverview | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [activityTimeline, setActivityTimeline] = useState<Array<{ time: string; totalInspected: number; elevatedThreats: number; avgScore: number }>>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const refreshData = useCallback(async () => {
    try {
      setError(null);
      const [overviewData, alertsData, historyData, reportsData, timelineData] = await Promise.all([
        dataService.getScanOverview ? dataService.getScanOverview() : null,
        dataService.getThreatAlerts(),
        dataService.getScanHistory(),
        dataService.getReports(),
        dataService.getThreatActivityTimeline ? dataService.getThreatActivityTimeline() : [],
      ]);

      if (overviewData) setOverview(overviewData as ScanOverview);
      setAlerts(alertsData);
      setHistory(historyData);
      setReports(reportsData);
      if (timelineData) setActivityTimeline(timelineData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch security telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      dataService.getScanOverview ? dataService.getScanOverview() : null,
      dataService.getThreatAlerts(),
      dataService.getScanHistory(),
      dataService.getReports(),
      dataService.getThreatActivityTimeline ? dataService.getThreatActivityTimeline() : [],
    ]).then(([overviewData, alertsData, historyData, reportsData, timelineData]) => {
      if (active) {
        if (overviewData) setOverview(overviewData as ScanOverview);
        setAlerts(alertsData);
        setHistory(historyData);
        setReports(reportsData);
        if (timelineData) setActivityTimeline(timelineData);
        setLoading(false);
      }
    }).catch((err) => {
      if (active) {
        setError(err instanceof Error ? err.message : 'Failed to fetch security telemetry');
        setLoading(false);
      }
    });

    return () => {
      active = false;
    };
  }, []);

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
