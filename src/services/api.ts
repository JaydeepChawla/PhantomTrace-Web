import type {
  ProcessItem,
  ThreatAlert,
  ScanOverview,
  ScanHistoryItem,
  ReportItem,
  SystemSettings
} from '../types';
import {
  mockOverview,
  mockProcesses,
  mockThreatAlerts,
  mockScanHistory,
  mockReports,
  mockSettings,
  mockThreatActivityTimeline
} from '../data/mockData';

/**
 * =====================================================================
 * PHANTOMTRACE SERVICE LAYER (API ARCHITECTURE)
 * =====================================================================
 * This service layer serves as the single source of truth for the
 * React frontend.
 *
 * Target Telemetry Pipeline:
 *   PhantomTrace Windows EXE
 *           ↓
 *   scan_results.json
 *           ↓
 *   PhantomTrace REST API (e.g. POST /v1/telemetry/ingest)
 *           ↓
 *   Firebase Cloud Firestore / Realtime Store
 *           ↓
 *   PhantomTrace Web Platform (api.ts / firebase.ts)
 *
 * TODO: Replace internal development provider with live fetch calls to
 * PhantomTrace REST API when backend service is deployed.
 * =====================================================================
 */

export const API_CONFIG = {
  // TODO: Read from import.meta.env.VITE_PHANTOMTRACE_API_URL when live
  baseUrl: 'https://api.phantomtrace.security/v1',
  timeoutMs: 8000,
  isLiveConnectionConfigured: false,
};

class PhantomTraceApiService {
  /**
   * Fetch current scan overview metrics and global system risk state.
   */
  async getScanOverview(): Promise<ScanOverview> {
    // TODO: Connect to REST API endpoint: GET /api/v1/scan/overview
    // Example:
    // const res = await fetch(`${API_CONFIG.baseUrl}/scan/overview`);
    // return await res.json();
    return new Promise((resolve) => {
      setTimeout(() => resolve({ ...mockOverview }), 150);
    });
  }

  /**
   * Fetch list of all active inspected processes.
   */
  async getProcesses(): Promise<ProcessItem[]> {
    // TODO: Connect to REST API endpoint: GET /api/v1/processes
    // or Firebase Firestore collection: collection(db, 'processes')
    return new Promise((resolve) => {
      setTimeout(() => resolve([...mockProcesses]), 200);
    });
  }

  /**
   * Fetch detailed telemetry and forensic evidence for a specific process by PID.
   */
  async getProcessByPid(pid: number): Promise<ProcessItem | null> {
    // TODO: Connect to REST API endpoint: GET /api/v1/processes/:pid
    // or Firebase Firestore: doc(db, 'processes', pid.toString())
    return new Promise((resolve) => {
      setTimeout(() => {
        const found = mockProcesses.find((p) => p.pid === pid);
        resolve(found ? { ...found } : null);
      }, 150);
    });
  }

  /**
   * Fetch active threat alerts with score modes and evidence vectors.
   */
  async getThreatAlerts(): Promise<ThreatAlert[]> {
    // TODO: Connect to REST API endpoint: GET /api/v1/alerts
    return new Promise((resolve) => {
      setTimeout(() => resolve([...mockThreatAlerts]), 180);
    });
  }

  /**
   * Fetch historical scan records.
   */
  async getScanHistory(): Promise<ScanHistoryItem[]> {
    // TODO: Connect to REST API endpoint: GET /api/v1/history
    return new Promise((resolve) => {
      setTimeout(() => resolve([...mockScanHistory]), 180);
    });
  }

  /**
   * Fetch activity timeline data for visualization charts.
   */
  async getThreatActivityTimeline(): Promise<typeof mockThreatActivityTimeline> {
    // TODO: Connect to REST API endpoint: GET /api/v1/analytics/activity-timeline
    return new Promise((resolve) => {
      setTimeout(() => resolve([...mockThreatActivityTimeline]), 150);
    });
  }

  /**
   * Fetch pre-generated reports (scan_results.json, validation report, alert history).
   */
  async getReports(): Promise<ReportItem[]> {
    // TODO: Connect to REST API or Firebase Storage bucket for report downloads
    return new Promise((resolve) => {
      setTimeout(() => resolve([...mockReports]), 200);
    });
  }

  /**
   * Fetch single report item by id or file name.
   */
  async getReportByName(name: string): Promise<ReportItem | null> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const item = mockReports.find((r) => r.name === name);
        resolve(item ? { ...item } : null);
      }, 120);
    });
  }

  /**
   * Fetch platform configuration and subsystem status.
   */
  async getSettings(): Promise<SystemSettings> {
    // TODO: Connect to REST API endpoint: GET /api/v1/settings
    return new Promise((resolve) => {
      setTimeout(() => resolve({ ...mockSettings }), 150);
    });
  }

  /**
   * Update settings (mocked save, ready for backend PUT /api/v1/settings).
   */
  async updateSettings(updated: Partial<SystemSettings>): Promise<SystemSettings> {
    // TODO: Connect to REST API endpoint: PUT /api/v1/settings
    return new Promise((resolve) => {
      setTimeout(() => {
        const merged = { ...mockSettings, ...updated };
        resolve(merged);
      }, 300);
    });
  }

  /**
   * Diagnostic connection ping to test REST API connectivity.
   */
  async testApiConnection(endpointUrl: string): Promise<{ success: boolean; message: string; latencyMs: number }> {
    // TODO: Perform real ping to backend healthcheck: GET ${endpointUrl}/health
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          message: `Endpoint reachable (${endpointUrl || API_CONFIG.baseUrl}). Status: Awaiting telemetry ingestion payload stream.`,
          latencyMs: 38
        });
      }, 500);
    });
  }
}

export const apiService = new PhantomTraceApiService();
