import type {
  Process,
  ThreatAlert,
  ScanResult,
  ScanHistory,
  Report,
  ScanOverview,
  SystemSettings,
} from "../types";

/**
 * PhantomTrace Data Service Interface
 *
 * Defines the contract for acquiring forensic endpoint telemetry, threat alerts,
 * historical scan runs, and analyst reports.
 *
 * The dashboard interacts exclusively with this interface, maintaining complete
 * isolation from data sources (local fixture vs. live REST API vs. cloud store).
 */
export interface PhantomTraceDataService {
  /**
   * Enumerate all active host processes inspected by PhantomTrace.
   */
  getProcesses(): Promise<Process[]>;

  /**
   * Retrieve detailed forensic telemetry and evidence for a specific process by PID.
   */
  getProcess(pid: number): Promise<Process | null>;

  /**
   * Enumerate elevated threat alerts identified during scanning.
   */
  getThreatAlerts(): Promise<ThreatAlert[]>;

  /**
   * Retrieve a specific threat alert by its identifier.
   */
  getThreatAlert(id: string): Promise<ThreatAlert | null>;

  /**
   * Update the analyst investigation lifecycle status for a specific threat alert.
   * Modifies only dashboard triage state; does not alter endpoint state.
   */
  updateAlertStatus?(id: string, status: ThreatAlert["status"]): Promise<ThreatAlert | null>;

  /**
   * Retrieve chronological scan run records.
   */
  getScanHistory(): Promise<ScanHistory[]>;

  /**
   * Retrieve full result payload for a specific scan session.
   */
  getScanResult(scanId?: string): Promise<ScanResult | null>;

  /**
   * Retrieve available forensic exports and reports.
   */
  getReports(): Promise<Report[]>;

  /**
   * Retrieve a specific report by its identifier.
   */
  getReport(id: string): Promise<Report | null>;

  /**
   * Retrieve a specific report by its file name (e.g. 'scan_results.json').
   */
  getReportByName?(name: string): Promise<Report | null>;

  /**
   * Fetch system-wide scan overview metrics.
   */
  getScanOverview(): Promise<ScanOverview | ScanResult>;

  /**
   * Fetch activity timeline data points for risk visualization.
   */
  getThreatActivityTimeline(): Promise<Array<{ time: string; totalInspected: number; elevatedThreats: number; avgScore: number }>>;

  /**
   * Fetch platform configuration and subsystem parameters.
   */
  getSettings(): Promise<SystemSettings>;

  /**
   * Update platform configuration settings.
   */
  updateSettings(updated: Partial<SystemSettings>): Promise<SystemSettings>;

  /**
   * Run diagnostic ping to verify endpoint connectivity.
   */
  testApiConnection(endpointUrl: string): Promise<{ success: boolean; message: string; latencyMs: number }>;
}

// TODO Phase 3:
// Implement ApiDataService using PhantomTrace API.
// Dashboard pages must continue using PhantomTraceDataService
// without knowing whether the source is local or remote.
