import type {
  Process,
  ThreatAlert,
  ScanResult,
  ScanHistory,
  Report,
  ScanOverview,
  SystemSettings,
  ThreatLevel,
  ScoreMode,
} from "../types";
import type { PhantomTraceDataService } from "./dataService";
import {
  mockOverview,
  mockProcesses,
  mockThreatAlerts,
  mockScanHistory,
  mockReports,
  mockSettings,
  mockThreatActivityTimeline,
} from "../data/mockData";

function normalizeThreatLevel(level?: string): ThreatLevel {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    case 'LOW':
      return 'LOW';
    case 'NORMAL':
    case 'CLEAN':
    default:
      return 'NORMAL';
  }
}

function normalizeScoreMode(mode?: string): ScoreMode {
  switch (mode?.toUpperCase()) {
    case 'CORRELATED':
      return 'CORRELATED';
    case 'MEMORY ONLY':
    case 'MEMORY_ONLY':
      return 'MEMORY_ONLY';
    case 'BEHAVIOR ONLY':
    case 'BEHAVIOR_ONLY':
      return 'BEHAVIOR_ONLY';
    case 'BASELINE':
    case 'BASELINE_ADJUSTED':
      return 'BASELINE_ADJUSTED';
    default:
      return 'NONE';
  }
}

/**
 * Local PhantomTrace Data Service Implementation
 *
 * Implements the PhantomTraceDataService contract backed by local forensic
 * mock data structures. Serves as the primary data provider for Phase 2.2,
 * decoupling the UI from direct mock imports.
 */
export class LocalDataService implements PhantomTraceDataService {
  /**
   * Enumerate all active host processes inspected by PhantomTrace.
   */
  async getProcesses(): Promise<Process[]> {
    return new Promise((resolve) => {
      setTimeout(() => {
        // Map mock processes ensuring all Phase 2.1 Process fields and presentation fields are populated
        const mapped: Process[] = mockProcesses.map((p) => ({
          ...p,
          executablePath: p.path,
          applicationName: p.application,
          threatLevel: normalizeThreatLevel(p.threatLevel),
          scoreMode: normalizeScoreMode(p.scoreMode),
          correlationScore: p.threatScore,
          memoryEvidence: {
            present: p.memoryEvidenceCount > 0,
            strength: p.threatScore >= 90 ? "HIGH" : p.threatScore >= 50 ? "MEDIUM" : "LOW",
            indicators: p.memoryIndicators,
            suspiciousRegions: p.memoryEvidenceCount,
            scanStatus: "SCANNED",
            accessDenied: false,
            details: p.memoryEvidence.map((m) => m.details),
            timestamp: p.timestamp,
          },
          behaviorEvidence: {
            present: p.behaviorEvidenceCount > 0,
            score: p.behaviorScore,
            indicators: p.behaviorEvidence.map((b) => b.description),
            suspiciousCommandLine: p.commandLine.includes("-W Hidden") || p.commandLine.includes("-enc"),
            suspiciousParent: p.parentName === "wscript.exe",
            commandLine: p.commandLine,
            parentProcess: p.parentName,
            details: p.behaviorEvidence.map((b) => b.description),
            timestamp: p.timestamp,
          },
          correlationEvidence: {
            present: Boolean(p.correlationSummary),
            score: p.threatScore,
            memoryEvidencePresent: p.memoryEvidenceCount > 0,
            behaviorEvidencePresent: p.behaviorEvidenceCount > 0,
            correlatedIndicators: [...p.memoryIndicators],
            explanation: p.correlationSummary,
            timestamp: p.timestamp,
          },
          detailedMemoryEvidence: p.memoryEvidence,
          detailedBehaviorEvidence: p.behaviorEvidence,
        }));
        resolve(mapped);
      }, 120);
    });
  }

  /**
   * Retrieve detailed telemetry and forensic evidence for a specific process by PID.
   */
  async getProcess(pid: number): Promise<Process | null> {
    const list = await this.getProcesses();
    const found = list.find((p) => p.pid === pid);
    return found ? { ...found } : null;
  }

  private alertStatuses = new Map<string, ThreatAlert["status"]>();

  /**
   * Enumerate elevated threat alerts identified during scanning.
   */
  async getThreatAlerts(): Promise<ThreatAlert[]> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const mappedAlerts: ThreatAlert[] = mockThreatAlerts.map((a) => {
          const proc = mockProcesses.find((p) => p.pid === a.pid);
          const currentStatus = this.alertStatuses.get(a.id) ?? a.status ?? "NEW";
          const scoreModeNorm = normalizeScoreMode(a.scoreMode);

          const shouldIncludeBehavior = scoreModeNorm === "CORRELATED" || scoreModeNorm === "BEHAVIOR_ONLY";
          const shouldIncludeCorrelation = scoreModeNorm === "CORRELATED";

          return {
            ...a,
            level: normalizeThreatLevel(a.level || a.threatLevel),
            scoreMode: scoreModeNorm,
            status: currentStatus,
            behaviorEvidence: a.behaviorEvidence || (shouldIncludeBehavior && proc && (proc.behaviorEvidenceCount ?? 0) > 0 ? {
              present: true,
              score: proc.behaviorScore,
              indicators: Array.isArray(proc.behaviorEvidence) ? proc.behaviorEvidence.map((b) => b.description) : [],
              suspiciousCommandLine: proc.commandLine?.includes("-W Hidden") || proc.commandLine?.includes("-enc") || false,
              suspiciousParent: proc.parentName === "wscript.exe" || false,
              commandLine: proc.commandLine,
              parentProcess: proc.parentName,
              details: Array.isArray(proc.behaviorEvidence) ? proc.behaviorEvidence.map((b) => b.description) : [],
              timestamp: proc.timestamp,
            } : undefined),
            correlationEvidence: a.correlationEvidence || (shouldIncludeCorrelation && proc && proc.correlationSummary ? {
              present: Boolean(proc.correlationSummary),
              score: proc.threatScore,
              memoryEvidencePresent: Boolean(a.memoryEvidence?.present || (proc.memoryEvidenceCount ?? 0) > 0),
              behaviorEvidencePresent: Boolean((proc.behaviorEvidenceCount ?? 0) > 0),
              correlatedIndicators: [...(proc.memoryIndicators || a.memoryEvidence?.indicators || [])],
              explanation: proc.correlationSummary,
              timestamp: proc.timestamp,
            } : undefined),
          };
        });
        resolve(mappedAlerts);
      }, 120);
    });
  }

  /**
   * Retrieve a specific threat alert by its identifier.
   */
  async getThreatAlert(id: string): Promise<ThreatAlert | null> {
    const list = await this.getThreatAlerts();
    const found = list.find((a) => a.id === id);
    return found ? { ...found } : null;
  }

  /**
   * Update the analyst investigation lifecycle status for a specific threat alert.
   */
  async updateAlertStatus(id: string, status: ThreatAlert["status"]): Promise<ThreatAlert | null> {
    this.alertStatuses.set(id, status);
    return this.getThreatAlert(id);
  }

  /**
   * Retrieve chronological scan run records.
   */
  async getScanHistory(): Promise<ScanHistory[]> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const history: ScanHistory[] = mockScanHistory.map((item) => ({
          ...item,
          startedAt: item.scanDate,
          completedAt: item.scanDate,
          durationMs: parseFloat(item.duration) * 1000,
          totalProcesses: item.processes,
          totalAlerts: item.alerts,
          highestScore: item.highestScore,
          highestThreatLevel: item.critical > 0 ? "CRITICAL" : item.high > 0 ? "HIGH" : item.medium > 0 ? "MEDIUM" : "LOW",
          scannerVersion: item.engineVersion,
        }));
        resolve(history);
      }, 120);
    });
  }

  /**
   * Retrieve full result payload for a specific scan session.
   */
  async getScanResult(scanId?: string): Promise<ScanResult | null> {
    const processes = await this.getProcesses();
    const alerts = await this.getThreatAlerts();

    return new Promise((resolve) => {
      setTimeout(() => {
        const result: ScanResult = {
          ...mockOverview,
          scanId: scanId || "scan-20260925-01",
          timestamp: mockOverview.scanTime,
          durationMs: 4820,
          scannerVersion: mockOverview.engineVersion,
          platform: "Windows 11 Pro 64-bit",
          totalProcesses: mockOverview.totalProcesses,
          memoryScanned: mockOverview.memoryInspectedMb,
          memoryAccessDenied: 0,
          highestScore: mockOverview.highestThreatScore,
          counts: {
            normal: mockOverview.lowCount,
            low: mockOverview.lowCount,
            medium: mockOverview.mediumCount,
            high: mockOverview.highCount,
            critical: mockOverview.criticalCount,
          },
          processes,
          alerts,
        };
        resolve(result);
      }, 120);
    });
  }

  /**
   * Retrieve available forensic exports and reports.
   */
  async getReports(): Promise<Report[]> {
    const alerts = await this.getThreatAlerts();

    return new Promise((resolve) => {
      setTimeout(() => {
        const reports: Report[] = mockReports.map((r) => ({
          ...r,
          scanId: "scan-20260925-01",
          createdAt: r.lastModified,
          title: r.name,
          summary: r.description,
          totalProcesses: r.recordCount ?? 148,
          totalAlerts: alerts.length,
          highestScore: 94,
          highestThreatLevel: "CRITICAL",
          alerts,
          generatedBy: "PHANTOMTRACE",
        }));
        resolve(reports);
      }, 120);
    });
  }

  /**
   * Retrieve a specific report by its identifier.
   */
  async getReport(id: string): Promise<Report | null> {
    const reports = await this.getReports();
    const found = reports.find((r) => r.id === id);
    return found ? { ...found } : null;
  }

  /**
   * Retrieve a specific report by its filename.
   */
  async getReportByName(name: string): Promise<Report | null> {
    const reports = await this.getReports();
    const found = reports.find((r) => r.name === name);
    return found ? { ...found } : null;
  }

  /**
   * Fetch system-wide scan overview metrics.
   */
  async getScanOverview(): Promise<ScanOverview> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({ ...mockOverview });
      }, 100);
    });
  }

  /**
   * Fetch activity timeline data points for risk visualization.
   */
  async getThreatActivityTimeline(): Promise<typeof mockThreatActivityTimeline> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve([...mockThreatActivityTimeline]);
      }, 100);
    });
  }

  /**
   * Fetch platform configuration and subsystem parameters.
   */
  async getSettings(): Promise<SystemSettings> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({ ...mockSettings });
      }, 100);
    });
  }

  /**
   * Update platform configuration settings.
   */
  async updateSettings(updated: Partial<SystemSettings>): Promise<SystemSettings> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const merged = { ...mockSettings, ...updated };
        resolve(merged);
      }, 150);
    });
  }

  /**
   * Run diagnostic ping to verify endpoint connectivity.
   */
  async testApiConnection(endpointUrl: string): Promise<{ success: boolean; message: string; latencyMs: number }> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          message: `Endpoint reachable (${endpointUrl || "https://api.phantomtrace.security/v1"}). Status: Awaiting telemetry ingestion payload stream.`,
          latencyMs: 38,
        });
      }, 300);
    });
  }

  getSyncStatus(): { isRealData: boolean; label: string; lastSyncedAt: string | null } {
    return {
      isRealData: false,
      label: "Local Fixture (Demo)",
      lastSyncedAt: null,
    };
  }

  getTelemetrySource(): "Windows Scanner (Cloud)" | "Local Fixture (Demo)" {
    return "Local Fixture (Demo)";
  }

  async checkHealth(): Promise<{ status: "Cloud Not Configured"; firebaseConfigured: false; message: string }> {
    return {
      status: "Cloud Not Configured",
      firebaseConfigured: false,
      message: "Cloud sync is not configured yet.",
    };
  }

  async syncTelemetry(): Promise<{
    success: false;
    status: "Cloud Not Configured";
    source: "Local Fixture (Demo)";
    message: string;
    timestamp: string;
  }> {
    return {
      success: false,
      status: "Cloud Not Configured",
      source: "Local Fixture (Demo)",
      message: "Cloud sync is not configured yet.",
      timestamp: new Date().toLocaleTimeString(),
    };
  }
}
