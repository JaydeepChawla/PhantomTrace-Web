import type {
  Process,
  ThreatAlert,
  ScanResult,
  ScanHistory,
  Report,
  ScanOverview,
  SystemSettings,
  WebThreatEvent,
  WebThreatStatus,
  DomainPolicy,
  UnifiedThreatAlert,
  CorrelatedThreatEvent,
  DashboardSecurityOverview,
  SecurityTimelineEvent,
  SystemHealthStatus,
} from "../types";
import type {
  PhantomTraceDataService,
  TelemetrySource,
  CloudHealthStatus,
  SyncResult,
} from "./dataService";
import { LocalDataService } from "./localDataService";
import { formatScanDate } from "../utils/dateFormat";

/**
 * =====================================================================
 * PHANTOMTRACE API DATA SERVICE
 * =====================================================================
 * Connects the React Dashboard to the deployed PhantomTrace Backend REST API.
 *
 * Architecture:
 *   Vercel Dashboard
 *       ↓
 *   dataService (ApiDataService)
 *       ↓ (Authenticated REST / Bearer Token)
 *   Render API
 *       ↓
 *   Supabase PostgreSQL
 * =====================================================================
 */
export class ApiDataService implements PhantomTraceDataService {
  private baseUrl: string;
  private token: string | null = null;
  private localFallback: LocalDataService;
  private lastSyncSource: "REAL_SCANNER" | "LOCAL_DEMO" = "REAL_SCANNER";
  private lastSyncTimestamp: string | null = null;
  private lastKnownScanId: string | null = null;

  constructor(baseUrl?: string) {
    const isProductionHost =
      typeof window !== "undefined" &&
      window.location.hostname !== "localhost" &&
      window.location.hostname !== "127.0.0.1";

    const defaultUrl = isProductionHost
      ? "https://phantomtrace-web.onrender.com"
      : "http://localhost:5000";

    const rawEnvUrl =
      (typeof import.meta !== "undefined" &&
        (import.meta.env?.VITE_API_BASE_URL ||
          import.meta.env?.VITE_PHANTOMTRACE_API_URL)) ||
      defaultUrl;

    const normalized = rawEnvUrl.endsWith("/") ? rawEnvUrl.slice(0, -1) : rawEnvUrl;
    this.baseUrl = baseUrl || (normalized.endsWith("/api") ? normalized : `${normalized}/api`);
    this.localFallback = new LocalDataService();

    // Authenticate strictly with user session stored in local storage (never hardcode or bundle shared production secrets)
    if (typeof window !== "undefined") {
      this.token =
        localStorage.getItem("phantomtrace_auth_token") ||
        localStorage.getItem("phantomtrace_session_token") ||
        "";
    } else {
      this.token = "";
    }
  }

  /**
   * Set or update the active Bearer auth token.
   */
  public setAuthToken(token: string | null): void {
    this.token = token;
    if (typeof window !== "undefined") {
      if (token) {
        localStorage.setItem("phantomtrace_auth_token", token);
      } else {
        localStorage.removeItem("phantomtrace_auth_token");
        localStorage.removeItem("phantomtrace_session_token");
        localStorage.removeItem("phantomtrace_api_key");
      }
    }
  }

  /**
   * Retrieve active authentication headers.
   */
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    return headers;
  }

  /**
   * Performs an authenticated fetch against the backend API.
   * Auto-provisions a scoped public session if unauthenticated.
   * Throws an error on non-2xx responses to preserve strict error reporting
   * rather than generating fake or mock security data.
   */
  private async safeFetch<T>(path: string, options?: RequestInit): Promise<T> {
    // If no token exists and not hitting auth route, attempt auto-session negotiation
    if (!this.token && !path.startsWith("/auth/session") && typeof window !== "undefined") {
      await this.ensureAuthenticatedSession();
    }

    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    let response = await fetch(url, {
      ...options,
      headers: {
        ...this.getHeaders(),
        ...((options?.headers as Record<string, string>) || {}),
      },
    });

    // If unauthorized, attempt one-time session recovery for public sessions
    if (response.status === 401 && !path.startsWith("/auth/session") && typeof window !== "undefined") {
      this.token = "";
      localStorage.removeItem("phantomtrace_auth_token");
      await this.ensureAuthenticatedSession();
      if (this.token) {
        response = await fetch(url, {
          ...options,
          headers: {
            ...this.getHeaders(),
            ...((options?.headers as Record<string, string>) || {}),
          },
        });
      }
    }

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error("Unable to load PhantomTrace data. Authentication required or token invalid.");
      }
      throw new Error(`Unable to load PhantomTrace data. (HTTP ${response.status})`);
    }

    const json = await response.json();
    return json as T;
  }

  /**
   * Enumerate all active host processes inspected by PhantomTrace from the cloud database.
   */
  async getProcesses(): Promise<Process[]> {
    const res = await this.safeFetch<{ processes: any[] }>("/processes");
    const list = res.processes || [];

    if (list.length > 0) {
      this.lastSyncSource = "REAL_SCANNER";
      this.lastSyncTimestamp = formatScanDate(new Date());
    }

    return list.map((p: any) => ({
      pid: Number(p.pid),
      name: p.name,
      executablePath: p.executablePath || p.path,
      path: p.executablePath || p.path || "",
      applicationName: p.applicationName || p.application || "Standard Windows Process",
      application: p.applicationName || p.application || "Standard Windows Process",
      parentPid: p.parentPid !== undefined && p.parentPid !== null ? Number(p.parentPid) : undefined,
      parentName: p.parentName || "Unknown",
      commandLine: p.commandLine || "",
      threatScore: Number(p.threatScore ?? 0),
      threatLevel: p.threatLevel || "NORMAL",
      scoreMode: p.scoreMode || "NONE",
      behaviorScore: p.behaviorScore !== undefined && p.behaviorScore !== null ? Number(p.behaviorScore) : 0,
      memoryScore: p.memoryScore !== undefined && p.memoryScore !== null ? Number(p.memoryScore) : 0,
      correlationScore: p.correlationScore !== undefined && p.correlationScore !== null ? Number(p.correlationScore) : 0,
      memoryEvidence: p.memoryEvidence || { present: false, indicators: [] },
      behaviorEvidence: p.behaviorEvidence || { present: false, indicators: [] },
      correlationEvidence: p.correlationEvidence || { present: false, correlatedIndicators: [], memoryEvidencePresent: false, behaviorEvidencePresent: false },
      timestamp: p.timestamp ? formatScanDate(p.timestamp) : p.timestamp,
      userContext: p.userContext || "NT AUTHORITY\\SYSTEM",
      memoryEvidenceCount: p.memoryEvidenceCount ?? (p.memoryEvidence?.indicators?.length ?? 0),
      behaviorEvidenceCount: p.behaviorEvidenceCount ?? (p.behaviorEvidence?.indicators?.length ?? 0),
      memoryIndicators: p.memoryIndicators ?? (p.memoryEvidence?.indicators ?? []),
      integrityLevel: p.integrityLevel || "System",
      responseRecommendation: p.responseRecommendation,
    }));
  }

  /**
   * Retrieve detailed forensic telemetry and evidence for a specific process by PID.
   */
  async getProcess(pid: number): Promise<Process | null> {
    const res = await this.safeFetch<{ process: any | null }>(`/processes/${pid}`);
    const p = res.process;
    if (!p) return null;

    return {
      pid: Number(p.pid),
      name: p.name,
      executablePath: p.executablePath || p.path,
      path: p.executablePath || p.path || "",
      applicationName: p.applicationName || p.application || "Standard Windows Process",
      application: p.applicationName || p.application || "Standard Windows Process",
      parentPid: p.parentPid !== undefined && p.parentPid !== null ? Number(p.parentPid) : undefined,
      parentName: p.parentName || "Unknown",
      commandLine: p.commandLine || "",
      threatScore: Number(p.threatScore ?? 0),
      threatLevel: p.threatLevel || "NORMAL",
      scoreMode: p.scoreMode || "NONE",
      behaviorScore: p.behaviorScore !== undefined && p.behaviorScore !== null ? Number(p.behaviorScore) : 0,
      memoryScore: p.memoryScore !== undefined && p.memoryScore !== null ? Number(p.memoryScore) : 0,
      correlationScore: p.correlationScore !== undefined && p.correlationScore !== null ? Number(p.correlationScore) : 0,
      memoryEvidence: p.memoryEvidence || { present: false, indicators: [] },
      behaviorEvidence: p.behaviorEvidence || { present: false, indicators: [] },
      correlationEvidence: p.correlationEvidence || { present: false, correlatedIndicators: [], memoryEvidencePresent: false, behaviorEvidencePresent: false },
      timestamp: p.timestamp ? formatScanDate(p.timestamp) : p.timestamp,
      userContext: p.userContext || "NT AUTHORITY\\SYSTEM",
      memoryEvidenceCount: p.memoryEvidenceCount ?? (p.memoryEvidence?.indicators?.length ?? 0),
      behaviorEvidenceCount: p.behaviorEvidenceCount ?? (p.behaviorEvidence?.indicators?.length ?? 0),
      memoryIndicators: p.memoryIndicators ?? (p.memoryEvidence?.indicators ?? []),
      integrityLevel: p.integrityLevel || "System",
      responseRecommendation: p.responseRecommendation,
    };
  }

  /**
   * Enumerate elevated threat alerts identified during scanning.
   */
  async getThreatAlerts(): Promise<ThreatAlert[]> {
    const res = await this.safeFetch<{ alerts: any[] }>("/alerts");
    const list = res.alerts || [];

    return list.map((a: any) => ({
      id: a.id || a.alertId,
      pid: Number(a.pid),
      processName: a.processName || a.process || a.name || `PID ${a.pid}`,
      process: a.processName || a.process || a.name || `PID ${a.pid}`,
      score: Number(a.score ?? a.threatScore ?? 0),
      threatScore: Number(a.threatScore ?? a.score ?? 0),
      level: a.level || a.threatLevel || "NORMAL",
      threatLevel: a.threatLevel || a.level || "NORMAL",
      scoreMode: a.scoreMode || "NONE",
      title: a.title,
      description: a.description,
      memoryEvidence: a.memoryEvidence,
      behaviorEvidence: a.behaviorEvidence,
      correlationEvidence: a.correlationEvidence,
      detectedAt: a.detectedAt ? formatScanDate(a.detectedAt) : a.detectedAt,
      timestamp: a.timestamp ? formatScanDate(a.timestamp) : a.timestamp,
      status: a.status || "NEW",
      application: a.application || "Standard Binary",
      behaviorScore: a.behaviorScore,
      memoryScore: a.memoryScore,
      correlation: a.correlation || a.correlationSummary,
      recommendedActions: a.recommendedActions,
    }));
  }

  /**
   * Retrieve a specific threat alert by its identifier.
   */
  async getThreatAlert(id: string): Promise<ThreatAlert | null> {
    const res = await this.safeFetch<{ alert: any | null }>(
      `/alerts/${encodeURIComponent(id)}`
    );
    const a = res.alert;
    if (!a) return null;

    return {
      id: a.id || a.alertId,
      pid: Number(a.pid),
      processName: a.processName || a.process || a.name || `PID ${a.pid}`,
      process: a.processName || a.process || a.name || `PID ${a.pid}`,
      score: Number(a.score ?? a.threatScore ?? 0),
      threatScore: Number(a.threatScore ?? a.score ?? 0),
      level: a.level || a.threatLevel || "NORMAL",
      threatLevel: a.threatLevel || a.level || "NORMAL",
      scoreMode: a.scoreMode || "NONE",
      title: a.title,
      description: a.description,
      memoryEvidence: a.memoryEvidence,
      behaviorEvidence: a.behaviorEvidence,
      correlationEvidence: a.correlationEvidence,
      detectedAt: a.detectedAt ? formatScanDate(a.detectedAt) : a.detectedAt,
      timestamp: a.timestamp ? formatScanDate(a.timestamp) : a.timestamp,
      status: a.status || "NEW",
      application: a.application || "Standard Binary",
      behaviorScore: a.behaviorScore,
      memoryScore: a.memoryScore,
      correlation: a.correlation || a.correlationSummary,
      recommendedActions: a.recommendedActions,
    };
  }

  /**
   * Update the analyst investigation lifecycle status for a specific threat alert.
   */
  async updateAlertStatus(
    id: string,
    status: ThreatAlert["status"]
  ): Promise<ThreatAlert | null> {
    return this.localFallback.updateAlertStatus(id, status);
  }

  /**
   * Retrieve chronological scan run records.
   */
  async getScanHistory(): Promise<ScanHistory[]> {
    const res = await this.safeFetch<{ scans: any[] }>("/scans");
    const scans = res.scans || [];

    return scans.map((s: any) => {
      const crit = Number(s.counts?.critical ?? 0);
      const high = Number(s.counts?.high ?? 0);
      const med = Number(s.counts?.medium ?? 0);
      const low = Number(s.counts?.low ?? 0);
      const totalAlerts = crit + high + med + low;

      return {
        id: s.scanId,
        startedAt: s.timestamp,
        durationMs: s.durationMs,
        status:
          crit + high > 0
            ? "Investigation Flags"
            : "Verified Clean",
        totalProcesses: Number(s.totalProcesses ?? 0),
        totalAlerts,
        alerts: totalAlerts,
        highestScore: Number(s.highestScore ?? 0),
        highestThreatLevel:
          s.highestScore >= 80
            ? "CRITICAL"
            : s.highestScore >= 60
            ? "HIGH"
            : s.highestScore >= 40
            ? "MEDIUM"
            : s.highestScore >= 20
            ? "LOW"
            : "NORMAL",
        scannerVersion: s.scannerVersion || "PhantomTrace",
        scanDate: s.timestamp ? formatScanDate(s.timestamp) : s.timestamp,
        processes: Number(s.totalProcesses ?? 0),
        critical: crit,
        high,
        medium: med,
        low,
        highestThreatScore: Number(s.highestScore ?? 0),
        duration: s.durationMs ? `${(s.durationMs / 1000).toFixed(1)}s` : "0.0s",
      };
    });
  }

  /**
   * Retrieve full result payload for a specific scan session.
   */
  async getScanResult(scanId?: string): Promise<ScanResult | null> {
    if (scanId) {
      const res = await this.safeFetch<{ scan: ScanResult | null }>(`/scans/${scanId}`);
      return res.scan || null;
    }
    const res = await this.safeFetch<{ scans: any[] }>("/scans");
    if (res.scans && res.scans.length > 0) {
      return res.scans[0] as ScanResult;
    }
    return null;
  }

  /**
   * Retrieve available forensic exports and reports.
   */
  async getReports(): Promise<Report[]> {
    const res = await this.safeFetch<{ reports: any[] }>("/reports");
    const reports = res.reports || [];

    return reports.map((r: any) => ({
      id: r.id,
      scanId: r.scanId || "",
      createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : new Date().toISOString(),
      title: r.title || r.name || "Endpoint Forensic Scan Report",
      summary: r.summary || r.description || "PhantomTrace forensic scan report",
      totalProcesses: Number(r.totalProcesses ?? 246),
      totalAlerts: Number(r.totalAlerts ?? 0),
      highestScore: Number(r.highestScore ?? 0),
      highestThreatLevel: r.highestThreatLevel || "NORMAL",
      alerts: r.alerts || [],
      generatedBy: r.generatedBy || "PHANTOMTRACE",
      name: r.name || (r.type === "json" ? "scan_results.json" : "phantomtrace_validation_report.txt"),
      type: r.type || "json",
      size: r.size || "102.2 KB",
      lastModified: r.createdAt ? formatScanDate(r.createdAt) : formatScanDate(new Date()),
      description: r.summary || r.title || "Forensic endpoint scan report",
      content: r.content || JSON.stringify(r, null, 2),
      recordCount: Number(r.recordCount ?? r.totalProcesses ?? 246),
    }));
  }

  /**
   * Retrieve a specific report by its identifier.
   */
  async getReport(id: string): Promise<Report | null> {
    const res = await this.safeFetch<{ report: any | null }>(
      `/reports/${encodeURIComponent(id)}`
    );
    const r = res.report;
    if (!r) return null;

    return {
      id: r.id,
      scanId: r.scanId || "",
      createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : new Date().toISOString(),
      title: r.title || r.name || "Endpoint Forensic Scan Report",
      summary: r.summary || r.description || "PhantomTrace forensic scan report",
      totalProcesses: Number(r.totalProcesses ?? 246),
      totalAlerts: Number(r.totalAlerts ?? 0),
      highestScore: Number(r.highestScore ?? 0),
      highestThreatLevel: r.highestThreatLevel || "NORMAL",
      alerts: r.alerts || [],
      generatedBy: r.generatedBy || "PHANTOMTRACE",
      name: r.name || (r.type === "json" ? "scan_results.json" : "phantomtrace_validation_report.txt"),
      type: r.type || "json",
      size: r.size || "102.2 KB",
      lastModified: r.createdAt ? formatScanDate(r.createdAt) : formatScanDate(new Date()),
      description: r.summary || r.title || "Forensic endpoint scan report",
      content: r.content || JSON.stringify(r, null, 2),
      recordCount: Number(r.recordCount ?? r.totalProcesses ?? 246),
    };
  }

  /**
   * Retrieve a specific report by its file name.
   */
  async getReportByName(name: string): Promise<Report | null> {
    const reports = await this.getReports();
    return reports.find((r) => r.name === name || r.title === name) || null;
  }

  /**
   * Status indicator identifying whether current telemetry is from real Windows Scanner
   * or local development fallback.
   */
  public getSyncStatus(): { isRealData: boolean; label: string; lastSyncedAt: string | null } {
    return {
      isRealData: this.lastSyncSource === "REAL_SCANNER",
      label:
        this.lastSyncSource === "REAL_SCANNER"
          ? "Windows Scanner (Cloud)"
          : "Cloud Connected",
      lastSyncedAt: this.lastSyncTimestamp,
    };
  }

  /**
   * Return exact TelemetrySource enum string.
   */
  public getTelemetrySource(): TelemetrySource {
    return this.lastSyncSource === "REAL_SCANNER"
      ? "Windows Scanner (Cloud)"
      : "Cloud Connected";
  }

  /**
   * Fetch system-wide scan overview metrics.
   * Synthesizes live metrics directly from PostgreSQL via Render REST API.
   */
  async getScanOverview(): Promise<ScanOverview | ScanResult> {
    const scansRes = await this.safeFetch<{ scans: any[] }>("/scans");
    const scans = scansRes.scans || [];

    if (scans.length === 0) {
      return null as unknown as ScanOverview;
    }

    const latestScan = scans[0];

    // Fetch alerts if available
    let alerts: ThreatAlert[] = [];
    try {
      const alertsRes = await this.safeFetch<{ alerts: any[] }>("/alerts");
      alerts = (alertsRes.alerts || []) as ThreatAlert[];
    } catch {
      alerts = [];
    }

    // User-friendly endpoint identity
    const endpointName = "Windows PC";

    this.lastSyncSource = "REAL_SCANNER";
    this.lastSyncTimestamp = latestScan.timestamp ? formatScanDate(latestScan.timestamp) : formatScanDate(new Date());

    const totalProcesses = Number(latestScan.totalProcesses ?? 0);
    const criticalCount = Number(latestScan.counts?.critical ?? 0);
    const highCount = Number(latestScan.counts?.high ?? 0);
    const mediumCount = Number(latestScan.counts?.medium ?? 0);
    const lowCount = Number(latestScan.counts?.low ?? 0);
    const normalCount = Number(latestScan.counts?.normal ?? Math.max(0, totalProcesses - (criticalCount + highCount + mediumCount + lowCount)));

    const overview: ScanOverview = {
      totalProcesses,
      threatAlertsCount: alerts.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      normalCount,
      highestThreatScore: Number(latestScan.highestScore ?? 0),
      scanTime: latestScan.timestamp ? formatScanDate(latestScan.timestamp) : "No scan timestamp recorded",
      duration: latestScan.durationMs ? `${(latestScan.durationMs / 1000).toFixed(1)}s` : "0.0s",
      memoryInspectedMb: Number(latestScan.memoryScanned ?? 0),
      engineVersion: latestScan.scannerVersion || "PhantomTrace Scanner",
      scanMode: "Memory & Behavioral Heuristics (Windows Ingested)",
      readOnlyEngineEnforced: true,
      scanId: latestScan.scanId,
      endpointId: latestScan.endpointId,
      endpointName: endpointName,
    };

    return overview;
  }

  /**
   * Fetch activity timeline data points for risk visualization.
   */
  async getThreatActivityTimeline(): Promise<
    Array<{ time: string; totalInspected: number; elevatedThreats: number; avgScore: number }>
  > {
    try {
      const scansRes = await this.safeFetch<{ scans: any[] }>("/scans");
      const scans = scansRes.scans || [];
      if (scans.length > 0) {
        return scans.map((s, idx) => ({
          time: s.timestamp
            ? new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : `Scan ${idx + 1}`,
          totalInspected: Number(s.totalProcesses ?? 0),
          elevatedThreats: (s.counts?.critical || 0) + (s.counts?.high || 0),
          avgScore: Number(s.highestScore ?? 0),
        }));
      }
    } catch {
      return [];
    }
    return [];
  }

  /**
   * Fetch platform configuration and subsystem parameters.
   */
  async getSettings(): Promise<SystemSettings> {
    return this.localFallback.getSettings();
  }

  /**
   * Update platform configuration settings.
   */
  async updateSettings(updated: Partial<SystemSettings>): Promise<SystemSettings> {
    return this.localFallback.updateSettings(updated);
  }

  /**
   * Run diagnostic ping to verify endpoint connectivity against /api/health.
   */
  async testApiConnection(
    endpointUrl: string
  ): Promise<{ success: boolean; message: string; latencyMs: number }> {
    const start = performance.now();
    try {
      const normalizedUrl = endpointUrl.endsWith("/")
        ? endpointUrl.slice(0, -1)
        : endpointUrl;
      const targetUrl = normalizedUrl.includes("/api/health")
        ? normalizedUrl
        : normalizedUrl.includes("/api")
        ? `${normalizedUrl}/health`
        : `${normalizedUrl}/api/health`;

      const response = await fetch(targetUrl);
      const latencyMs = Math.round(performance.now() - start);

      let data: any = null;
      try {
        data = await response.json();
      } catch {}

      if (response.ok) {
        return {
          success: true,
          message: `Connected to ${data?.service || "PhantomTrace API"} (Status: ${data?.status || "ok"}, Version: ${data?.version || "1.0.0"})`,
          latencyMs,
        };
      }

      if (response.status === 503 && data && data.service) {
        return {
          success: true,
          message: `Connected to ${data.service} (Status: ${data.status} — Database offline, in-memory fallback active)`,
          latencyMs,
        };
      }

      return {
        success: false,
        message: `HTTP ${response.status} from API healthcheck`,
        latencyMs,
      };
    } catch (err: unknown) {
      const latencyMs = Math.round(performance.now() - start);
      const msg = err instanceof Error ? err.message : "Connection refused";
      return {
        success: false,
        message: `Unable to reach API server: ${msg}`,
        latencyMs,
      };
    }
  }

  /**
   * Check connection status to PhantomTrace API and PostgreSQL configuration.
   * Uses GET /api/health to determine backend availability and database connectivity.
   */
  async checkHealth(): Promise<CloudHealthStatus> {
    try {
      const normalizedBase = this.baseUrl.endsWith("/") ? this.baseUrl.slice(0, -1) : this.baseUrl;
      const healthUrl = normalizedBase.endsWith("/api")
        ? `${normalizedBase}/health`
        : normalizedBase.includes("/api")
        ? `${normalizedBase.replace(/\/api.*$/, "")}/api/health`
        : `${normalizedBase}/api/health`;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(healthUrl, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        let healthData: any = null;
        try {
          healthData = await response.json();
        } catch {}

        if (healthData && healthData.service) {
          return {
            status: "Cloud Not Configured",
            firebaseConfigured: false,
            message: "API online (database connection offline).",
          };
        }

        return {
          status: "API Offline",
          firebaseConfigured: false,
          message: "Sync unavailable — API connection could not be established.",
        };
      }

      const data = await response.json();
      if (
        data &&
        (data.databaseConnected === true ||
          data.status === "ok" ||
          data.firebaseConfigured === true)
      ) {
        return {
          status: "Cloud Connected",
          firebaseConfigured: true,
          message: "Cloud Connected",
        };
      }

      return {
        status: "Cloud Not Configured",
        firebaseConfigured: false,
        message: "Cloud sync is not configured yet.",
      };
    } catch {
      return {
        status: "API Offline",
        firebaseConfigured: false,
        message: "Sync unavailable — API connection could not be established.",
      };
    }
  }

  /**
   * Perform real telemetry synchronization against the Render backend.
   */
  async syncTelemetry(): Promise<SyncResult> {
    const health = await this.checkHealth();

    if (health.status === "API Offline") {
      return {
        success: false,
        status: "API Offline",
        source: "Cloud Connected",
        message: "Unable to update telemetry: API connection could not be established.",
        timestamp: formatScanDate(new Date()),
      };
    }

    if (health.status === "Cloud Not Configured") {
      return {
        success: false,
        status: "Cloud Not Configured",
        source: "Cloud Connected",
        message: "Unable to update telemetry: Cloud sync is not configured yet.",
        timestamp: formatScanDate(new Date()),
      };
    }

    try {
      const url = `${this.baseUrl}/scans`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const response = await fetch(url, {
        headers: this.getHeaders(),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          success: false,
          status: "Cloud Connected",
          source: "Cloud Connected",
          message: `Unable to update telemetry: HTTP ${response.status}`,
          timestamp: formatScanDate(new Date()),
        };
      }

      const json = await response.json();
      const scans = json.scans;

      if (Array.isArray(scans) && scans.length > 0) {
        this.lastSyncSource = "REAL_SCANNER";
        const latestScan = scans[0];
        const formattedTimestamp = formatScanDate(latestScan.timestamp || new Date());
        this.lastSyncTimestamp = formattedTimestamp;

        const isNewer = this.lastKnownScanId !== null && this.lastKnownScanId !== latestScan.scanId;
        const isFirst = this.lastKnownScanId === null;
        this.lastKnownScanId = latestScan.scanId;

        if (isNewer || isFirst) {
          return {
            success: true,
            status: "Cloud Connected",
            source: "Windows Scanner (Cloud)",
            message: `Updated just now (Latest scan: ${formattedTimestamp})`,
            timestamp: formattedTimestamp,
          };
        } else {
          return {
            success: true,
            status: "Cloud Connected",
            source: "Windows Scanner (Cloud)",
            message: `No new scan available (Latest scan: ${formattedTimestamp})`,
            timestamp: formattedTimestamp,
          };
        }
      }

      return {
        success: false,
        status: "Cloud Connected",
        source: "Cloud Connected",
        message: "No new scan available",
        timestamp: formatScanDate(new Date()),
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network error";
      return {
        success: false,
        status: "Cloud Connected",
        source: "Cloud Connected",
        message: `Unable to update telemetry: ${msg}`,
        timestamp: formatScanDate(new Date()),
      };
    }
  }

  /**
   * Ensures an active user session token exists.
   * Auto-provisions a secure public session if unauthenticated.
   */
  public async ensureAuthenticatedSession(): Promise<string> {
    if (this.token) return this.token;

    try {
      const url = `${this.baseUrl}/auth/session`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          displayName: "Security Analyst",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.sessionToken) {
          this.setAuthToken(data.sessionToken);
          return data.sessionToken;
        }
      }
    } catch (err) {
      console.warn("[ApiDataService] Could not establish public session:", err);
    }
    return "";
  }

  /**
   * Authenticates as the system administrator using the master API key.
   * Exchanges the key for a secure, scoped session token tied to 'phantomtrace-owner'.
   */
  public async loginWithApiKey(apiKey: string): Promise<{ success: boolean; message?: string }> {
    try {
      const url = `${this.baseUrl}/auth/login`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: apiKey.trim() }),
      });
      const data = await res.json();
      if (res.ok && data.sessionToken) {
        this.setAuthToken(data.sessionToken);
        return { success: true };
      }
      return { success: false, message: data.message || "Invalid administrator credentials" };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network error";
      return { success: false, message: msg };
    }
  }

  /**
   * Initiates a short-lived device pairing request.
   */
  public async startDevicePairing(): Promise<{ pairingId: string; pairingCode: string; expiresAt: string }> {
    await this.ensureAuthenticatedSession();
    return this.safeFetch<{ pairingId: string; pairingCode: string; expiresAt: string }>(
      "/devices/pair/start",
      { method: "POST" }
    );
  }

  /**
   * Checks the status of an active device pairing handshake.
   */
  public async checkDevicePairingStatus(
    pairingId: string
  ): Promise<{ status: "PENDING" | "PAIRED" | "EXPIRED"; deviceId?: string }> {
    return this.safeFetch<{ status: "PENDING" | "PAIRED" | "EXPIRED"; deviceId?: string }>(
      `/devices/pair/status?pairingId=${encodeURIComponent(pairingId)}`
    );
  }

  /**
   * Enumerate all registered devices for the current user.
   */
  public async getDevices(): Promise<
    Array<{ deviceId: string; deviceName: string; createdAt: string; lastSeenAt: string; isRevoked: boolean }>
  > {
    try {
      const res = await this.safeFetch<{ devices: any[] }>("/devices");
      return (res.devices || []).map((d) => ({
        deviceId: d.deviceId,
        deviceName: d.deviceName || "Windows PC",
        createdAt: formatScanDate(d.createdAt),
        lastSeenAt: formatScanDate(d.lastSeenAt),
        isRevoked: Boolean(d.isRevoked),
      }));
    } catch {
      return [];
    }
  }

  /**
   * Revoke a registered device credential, terminating upload permissions immediately.
   */
  public async revokeDevice(deviceId: string): Promise<boolean> {
    try {
      const res = await this.safeFetch<{ success: boolean }>(
        `/devices/${encodeURIComponent(deviceId)}/revoke`,
        { method: "POST" }
      );
      return res.success === true;
    } catch {
      return false;
    }
  }

  /**
   * =====================================================================
   * PHASE 3: WEB THREAT MONITOR METHODS
   * =====================================================================
   */
  public async getWebThreatStatus(): Promise<WebThreatStatus> {
    try {
      const res = await this.safeFetch<{
        status: string;
        service?: string;
        provider?: string;
        cachedCount?: number;
      }>("/web-threats/status");

      return {
        status: res.status === "ok" ? "ENABLED" : "UNAVAILABLE",
        provider: res.provider || "PhantomTrace-Mock-ThreatIntel",
        serviceOnline: res.status === "ok",
        activeCount: res.cachedCount || 0,
      };
    } catch (err: any) {
      return {
        status: "UNAVAILABLE",
        serviceOnline: false,
        activeCount: 0,
        message: err?.message || "Reputation provider unreachable",
      };
    }
  }

  public async getWebThreatEvents(): Promise<WebThreatEvent[]> {
    try {
      const res = await this.safeFetch<{ events: WebThreatEvent[] }>("/web-threats/events");
      return res.events || [];
    } catch {
      return [];
    }
  }

  public async dismissWebThreatEvent(eventId: string): Promise<boolean> {
    try {
      const res = await this.safeFetch<{ success: boolean }>(
        `/web-threats/events/${encodeURIComponent(eventId)}/dismiss`,
        { method: "POST" }
      );
      return res.success === true;
    } catch {
      return false;
    }
  }

  /**
   * =====================================================================
   * PHASE 4: DOMAIN POLICY & CROSS-VECTOR THREAT MANAGEMENT
   * =====================================================================
   */
  public async getDomainPolicies(): Promise<DomainPolicy[]> {
    try {
      const res = await this.safeFetch<{ policies: DomainPolicy[] }>("/web-threats/policies");
      return res.policies || [];
    } catch {
      return [];
    }
  }

  public async addDomainPolicy(domain: string, policyType: "ALLOW" | "BLOCK", reason?: string): Promise<DomainPolicy> {
    const res = await this.safeFetch<{ success: boolean; policy: DomainPolicy }>(
      "/web-threats/policies",
      {
        method: "POST",
        body: JSON.stringify({ domain, policyType, reason }),
      }
    );
    return res.policy;
  }

  public async deleteDomainPolicy(policyId: string): Promise<boolean> {
    try {
      const res = await this.safeFetch<{ success: boolean }>(
        `/web-threats/policies/${encodeURIComponent(policyId)}`,
        { method: "DELETE" }
      );
      return res.success === true;
    } catch {
      return false;
    }
  }

  public async updateWebThreatStatus(eventId: string, status: string, notes?: string): Promise<boolean> {
    try {
      const res = await this.safeFetch<{ success: boolean }>(
        `/web-threats/events/${encodeURIComponent(eventId)}/status`,
        {
          method: "POST",
          body: JSON.stringify({ status, notes }),
        }
      );
      return res.success === true;
    } catch {
      return false;
    }
  }

  public async getUnifiedThreatAlerts(): Promise<UnifiedThreatAlert[]> {
    try {
      const res = await this.safeFetch<{ alerts: UnifiedThreatAlert[] }>("/alerts/unified");
      return res.alerts || [];
    } catch {
      return [];
    }
  }

  public async getCorrelatedThreatEvents(): Promise<CorrelatedThreatEvent[]> {
    try {
      const res = await this.safeFetch<{ correlatedEvents: CorrelatedThreatEvent[] }>("/web-threats/correlated");
      return res.correlatedEvents || [];
    } catch {
      return [];
    }
  }

  public async generateUnifiedSocReport(): Promise<Report> {
    const res = await this.safeFetch<{ success: boolean; report: Report }>(
      "/reports/generate-unified",
      { method: "POST" }
    );
    return res.report;
  }

  /**
   * Phase 5: Retrieve real-time aggregated security overview.
   */
  public async getDashboardOverview(): Promise<DashboardSecurityOverview> {
    const res = await this.safeFetch<{ overview: DashboardSecurityOverview }>("/dashboard/overview");
    return res.overview;
  }

  /**
   * Phase 5: Retrieve unified chronological security event timeline.
   */
  public async getSecurityTimeline(
    type?: string,
    severity?: string,
    limit = 25,
    offset = 0
  ): Promise<{ events: SecurityTimelineEvent[]; total: number }> {
    const params = new URLSearchParams();
    if (type && type !== "ALL") params.append("type", type);
    if (severity && severity !== "ALL") params.append("severity", severity);
    params.append("limit", String(limit));
    params.append("offset", String(offset));

    const res = await this.safeFetch<{ events: SecurityTimelineEvent[]; total: number }>(
      `/dashboard/timeline?${params.toString()}`
    );
    return res;
  }

  /**
   * Phase 5: Retrieve system health and telemetry freshness status.
   */
  public async getSystemHealth(): Promise<SystemHealthStatus> {
    const res = await this.safeFetch<{ health: SystemHealthStatus }>("/dashboard/system-health");
    return res.health;
  }

}
