import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresPool } from "../config/postgres";
import { postgresService } from "../services/postgresService";
import type {
  AuthenticatedRequest,
  DashboardSecurityOverview,
  SecurityTimelineEvent,
  SystemHealthStatus,
} from "../types/api";

export const dashboardRouter = Router();

// All dashboard endpoints require authentication
dashboardRouter.use(authMiddleware);

/**
 * GET /api/dashboard/overview
 * Real-time aggregated security overview for SOC analysts.
 * Strictly calculates data from live PostgreSQL/scans; never serves fabricated numbers.
 */
dashboardRouter.get("/overview", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;

    const [scans, endpoints, alerts, webThreats, policies] = await Promise.all([
      postgresService.getScans(uid).catch(() => []),
      postgresService.getEndpoints(uid).catch(() => []),
      postgresService.getUnifiedThreatAlerts(uid).catch(() => []),
      postgresService.getWebThreatEvents(uid).catch(() => []),
      postgresService.getDomainPolicies(uid).catch(() => []),
    ]);

    const totalScans = scans.length;
    const registeredEndpoints = endpoints.length;

    let processFindings = {
      totalAnalyzed: 0,
      cleanProcesses: 0,
      elevatedProcesses: 0,
      highestThreatScore: 0,
      memoryInspectedMb: 0,
    };

    let lastSuccessfulScanUpload: string | null = null;
    let telemetryFreshness: "FRESH" | "RECENT" | "STALE" | "NONE" = "NONE";
    let isRealScannerData = false;

    if (scans.length > 0) {
      const latestScan = scans[0];
      lastSuccessfulScanUpload = latestScan.timestamp;
      isRealScannerData = true;

      const totalProcesses = Number(latestScan.totalProcesses || 0);
      const crit = Number(latestScan.counts?.critical || 0);
      const high = Number(latestScan.counts?.high || 0);
      const med = Number(latestScan.counts?.medium || 0);
      const low = Number(latestScan.counts?.low || 0);
      const elevated = crit + high + med + low;
      const clean = Number(
        latestScan.counts?.normal ?? Math.max(0, totalProcesses - elevated)
      );

      processFindings = {
        totalAnalyzed: totalProcesses,
        cleanProcesses: clean,
        elevatedProcesses: elevated,
        highestThreatScore: Number(latestScan.highestScore || 0),
        memoryInspectedMb: Number(latestScan.memoryScanned || 0),
      };

      const scanTime = new Date(latestScan.timestamp).getTime();
      const ageHours = (Date.now() - scanTime) / (1000 * 60 * 60);

      if (ageHours < 2) {
        telemetryFreshness = "FRESH";
      } else if (ageHours < 24) {
        telemetryFreshness = "RECENT";
      } else {
        telemetryFreshness = "STALE";
      }
    }

    // Threat alert distribution calculations
    const critAlerts = alerts.filter((a) => a.level === "CRITICAL").length;
    const highAlerts = alerts.filter((a) => a.level === "HIGH").length;
    const medAlerts = alerts.filter((a) => a.level === "MEDIUM").length;
    const lowAlerts = alerts.filter((a) => a.level === "LOW").length;

    const byStatus = {
      new: alerts.filter((a) => a.status === "NEW" || !a.status).length,
      investigating: alerts.filter((a) => a.status === "INVESTIGATING").length,
      contained: alerts.filter((a) => a.status === "CONTAINED").length,
      resolved: alerts.filter((a) => a.status === "RESOLVED").length,
      dismissed: alerts.filter((a) => a.status === "DISMISSED").length,
    };

    const byVector = {
      memory: alerts.filter((a) => a.vector === "ENDPOINT_MEMORY").length,
      web: alerts.filter((a) => a.vector === "WEB_THREAT").length,
    };

    const recentSecurityEventsCount = alerts.length + webThreats.length + policies.length;

    const overview: DashboardSecurityOverview = {
      totalScans,
      registeredEndpoints,
      processFindings,
      threatAlertsDistribution: {
        total: alerts.length,
        critical: critAlerts,
        high: highAlerts,
        medium: medAlerts,
        low: lowAlerts,
        byStatus,
        byVector,
      },
      recentSecurityEventsCount,
      lastSuccessfulScanUpload,
      lastSuccessfulRefresh: new Date().toISOString(),
      telemetryFreshness,
      telemetryMode: "PERIODIC_SCAN_SNAPSHOT",
      isRealScannerData,
    };

    res.status(200).json({ overview });
  } catch (err: unknown) {
    console.error("[Dashboard] Error generating security overview:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to generate dashboard security overview",
      },
    });
  }
});

/**
 * GET /api/dashboard/timeline
 * Consolidated security event timeline combining endpoint scans, web threats,
 * domain policy enforcement, and alert triage.
 */
dashboardRouter.get("/timeline", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const rawType = typeof req.query.type === "string" ? req.query.type.toUpperCase() : "ALL";
    const rawSeverity = typeof req.query.severity === "string" ? req.query.severity.toUpperCase() : "ALL";
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit || "25"), 10) || 25));
    const offset = Math.max(0, parseInt(String(req.query.offset || "0"), 10) || 0);

    const [scans, alerts, webThreats, policies] = await Promise.all([
      postgresService.getScans(uid).catch(() => []),
      postgresService.getUnifiedThreatAlerts(uid).catch(() => []),
      postgresService.getWebThreatEvents(uid).catch(() => []),
      postgresService.getDomainPolicies(uid).catch(() => []),
    ]);

    const events: SecurityTimelineEvent[] = [];

    // 1. Scan Ingest Events
    for (const s of scans) {
      events.push({
        id: `event-scan-${s.scanId}`,
        timestamp: s.timestamp,
        eventType: "SCAN_INGEST",
        severity: s.highestScore >= 80 ? "HIGH" : s.highestScore >= 40 ? "MEDIUM" : "INFO",
        title: "Endpoint Telemetry Scan Ingested",
        description: `Inspected ${s.totalProcesses} running processes (${s.memoryScanned || 0} MB memory analyzed). Highest threat score: ${s.highestScore}/100.`,
        target: `Scan ${s.scanId.slice(0, 12)}`,
        status: "COMPLETED",
        source: "Windows Endpoint Scanner",
        relatedId: s.scanId,
      });
    }

    // 2. Unified Threat Alerts (Memory & Web Threat vectors)
    for (const a of alerts) {
      const isWeb = a.vector === "WEB_THREAT";
      events.push({
        id: `event-alert-${a.id}`,
        timestamp: a.timestamp,
        eventType: isWeb ? "WEB_THREAT" : "SCAN_FINDING",
        severity: (a.level as any) || "MEDIUM",
        title: a.title,
        description: a.explanation || a.targetDetail || `Threat score: ${a.score}/100`,
        target: a.targetName,
        status: a.status,
        evidenceSummary: a.indicators,
        source: isWeb ? "Web Threat Monitor" : "Endpoint Memory Heuristics",
        relatedId: a.id,
        disclaimer: a.correlatedProcess
          ? "Heuristic correlation: Active browser process was identified in endpoint scan telemetry; does not constitute proof that this process executed the URL request."
          : undefined,
      });
    }

    // 3. Domain Policy Rules
    for (const p of policies) {
      events.push({
        id: `event-policy-${p.policyId}`,
        timestamp: p.createdAt,
        eventType: "POLICY_EVENT",
        severity: p.policyType === "BLOCK" ? "MEDIUM" : "INFO",
        title: `Domain ${p.policyType} Rule Configured`,
        description: `Domain '${p.domain}' designated as ${p.policyType}.${p.reason ? ` Reason: ${p.reason}` : ""}`,
        target: p.domain,
        status: "ENFORCED",
        source: "Domain Policy Manager",
        relatedId: p.policyId,
      });
    }

    // 4. Incident Triage Transitions
    for (const w of webThreats) {
      if (w.status && w.status !== "ACTIVE") {
        events.push({
          id: `event-triage-${w.id}`,
          timestamp: w.timestamp,
          eventType: "ALERT_TRIAGE",
          severity: "INFO",
          title: `Incident Triage: ${w.status}`,
          description: `Web threat for ${w.domain} transitioned to ${w.status}. Notes: ${w.notes || "None"}`,
          target: w.domain,
          status: w.status,
          source: "SOC Triage Workflow",
          relatedId: w.id,
        });
      }
    }

    // Sort descending by timestamp
    events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    // Apply filtering
    let filtered = events;
    if (rawType !== "ALL") {
      filtered = filtered.filter((e) => e.eventType === rawType);
    }
    if (rawSeverity !== "ALL") {
      filtered = filtered.filter((e) => e.severity === rawSeverity);
    }

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    res.status(200).json({
      events: paginated,
      total,
      limit,
      offset,
    });
  } catch (err: unknown) {
    console.error("[Dashboard] Error generating security timeline:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to generate security event timeline",
      },
    });
  }
});

/**
 * GET /api/dashboard/system-health
 * Diagnostic health status reporting Render backend and verified PostgreSQL connectivity.
 */
dashboardRouter.get("/system-health", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const startPing = Date.now();
    let dbConnected = false;

    try {
      await postgresPool.query("SELECT 1");
      dbConnected = true;
    } catch {
      dbConnected = false;
    }

    const apiLatencyMs = Date.now() - startPing;

    // Check latest scan for endpoint telemetry freshness
    let lastScanUpload: string | null = null;
    let freshnessStatus: "FRESH" | "RECENT" | "STALE" | "NO_TELEMETRY" = "NO_TELEMETRY";
    let freshnessDescription = "No endpoint scan telemetry received yet.";

    try {
      const scans = await postgresService.getScans(uid);
      if (scans.length > 0) {
        lastScanUpload = scans[0].timestamp;
        const ageHours = (Date.now() - new Date(scans[0].timestamp).getTime()) / (1000 * 60 * 60);
        if (ageHours < 2) {
          freshnessStatus = "FRESH";
          freshnessDescription = `Latest telemetry ingested ${Math.round(ageHours * 60)} minutes ago.`;
        } else if (ageHours < 24) {
          freshnessStatus = "RECENT";
          freshnessDescription = `Latest telemetry ingested ${Math.round(ageHours)} hours ago.`;
        } else {
          freshnessStatus = "STALE";
          freshnessDescription = `Telemetry is ${Math.round(ageHours / 24)} days old. Run a new scan to update.`;
        }
      }
    } catch {
      // safe fallback
    }

    const health: SystemHealthStatus = {
      apiStatus: dbConnected ? "ONLINE" : "DEGRADED",
      apiVersion: "1.0.0",
      apiLatencyMs,
      database: {
        engine: "PostgreSQL",
        connected: dbConnected,
        verifiedAt: new Date().toISOString(),
      },
      lastScanUpload,
      lastDataRefresh: new Date().toISOString(),
      endpointTelemetryFreshness: {
        status: freshnessStatus,
        lastSeenAt: lastScanUpload,
        description: freshnessDescription,
      },
      monitoringNotice:
        "Endpoint telemetry is derived from periodic scan snapshots (PhantomTrace Windows Engine). Continuous real-time process monitoring requires the active background Agent Service.",
    };

    res.status(200).json({ health });
  } catch (err: unknown) {
    console.error("[Dashboard] Error checking system health:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to retrieve system health diagnostics",
      },
    });
  }
});
