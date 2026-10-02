import crypto from "crypto";
import type {
  ThreatLevel,
  ScoreMode,
  EndpointDocument,
  ScanDocument,
  ProcessDocument,
  ThreatAlertDocument,
  ReportDocument,
  MemoryEvidencePayload,
  BehaviorEvidencePayload,
  CorrelationEvidencePayload,
  RawScannerResult,
  RawScannerProcess,
  RawScannerAlert,
  IngestedScanBundle,
} from "../types/api";

/**
 * Custom error class for invalid or malformed scanner JSON payloads.
 */
export class ScannerValidationError extends Error {
  public readonly code = "INVALID_SCAN";
  constructor(message: string) {
    super(message);
    this.name = "ScannerValidationError";
  }
}

/**
 * =====================================================================
 * SCANNER JSON ADAPTER SERVICE
 * =====================================================================
 * Converts Windows scanner JSON telemetry into strongly-typed PhantomTrace
 * models without mutating scanner detection output or losing forensic evidence.
 * =====================================================================
 */
export class ScannerAdapter {
  /**
   * Validate and parse raw scanner JSON payload into an IngestedScanBundle.
   */
  public parseScanResult(
    rawPayload: unknown,
    ownerUid: string,
    customTimestamp?: string,
    customEndpointId?: string
  ): IngestedScanBundle {
    this.validateRawPayload(rawPayload);

    const raw = rawPayload as RawScannerResult;
    const scanTimestamp = customTimestamp || raw.timestamp || new Date().toISOString();

    // 1. Establish stable, deterministic identifiers
    const scanId = this.deriveScanId(raw);
    const endpointId = this.deriveEndpointId(raw, ownerUid, customEndpointId);

    // 2. Map Endpoint Document
    const endpoint: EndpointDocument = {
      endpointId,
      ownerUid,
      name: `${(raw.platform || "Windows").toUpperCase()}-ENDPOINT-${endpointId.slice(-6).toUpperCase()}`,
      platform: raw.platform || "Windows",
      scannerVersion: raw.phantomtrace_version || "PhantomTrace 1.0",
      lastSeenAt: scanTimestamp,
      createdAt: scanTimestamp,
    };

    // 3. Map Inspected Processes
    const processes: ProcessDocument[] = raw.results.map((proc) =>
      this.mapProcess(proc, scanId, endpointId, ownerUid, scanTimestamp)
    );

    // 4. Map Threat Alerts
    const processMap = new Map<number, ProcessDocument>();
    for (const p of processes) {
      processMap.set(p.pid, p);
    }

    const threatAlerts = this.mapThreatAlerts(
      raw,
      processes,
      processMap,
      scanId,
      endpointId,
      ownerUid,
      scanTimestamp
    );

    // 5. Compute memory inspection statistics
    let totalMemoryScannedBytes = 0;
    let accessDeniedCount = 0;

    for (const p of raw.results) {
      if (p.memory?.status === "access_denied") {
        accessDeniedCount++;
      }
      if (p.memory?.regions) {
        for (const r of p.memory.regions) {
          totalMemoryScannedBytes += r.region_size || 0;
        }
      }
    }

    const memoryScannedMb = Math.round((totalMemoryScannedBytes / (1024 * 1024)) * 10) / 10;

    // 6. Map Scan Document
    const scan: ScanDocument = {
      scanId,
      endpointId,
      ownerUid,
      timestamp: scanTimestamp,
      durationMs: raw.scan_time_seconds ? Math.round(raw.scan_time_seconds * 1000) : 4000,
      scannerVersion: raw.phantomtrace_version || "PhantomTrace 1.0",
      platform: raw.platform || "Windows",
      totalProcesses: raw.summary.total_processes || processes.length,
      memoryScanned: memoryScannedMb,
      memoryAccessDenied: accessDeniedCount,
      highestScore: raw.summary.highest_score || 0,
      counts: {
        normal: raw.summary.normal || 0,
        low: raw.summary.low || 0,
        medium: raw.summary.medium || 0,
        high: raw.summary.high || 0,
        critical: raw.summary.critical || 0,
      },
    };

    // 7. Map Forensic Report Document
    const report: ReportDocument = {
      id: `rep-${scanId}`,
      scanId,
      endpointId,
      ownerUid,
      createdAt: scanTimestamp,
      title: `Endpoint Forensic Scan Report — ${endpoint.name}`,
      summary: `PhantomTrace executed a read-only endpoint inspection across ${scan.totalProcesses} active processes in ${(
        (scan.durationMs || 0) / 1000
      ).toFixed(2)} seconds. Identified ${threatAlerts.length} elevated threat alerts with a peak threat score of ${
        scan.highestScore
      }/100. Read-only integrity was strictly preserved across all operations.`,
      totalProcesses: scan.totalProcesses,
      totalAlerts: threatAlerts.length,
      highestScore: scan.highestScore,
      highestThreatLevel:
        scan.highestScore >= 90
          ? "CRITICAL"
          : scan.highestScore >= 75
          ? "HIGH"
          : scan.highestScore >= 40
          ? "MEDIUM"
          : scan.highestScore >= 20
          ? "LOW"
          : "NORMAL",
      alerts: threatAlerts,
      generatedBy: "PHANTOMTRACE",
      type: "json",
      size: `${Math.round((JSON.stringify(raw).length / 1024) * 10) / 10} KB`,
      recordCount: scan.totalProcesses,
    };

    return {
      endpoint,
      scan,
      processes,
      threatAlerts,
      report,
    };
  }

  /**
   * Validate raw scanner JSON structure.
   */
  public validateRawPayload(raw: unknown): asserts raw is RawScannerResult {
    if (!raw || typeof raw !== "object") {
      throw new ScannerValidationError("Payload must be a non-null JSON object.");
    }

    const candidate = raw as Record<string, unknown>;

    if (!Array.isArray(candidate.results)) {
      throw new ScannerValidationError("Malformed scan data: missing or non-array 'results' collection.");
    }

    if (!candidate.summary || typeof candidate.summary !== "object") {
      throw new ScannerValidationError("Malformed scan data: missing 'summary' metadata object.");
    }

    const summary = candidate.summary as Record<string, unknown>;
    if (typeof summary.total_processes !== "number" || typeof summary.highest_score !== "number") {
      throw new ScannerValidationError("Malformed scan summary: missing numeric process or score metrics.");
    }
  }

  /**
   * Generate a deterministic, stable Scan ID from scan payload contents.
   */
  public deriveScanId(raw: RawScannerResult): string {
    const rawRecord = raw as unknown as Record<string, unknown>;
    if (typeof rawRecord.scan_id === "string" && rawRecord.scan_id.trim().length > 0) {
      return rawRecord.scan_id.trim();
    }
    if (typeof rawRecord.scanId === "string" && rawRecord.scanId.trim().length > 0) {
      return rawRecord.scanId.trim();
    }

    // Deterministic hash based on version, platform, duration, and summary counts
    const hashBasis = [
      raw.phantomtrace_version || "pt-1.0",
      raw.platform || "Windows",
      raw.scan_time_seconds ?? 0,
      raw.summary.total_processes,
      raw.summary.highest_score,
      raw.summary.critical,
      raw.summary.high,
      raw.results.length,
      // Sample first 3 PIDs for uniqueness
      raw.results.slice(0, 3).map((p) => `${p.pid}:${p.score}`).join(";"),
    ].join("|");

    const hash = crypto.createHash("sha256").update(hashBasis).digest("hex").slice(0, 16);
    return `scan-${hash}`;
  }

  /**
   * Derive or resolve a stable Endpoint ID.
   */
  public deriveEndpointId(
    raw: RawScannerResult,
    ownerUid: string,
    explicitEndpointId?: string
  ): string {
    if (explicitEndpointId && explicitEndpointId.trim().length > 0) {
      return explicitEndpointId.trim();
    }

    if (raw.endpoint_id && raw.endpoint_id.trim().length > 0) {
      return raw.endpoint_id.trim();
    }

    if (raw.machine_id && raw.machine_id.trim().length > 0) {
      return raw.machine_id.trim();
    }

    // Stable endpoint hash per user and host platform
    const endpointHash = crypto
      .createHash("sha256")
      .update(`${raw.platform || "Windows"}-${ownerUid}`)
      .digest("hex")
      .slice(0, 10);

    return `ep-win-${endpointHash}`;
  }

  /**
   * Map raw process item to ProcessDocument.
   */
  public mapProcess(
    p: RawScannerProcess,
    scanId: string,
    endpointId: string,
    ownerUid: string,
    timestamp: string
  ): ProcessDocument {
    const threatScore = Math.min(100, Math.max(0, Math.round(p.score || 0)));
    const threatLevel = this.mapThreatLevel(p.level);
    const scoreMode = this.mapScoreMode(p.score_mode);
    const applicationName = this.mapApplicationContext(p.application_context);

    const memoryEvidence = this.mapMemoryEvidence(p, timestamp);
    const behaviorEvidence = this.mapBehaviorEvidence(p, timestamp);
    const correlationEvidence = this.mapCorrelationEvidence(p, timestamp);

    const processDoc: ProcessDocument = {
      processId: `proc-${scanId.slice(0, 10)}-${p.pid}`,
      scanId,
      endpointId,
      ownerUid,
      pid: p.pid,
      name: p.name || "Unknown Process",
      executablePath: p.executable || undefined,
      applicationName,
      parentPid: p.parent?.pid ?? undefined,
      parentName: p.parent?.name ?? undefined,
      threatScore,
      threatLevel,
      scoreMode,
      behaviorScore: p.behavior_score ?? p.behavior?.score ?? 0,
      memoryScore: p.memory_score ?? p.memory?.threat_score ?? 0,
      correlationScore: p.correlation_bonus ?? 0,
      memoryEvidence,
      behaviorEvidence,
      correlationEvidence,
      timestamp,
      commandLine: undefined,
      userContext: undefined,
      integrityLevel: undefined,
    };

    if (threatScore >= 60 || threatLevel === "CRITICAL" || threatLevel === "HIGH") {
      processDoc.responseRecommendation = this.generateResponseRecommendation(p, threatScore);
    }

    return processDoc;
  }

  /**
   * Map memory evidence from raw process data.
   */
  public mapMemoryEvidence(p: RawScannerProcess, timestamp: string): MemoryEvidencePayload {
    const mem = p.memory;
    const indicators = mem?.indicators || [];
    const hasIndicators = indicators.length > 0;
    const isAccessDenied = mem?.status === "access_denied";

    let scanStatus: "SCANNED" | "ACCESS_DENIED" | "NOT_SCANNED" = "NOT_SCANNED";
    if (isAccessDenied) {
      scanStatus = "ACCESS_DENIED";
    } else if (mem?.status === "scanned") {
      scanStatus = "SCANNED";
    }

    const details: string[] = [];
    if (mem?.error) details.push(mem.error);
    if (mem?.total_regions) details.push(`Inspected ${mem.total_regions} virtual memory regions.`);
    if (mem?.suspicious_regions) details.push(`Identified ${mem.suspicious_regions} anomalous regions.`);

    return {
      present: p.has_memory_evidence || hasIndicators,
      strength: this.mapStrength(p.memory_evidence_strength || mem?.evidence_strength),
      indicators,
      suspiciousRegions: mem?.suspicious_regions || 0,
      rwxRegions: mem?.writable_executable_regions || 0,
      privateExecutableRegions: mem?.private_executable_regions || 0,
      executableWritableRegions: mem?.writable_executable_regions || 0,
      scanStatus,
      accessDenied: isAccessDenied,
      details: details.length > 0 ? details : undefined,
      timestamp,
    };
  }

  /**
   * Map behavioral evidence from raw process data.
   */
  public mapBehaviorEvidence(p: RawScannerProcess, timestamp: string): BehaviorEvidencePayload {
    const beh = p.behavior;
    const indicators = beh?.indicators || [];
    const hasIndicators = indicators.length > 0;

    const details = beh?.raw_indicators
      ? beh.raw_indicators.map((r) => r.description).filter((d): d is string => typeof d === "string")
      : [];

    return {
      present: p.has_behavior_evidence || hasIndicators,
      score: p.behavior_score ?? beh?.score ?? 0,
      indicators,
      suspiciousCommandLine: indicators.some((i) => i.toLowerCase().includes("command")),
      suspiciousParent: indicators.some((i) => i.toLowerCase().includes("parent")),
      commandLine: undefined,
      parentProcess: p.parent?.name || undefined,
      details: details.length > 0 ? details : undefined,
      timestamp,
    };
  }

  /**
   * Map correlation evidence from raw process data.
   */
  public mapCorrelationEvidence(p: RawScannerProcess, timestamp: string): CorrelationEvidencePayload {
    const findings = p.correlation_findings || [];
    const bonus = p.correlation_bonus || 0;
    const isCorrelated = findings.length > 0 || bonus > 0;

    return {
      present: isCorrelated,
      score: bonus,
      memoryEvidencePresent: Boolean(p.has_memory_evidence),
      behaviorEvidencePresent: Boolean(p.has_behavior_evidence),
      correlatedIndicators: findings,
      explanation: isCorrelated
        ? `Co-occurring signals detected: ${findings.join(", ") || "Cross-domain heuristic correlation"} (+${bonus} score bonus).`
        : undefined,
      timestamp,
    };
  }

  /**
   * Map threat alerts from raw summary alerts and elevated processes.
   */
  public mapThreatAlerts(
    raw: RawScannerResult,
    processes: ProcessDocument[],
    processMap: Map<number, ProcessDocument>,
    scanId: string,
    endpointId: string,
    ownerUid: string,
    timestamp: string
  ): ThreatAlertDocument[] {
    const alerts: ThreatAlertDocument[] = [];
    const seenPids = new Set<number>();

    // 1. Process explicit summary alerts
    if (raw.summary.threat_alerts && Array.isArray(raw.summary.threat_alerts)) {
      for (const alert of raw.summary.threat_alerts) {
        seenPids.add(alert.pid);
        const matched = processMap.get(alert.pid);
        alerts.push(this.mapSingleThreatAlert(alert, matched, scanId, endpointId, ownerUid, timestamp));
      }
    }

    // 2. Also promote any process with CRITICAL or HIGH score not already in summary alerts
    for (const proc of processes) {
      if (!seenPids.has(proc.pid) && (proc.threatLevel === "CRITICAL" || proc.threatLevel === "HIGH" || proc.threatScore >= 75)) {
        seenPids.add(proc.pid);
        alerts.push({
          id: `alert-pt-${scanId.slice(-8)}-${proc.pid}`,
          scanId,
          endpointId,
          ownerUid,
          pid: proc.pid,
          processName: proc.name,
          score: proc.threatScore,
          level: proc.threatLevel,
          scoreMode: proc.scoreMode,
          title: `${proc.threatLevel} Alert: ${proc.name} (PID: ${proc.pid})`,
          description: `Process ${proc.name} flagged with threat score ${proc.threatScore}/100. Score mode: ${proc.scoreMode}.`,
          memoryEvidence: proc.memoryEvidence,
          behaviorEvidence: proc.behaviorEvidence,
          correlationEvidence: proc.correlationEvidence,
          detectedAt: timestamp,
          status: "NEW",
          recommendedActions: [
            `Audit execution origin and parent process for ${proc.name} (PID: ${proc.pid})`,
            "Verify memory allocations for unbacked executable code or RWX pages",
            "Maintain read-only monitoring; avoid active termination until scope verified",
          ],
        });
      }
    }

    return alerts;
  }

  private mapSingleThreatAlert(
    alert: RawScannerAlert,
    matched: ProcessDocument | undefined,
    scanId: string,
    endpointId: string,
    ownerUid: string,
    timestamp: string
  ): ThreatAlertDocument {
    const score = Math.round(alert.score || matched?.threatScore || 0);
    const level = this.mapThreatLevel(alert.level || matched?.threatLevel);
    const scoreMode = this.mapScoreMode(alert.score_mode || matched?.scoreMode);

    return {
      id: `alert-pt-${scanId.slice(-8)}-${alert.pid}`,
      scanId,
      endpointId,
      ownerUid,
      pid: alert.pid,
      processName: alert.name || matched?.name || "Unknown Process",
      score,
      level,
      scoreMode,
      title: `${level} Threat Finding: ${alert.name} (Score: ${score}/100)`,
      description: `Elevated risk detected on ${alert.name} (PID ${alert.pid}) using ${scoreMode} analysis. Strength: ${
        alert.memory_evidence_strength || matched?.memoryEvidence?.strength || "MODERATE"
      }.`,
      memoryEvidence: matched?.memoryEvidence,
      behaviorEvidence: matched?.behaviorEvidence,
      correlationEvidence: matched?.correlationEvidence,
      detectedAt: timestamp,
      status: "NEW",
      recommendedActions: [
        `Review process lineage and execution context for PID ${alert.pid} (${alert.name})`,
        "Inspect memory region allocations for unbacked executable pages or RWX sections",
        "Correlate with Windows Event Log (Sysmon / PowerShell ScriptBlock)",
        "Enforce read-only containment protocols; do not alter endpoint state",
      ],
    };
  }

  /**
   * Helper: Map threat level string to categorical ThreatLevel.
   */
  public mapThreatLevel(level?: string): ThreatLevel {
    const upper = (level || "").toUpperCase();
    if (upper === "CRITICAL") return "CRITICAL";
    if (upper === "HIGH") return "HIGH";
    if (upper === "MEDIUM") return "MEDIUM";
    if (upper === "LOW") return "LOW";
    return "NORMAL";
  }

  /**
   * Helper: Map score mode string to ScoreMode.
   */
  public mapScoreMode(mode?: string): ScoreMode {
    const upper = (mode || "").toUpperCase();
    if (upper.includes("CORRELATED") || upper.includes("CORRELATION")) return "CORRELATED";
    if (upper.includes("MEMORY_ONLY") || upper.includes("MEMORY")) return "MEMORY_ONLY";
    if (upper.includes("BEHAVIOR_ONLY") || upper.includes("BEHAVIOR")) return "BEHAVIOR_ONLY";
    if (upper.includes("BASELINE")) return "BASELINE_ADJUSTED";
    return "NONE";
  }

  /**
   * Helper: Map application context string.
   */
  public mapApplicationContext(ctx?: string): string {
    const upper = (ctx || "").toUpperCase();
    if (upper.includes("TRUSTED") || upper.includes("COMMON")) return "Trusted Application";
    if (upper.includes("SYSTEM")) return "System Binary";
    if (upper.includes("SCRIPT")) return "Script Interpreter";
    return "Standard Windows Process";
  }

  /**
   * Helper: Map evidence strength.
   */
  public mapStrength(strength?: string): "NONE" | "LOW" | "MEDIUM" | "HIGH" {
    const upper = (strength || "").toUpperCase();
    if (upper.includes("VERY_STRONG") || upper.includes("HIGH")) return "HIGH";
    if (upper.includes("MODERATE") || upper.includes("MEDIUM")) return "MEDIUM";
    if (upper.includes("WEAK") || upper.includes("LOW")) return "LOW";
    return "NONE";
  }

  /**
   * Helper: Non-destructive investigation recommendations for high/critical threats.
   */
  public generateResponseRecommendation(p: RawScannerProcess, score: number) {
    const indicators = p.indicators || [];
    const mitre: string[] = [];
    if (p.name?.toLowerCase().includes("powershell")) mitre.push("T1059.001 - PowerShell");
    if (p.memory?.writable_executable_regions) mitre.push("T1055 - Process Injection (RWX Memory)");
    if (mitre.length === 0) mitre.push("T1055 - Defense Evasion & Memory Execution");

    return {
      whyFlagged: `Threat score ${score}/100 triggered by indicators: ${indicators.join(", ") || "Elevated anomaly threshold"}.`,
      investigationSteps: [
        `Inspect process tree for parent PID ${p.parent?.pid ?? "unknown"} (${p.parent?.name ?? "unknown"})`,
        `Audit memory regions for executable unbacked allocations (${p.memory?.suspicious_regions ?? 0} suspicious regions)`,
        "Review corresponding security event logs for script block logging or command invocation",
      ],
      mitreReferences: mitre,
      containmentGuidance: "Isolate endpoint on the network if anomalous command patterns or beaconing are suspected. Maintain read-only monitoring.",
      readOnlyNotice: "PhantomTrace operates strictly in read-only analysis mode. No processes were terminated, modified, or quarantined.",
    };
  }
}

export const scannerAdapter = new ScannerAdapter();
