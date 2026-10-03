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
   * Extract raw process collection, prioritizing the real scanner's 'processes' key
   * while maintaining backward compatibility with 'results'.
   */
  public extractRawProcesses(raw: RawScannerResult): RawScannerProcess[] {
    if (Array.isArray(raw.processes)) {
      return raw.processes;
    }
    if (Array.isArray(raw.results)) {
      return raw.results;
    }
    return [];
  }

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
    const scanObj = raw.scan && typeof raw.scan === "object" ? (raw.scan as Record<string, unknown>) : undefined;

    const scanTimestamp =
      customTimestamp ||
      raw.timestamp ||
      raw.scan_time ||
      raw.scan_timestamp ||
      (typeof scanObj?.timestamp === "string" ? (scanObj.timestamp as string) : undefined) ||
      new Date().toISOString();

    const platform =
      (typeof raw.platform === "string" && raw.platform.trim().length > 0
        ? raw.platform.trim()
        : undefined) ||
      (typeof scanObj?.platform === "string" && (scanObj.platform as string).trim().length > 0
        ? (scanObj.platform as string).trim()
        : undefined) ||
      "Windows";

    const scannerVersion =
      raw.phantomtrace_version ||
      raw.scanner ||
      raw.version ||
      (typeof scanObj?.scanner_version === "string"
        ? (scanObj.scanner_version as string).trim()
        : undefined) ||
      "PhantomTrace 1.0";

    // 1. Establish stable, deterministic identifiers
    const scanId = this.deriveScanId(raw);
    const endpointId = this.deriveEndpointId(raw, ownerUid, customEndpointId);

    // 2. Map Endpoint Document
    const endpoint: EndpointDocument = {
      endpointId,
      ownerUid,
      name: `${platform.toUpperCase()}-ENDPOINT-${endpointId.slice(-6).toUpperCase()}`,
      platform,
      scannerVersion,
      lastSeenAt: scanTimestamp,
      createdAt: scanTimestamp,
    };

    // 3. Map Inspected Processes
    const rawProcesses = this.extractRawProcesses(raw);
    const processes: ProcessDocument[] = rawProcesses.map((proc) =>
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

    for (const p of rawProcesses) {
      if (
        p.memory?.status === "access_denied" ||
        (typeof p.exe === "string" && p.exe.toLowerCase().includes("access denied"))
      ) {
        accessDeniedCount++;
      }
      if (p.memory?.regions) {
        for (const r of p.memory.regions) {
          totalMemoryScannedBytes += r.region_size || 0;
        }
      } else if (p.memory_rss || p.memory_vms) {
        totalMemoryScannedBytes += (p.memory_rss || 0) + (p.memory_vms || 0);
      }
    }

    const memoryScannedMb = Math.round((totalMemoryScannedBytes / (1024 * 1024)) * 10) / 10;

    // Derive summary metrics if missing or incomplete
    const summaryNormal =
      raw.summary?.normal ??
      processes.filter((p) => p.threatLevel === "NORMAL").length;
    const summaryLow =
      raw.summary?.low ??
      processes.filter((p) => p.threatLevel === "LOW").length;
    const summaryMedium =
      raw.summary?.medium ??
      processes.filter((p) => p.threatLevel === "MEDIUM").length;
    const summaryHigh =
      raw.summary?.high ??
      processes.filter((p) => p.threatLevel === "HIGH").length;
    const summaryCritical =
      raw.summary?.critical ??
      processes.filter((p) => p.threatLevel === "CRITICAL").length;

    let computedHighestScore = 0;
    for (const p of processes) {
      if (p.threatScore > computedHighestScore) computedHighestScore = p.threatScore;
    }
    for (const a of threatAlerts) {
      if (a.score > computedHighestScore) computedHighestScore = a.score;
    }

    const highestScore = raw.summary?.highest_score ?? computedHighestScore;
    const totalProcesses =
      raw.summary?.total_processes ?? raw.process_count ?? processes.length;

    let durationMs = 4000;
    if (typeof raw.scan_time_seconds === "number") {
      durationMs = Math.round(raw.scan_time_seconds * 1000);
    } else if (typeof scanObj?.duration_ms === "number") {
      durationMs = Math.round(scanObj.duration_ms as number);
    } else if (typeof scanObj?.scan_time_seconds === "number") {
      durationMs = Math.round((scanObj.scan_time_seconds as number) * 1000);
    }

    // 6. Map Scan Document
    const scan: ScanDocument = {
      scanId,
      endpointId,
      ownerUid,
      timestamp: scanTimestamp,
      durationMs,
      scannerVersion,
      platform,
      totalProcesses,
      memoryScanned: memoryScannedMb,
      memoryAccessDenied: accessDeniedCount,
      highestScore,
      counts: {
        normal: summaryNormal,
        low: summaryLow,
        medium: summaryMedium,
        high: summaryHigh,
        critical: summaryCritical,
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
   * Validate raw scanner JSON structure. Accepts real scanner payloads with
   * top-level 'processes' array, as well as legacy 'results' payloads.
   */
  public validateRawPayload(raw: unknown): asserts raw is RawScannerResult {
    if (!raw || typeof raw !== "object") {
      throw new ScannerValidationError("Payload must be a non-null JSON object.");
    }

    const candidate = raw as Record<string, unknown>;

    // Real scanner uses 'processes', legacy/sample uses 'results'
    const processes = candidate.processes ?? candidate.results;
    if (!Array.isArray(processes)) {
      throw new ScannerValidationError("Malformed scan data: missing or non-array 'processes' collection.");
    }

    if (candidate.summary !== undefined && (typeof candidate.summary !== "object" || candidate.summary === null)) {
      throw new ScannerValidationError("Malformed scan data: 'summary' must be a valid metadata object.");
    }

    if (candidate.alerts !== undefined && !Array.isArray(candidate.alerts)) {
      throw new ScannerValidationError("Malformed scan data: 'alerts' must be a valid collection.");
    }

    if (candidate.scan !== undefined && (typeof candidate.scan !== "object" || candidate.scan === null)) {
      throw new ScannerValidationError("Malformed scan data: 'scan' must be a valid metadata object.");
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
    const scanObj = raw.scan && typeof raw.scan === "object" ? (raw.scan as Record<string, unknown>) : undefined;
    if (scanObj) {
      if (typeof scanObj.scan_id === "string" && scanObj.scan_id.trim().length > 0) {
        return scanObj.scan_id.trim();
      }
      if (typeof scanObj.scanId === "string" && scanObj.scanId.trim().length > 0) {
        return scanObj.scanId.trim();
      }
    }

    const procs = this.extractRawProcesses(raw);
    const version = raw.phantomtrace_version || raw.scanner || raw.version || "pt-1.0";
    const platform = raw.platform || (scanObj?.platform as string) || "Windows";
    const scanTime = raw.scan_time || raw.scan_timestamp || raw.timestamp || "";
    const duration = raw.scan_time_seconds ?? (scanObj?.scan_time_seconds as number) ?? 0;
    const procCount = raw.summary?.total_processes ?? raw.process_count ?? procs.length;
    const highestScore = raw.summary?.highest_score ?? 0;

    // Deterministic hash based on version, platform, duration, process count, and sample processes
    const hashBasis = [
      version,
      platform,
      scanTime,
      duration,
      procCount,
      highestScore,
      procs.length,
      // Sample first 3 PIDs for uniqueness
      procs.slice(0, 3).map((p) => `${p.pid}:${p.score ?? p.threat_score ?? 0}`).join(";"),
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

    const scanObj = raw.scan && typeof raw.scan === "object" ? (raw.scan as Record<string, unknown>) : undefined;
    if (scanObj) {
      if (typeof scanObj.endpoint_id === "string" && (scanObj.endpoint_id as string).trim().length > 0) {
        return (scanObj.endpoint_id as string).trim();
      }
      if (typeof scanObj.machine_id === "string" && (scanObj.machine_id as string).trim().length > 0) {
        return (scanObj.machine_id as string).trim();
      }
    }

    // Stable endpoint hash per user and host platform
    const platform = raw.platform || (scanObj?.platform as string) || "Windows";
    const endpointHash = crypto
      .createHash("sha256")
      .update(`${platform}-${ownerUid}`)
      .digest("hex")
      .slice(0, 10);

    return `ep-win-${endpointHash}`;
  }

  /**
   * Map raw process item to ProcessDocument, extracting fields from both real scanner
   * telemetry ('exe', 'cmdline', 'parent_pid', etc.) and legacy models.
   */
  public mapProcess(
    p: RawScannerProcess,
    scanId: string,
    endpointId: string,
    ownerUid: string,
    timestamp: string
  ): ProcessDocument {
    const rawScore = p.score ?? p.threat_score ?? (typeof p.risk_score === "number" ? p.risk_score : undefined);
    const threatScore = Math.min(100, Math.max(0, Math.round(typeof rawScore === "number" ? rawScore : 0)));

    const rawLevel = p.level ?? p.threat_level ?? p.severity ?? p.risk_level;

    const threatLevel = this.mapThreatLevel(
      typeof rawLevel === "string"
        ? rawLevel
        : threatScore >= 90
        ? "CRITICAL"
        : threatScore >= 75
        ? "HIGH"
        : threatScore >= 40
        ? "MEDIUM"
        : threatScore >= 20
        ? "LOW"
        : "NORMAL"
    );

    const scoreMode = this.mapScoreMode(p.score_mode);
    const applicationName = this.mapApplicationContext(p.application_context);

    const memoryEvidence = this.mapMemoryEvidence(p, timestamp);
    const behaviorEvidence = this.mapBehaviorEvidence(p, timestamp);
    const correlationEvidence = this.mapCorrelationEvidence(p, timestamp);

    const executablePath =
      p.executable ||
      p.exe ||
      (typeof p.executable_path === "string" ? p.executable_path : undefined) ||
      (typeof p.path === "string" ? p.path : undefined) ||
      (typeof p.image_path === "string" ? p.image_path : undefined) ||
      undefined;

    const parentPid =
      p.parent?.pid ??
      p.parent_pid ??
      (typeof p.parentPid === "number" ? (p.parentPid as number) : undefined) ??
      undefined;

    const parentName =
      p.parent?.name ??
      p.parent_name ??
      (typeof p.parentName === "string" ? (p.parentName as string) : undefined) ??
      undefined;

    const rawCmd = p.commandLine ?? p.command_line ?? p.cmdline;
    const commandLine =
      typeof rawCmd === "string" && rawCmd.trim().length > 0
        ? rawCmd.trim()
        : Array.isArray(rawCmd) && rawCmd.length > 0
        ? rawCmd.join(" ")
        : undefined;

    const userContext =
      p.userContext ??
      p.username ??
      (typeof p.user_context === "string" ? (p.user_context as string) : undefined) ??
      undefined;

    const processDoc: ProcessDocument = {
      processId: `proc-${scanId.slice(0, 10)}-${p.pid}`,
      scanId,
      endpointId,
      ownerUid,
      pid: p.pid,
      name: p.name || "Unknown Process",
      executablePath: executablePath || undefined,
      applicationName,
      parentPid,
      parentName,
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
      commandLine,
      userContext,
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
    const indicators = [...(mem?.indicators || [])];
    const isAccessDenied =
      mem?.status === "access_denied" ||
      (typeof p.exe === "string" && p.exe.toLowerCase().includes("access denied"));

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

    // Real scanner process memory info
    if (p.memory_rss !== undefined || p.memory_vms !== undefined) {
      const rssKb = p.memory_rss ? Math.round(p.memory_rss / 1024) : 0;
      const vmsKb = p.memory_vms ? Math.round(p.memory_vms / 1024) : 0;
      details.push(`Memory RSS: ${rssKb} KB, VMS: ${vmsKb} KB.`);
    }

    const hasIndicators = indicators.length > 0;
    const present = Boolean(p.has_memory_evidence || hasIndicators || (mem?.suspicious_regions && mem.suspicious_regions > 0));

    return {
      present,
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
    const indicators = [...(beh?.indicators || [])];
    if (Array.isArray(p.indicators)) {
      for (const ind of p.indicators) {
        if (!indicators.includes(ind)) indicators.push(ind);
      }
    }
    const hasIndicators = indicators.length > 0;

    const details = beh?.raw_indicators
      ? beh.raw_indicators.map((r) => r.description).filter((d): d is string => typeof d === "string")
      : [];

    const parentProcess = p.parent?.name ?? p.parent_name ?? undefined;

    const rawCmd = p.commandLine ?? p.command_line ?? p.cmdline;
    const commandLine =
      typeof rawCmd === "string" && rawCmd.trim().length > 0
        ? rawCmd.trim()
        : Array.isArray(rawCmd) && rawCmd.length > 0
        ? rawCmd.join(" ")
        : undefined;

    return {
      present: Boolean(p.has_behavior_evidence || hasIndicators),
      score: p.behavior_score ?? beh?.score ?? 0,
      indicators,
      suspiciousCommandLine: indicators.some((i) => i.toLowerCase().includes("command")),
      suspiciousParent: indicators.some((i) => i.toLowerCase().includes("parent")),
      commandLine,
      parentProcess,
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
   * Map threat alerts from raw summary alerts, top-level alerts collection,
   * and elevated processes.
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

    // 1. Process explicit top-level alerts (real scanner format)
    if (Array.isArray(raw.alerts)) {
      for (const alert of raw.alerts) {
        const alertPid = alert.pid ?? alert.process?.pid ?? 0;
        seenPids.add(alertPid);
        const matched = processMap.get(alertPid);
        alerts.push(this.mapSingleThreatAlert(alert, matched, scanId, endpointId, ownerUid, timestamp));
      }
    }

    // 2. Process explicit summary alerts (legacy format)
    if (raw.summary?.threat_alerts && Array.isArray(raw.summary.threat_alerts)) {
      for (const alert of raw.summary.threat_alerts) {
        const alertPid = alert.pid ?? alert.process?.pid ?? 0;
        if (!seenPids.has(alertPid)) {
          seenPids.add(alertPid);
          const matched = processMap.get(alertPid);
          alerts.push(this.mapSingleThreatAlert(alert, matched, scanId, endpointId, ownerUid, timestamp));
        }
      }
    }

    // 3. Also promote any process with CRITICAL or HIGH score not already in summary alerts
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
    const alertPid = alert.pid ?? alert.process?.pid ?? matched?.pid ?? 0;
    const processName =
      alert.name ??
      alert.process_name ??
      alert.process?.name ??
      matched?.name ??
      "Unknown Process";

    const score = Math.round(
      alert.score ?? alert.threat_score ?? matched?.threatScore ?? 0
    );
    const level = this.mapThreatLevel(
      alert.level ?? alert.threat_level ?? alert.severity ?? matched?.threatLevel
    );
    const scoreMode = this.mapScoreMode(alert.score_mode ?? matched?.scoreMode);

    const alertId =
      alert.id ||
      alert.alert_id ||
      `alert-pt-${scanId.slice(-8)}-${alertPid}`;

    const recommendedActions =
      alert.recommended_actions ??
      (alert.recommended_action
        ? [alert.recommended_action]
        : [
            `Review process lineage and execution context for PID ${alertPid} (${processName})`,
            "Inspect memory region allocations for unbacked executable pages or RWX sections",
            "Correlate with Windows Event Log (Sysmon / PowerShell ScriptBlock)",
            "Enforce read-only containment protocols; do not alter endpoint state",
          ]);

    let behaviorEvidence = alert.behavior_evidence || matched?.behaviorEvidence;
    let memoryEvidence = alert.memory_evidence || matched?.memoryEvidence;
    const correlationEvidence = alert.correlation_evidence || matched?.correlationEvidence;

    if (alert.evidence && Array.isArray(alert.evidence) && alert.evidence.length > 0) {
      if (!behaviorEvidence) {
        behaviorEvidence = {
          present: true,
          indicators: alert.evidence,
          timestamp,
        };
      } else {
        const combined = Array.from(new Set([...behaviorEvidence.indicators, ...alert.evidence]));
        behaviorEvidence = { ...behaviorEvidence, indicators: combined, present: true };
      }
    }

    return {
      id: alertId,
      scanId,
      endpointId,
      ownerUid,
      pid: alertPid,
      processName,
      score,
      level,
      scoreMode,
      title: alert.title || `${level} Threat Finding: ${processName} (Score: ${score}/100)`,
      description:
        alert.description ||
        `Elevated risk detected on ${processName} (PID ${alertPid}) using ${scoreMode} analysis. Strength: ${
          alert.memory_evidence_strength || matched?.memoryEvidence?.strength || "MODERATE"
        }.`,
      memoryEvidence,
      behaviorEvidence,
      correlationEvidence,
      detectedAt: alert.timestamp || timestamp,
      status: (alert.status as ThreatAlertDocument["status"]) || "NEW",
      recommendedActions,
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
