/**
 * PhantomTrace Core TypeScript Data Models
 * Phase 2.1 & Phase 2.2 — Real endpoint scanner telemetry, evidence, and report structures.
 *
 * These models define the clean web application internal data representations
 * for real telemetry originating from the PhantomTrace Windows scanner.
 */

/**
 * Categorical threat severity classification.
 * Standard levels: "NORMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL".
 */
export type ThreatLevel =
  | "NORMAL"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

/**
 * Scoring mode indicating which heuristic detection engines contributed to the computed threat score.
 */
export type ScoreMode =
  | "MEMORY_ONLY"
  | "BEHAVIOR_ONLY"
  | "CORRELATED"
  | "BASELINE_ADJUSTED"
  | "NONE";

/**
 * Evidence discovered during read-only process memory analysis.
 *
 * Evidence is a signal used by the threat-scoring system.
 * It does not independently prove malicious activity.
 */
export interface MemoryEvidence {
  /** Indicates whether memory anomalies or indicators were detected. */
  present: boolean;

  /** Qualitative evaluation of evidence strength. */
  strength?: "NONE" | "LOW" | "MEDIUM" | "HIGH";

  /** Specific memory indicator strings (e.g., unbacked executable pages, RWX sections). */
  indicators: string[];

  /** Count of suspicious memory regions identified. */
  suspiciousRegions?: number;

  /** Count of regions allocated with PAGE_EXECUTE_READWRITE permissions. */
  rwxRegions?: number;

  /** Count of private commit regions marked as executable (MEM_PRIVATE + executable). */
  privateExecutableRegions?: number;

  /** Count of executable memory regions that are also writable. */
  executableWritableRegions?: number;

  /** Operational status of the memory inspection engine for this process. */
  scanStatus?: "SCANNED" | "ACCESS_DENIED" | "NOT_SCANNED";

  /** Indicates whether memory inspection was blocked due to insufficient privileges or protected process status. */
  accessDenied?: boolean;

  /** Detailed technical observations and region breakdown. */
  details?: string[];

  /** Timestamp when memory analysis took place. */
  timestamp?: string;
}

/**
 * Behavioral telemetry indicators observed from process creation, lineage, and execution context.
 *
 * Captures observable behaviors without hardcoded detection rules.
 */
export interface BehaviorEvidence {
  /** Indicates whether behavioral indicators were detected. */
  present: boolean;

  /** Independent behavioral threat score component (0-100). */
  score?: number;

  /** List of detected behavioral indicator descriptors. */
  indicators: string[];

  /** Flag indicating anomalous or obfuscated command-line execution parameters. */
  suspiciousCommandLine?: boolean;

  /** Flag indicating abnormal parent-child process relationship. */
  suspiciousParent?: boolean;

  /** Full command line invocation string captured during inspection. */
  commandLine?: string;

  /** Name of the parent process observed. */
  parentProcess?: string;

  /** Additional contextual behavioral notes or forensic details. */
  details?: string[];

  /** Timestamp when behavioral telemetry was recorded. */
  timestamp?: string;
}

/**
 * Evidence correlation linking memory anomalies with behavioral patterns.
 *
 * Correlation synthesizes existing evidence to evaluate co-occurrence.
 * It must describe existing evidence and NOT invent evidence.
 */
export interface CorrelationEvidence {
  /** Indicates whether meaningful correlation was established between evidence domains. */
  present: boolean;

  /** Correlation confidence or severity score contribution (0-100). */
  score?: number;

  /** Whether supporting memory evidence was present in the correlation evaluation. */
  memoryEvidencePresent: boolean;

  /** Whether supporting behavioral evidence was present in the correlation evaluation. */
  behaviorEvidencePresent: boolean;

  /** Specific indicators from memory and behavior that correlate together. */
  correlatedIndicators: string[];

  /** Human-readable explanation of why the correlation was flagged. */
  explanation?: string;

  /** Timestamp of the correlation evaluation. */
  timestamp?: string;
}

/**
 * Represents a running process on the host system inspected by PhantomTrace.
 * Contains forensic metadata, threat scores, and associated evidence.
 */
export interface Process {
  /** Windows Process Identifier (PID). */
  pid: number;

  /** Name of the process image (e.g., 'powershell.exe'). */
  name: string;

  /** Absolute filesystem path to the executable image on disk, if accessible. */
  executablePath?: string;

  /** UI presentation path alias. */
  path?: string;

  /** Friendly application name or binary classification (e.g., 'Windows PowerShell'). */
  applicationName?: string;

  /** UI presentation application classification alias. */
  application?: string;

  /** Parent Process Identifier (PPID) that spawned this process. */
  parentPid?: number;

  /** Name of the parent process image (e.g., 'explorer.exe'). */
  parentName?: string;

  /** Full command line string invoked to launch the process. */
  commandLine?: string;

  /** Overall computed threat score (0-100). */
  threatScore: number;

  /** Categorical threat severity classification. */
  threatLevel: ThreatLevel;

  /** Scoring engine mode evaluated for this process. */
  scoreMode: ScoreMode;

  /** Component score derived from behavioral telemetry (0-100). */
  behaviorScore?: number;

  /** Component score derived from memory inspection (0-100). */
  memoryScore?: number;

  /** Cross-domain correlation score evaluating co-occurring behavioral and memory indicators. */
  correlationScore?: number;

  /** Read-only virtual memory analysis evidence. */
  memoryEvidence?: MemoryEvidence;

  /** Observable behavioral indicators and lineage telemetry. */
  behaviorEvidence?: BehaviorEvidence;

  /** Correlated analysis linking memory anomalies with behavioral patterns. */
  correlationEvidence?: CorrelationEvidence;

  /** Scan timestamp in ISO 8601 or formatted UTC string. */
  timestamp: string;

  // Optional presentation and forensic fields
  /** User security context under which the process executes. */
  userContext?: string;

  /** Total count of suspicious memory evidence indicators. */
  memoryEvidenceCount?: number;

  /** Total count of suspicious behavioral signals. */
  behaviorEvidenceCount?: number;

  /** List of detected memory indicator labels. */
  memoryIndicators?: string[];

  /** Process token integrity level (System, High, Medium, Low). */
  integrityLevel?: string;

  /** Process launch timestamp. */
  startTime?: string;

  /** High-level correlation narrative summary. */
  correlationSummary?: string;

  /** Remediation and containment guidance. */
  responseRecommendation?: {
    whyFlagged: string;
    investigationSteps: string[];
    mitreReferences: string[];
    containmentGuidance: string;
    readOnlyNotice: string;
  };

  /** Detailed individual memory region allocations and heuristics. */
  detailedMemoryEvidence?: MemoryEvidenceRegion[];

  /** Detailed individual behavioral signals mapped to MITRE techniques. */
  detailedBehaviorEvidence?: BehaviorEvidenceSignal[];
}

/**
 * Detailed telemetry representation of an inspected memory region.
 */
export interface MemoryEvidenceRegion {
  id: string;
  type: string;
  address: string;
  size: string;
  protection: string;
  details: string;
  severity: ThreatLevel | string;
}

/**
 * Detailed telemetry representation of an observed behavioral signal.
 */
export interface BehaviorEvidenceSignal {
  id: string;
  category: string;
  description: string;
  mitreTechnique?: string;
  timestamp: string;
  confidence: "High" | "Medium" | "Low" | string;
}

/**
 * Security alert representing an elevated threat finding requiring analyst attention.
 * Supports the multi-stage investigation workflow:
 * Alert -> Why detected? -> Memory Evidence -> Behavior Evidence -> Correlation -> Recommended Response
 */
export interface ThreatAlert {
  /** Unique alert identifier. */
  id: string;

  /** Process Identifier associated with the alert. */
  pid: number;

  /** Process image name (e.g., 'powershell.exe'). */
  processName: string;

  /** Threat score associated with the alert (0-100). */
  score: number;

  /** Severity classification level. */
  level: ThreatLevel;

  /** Scoring engine mode that triggered the alert. */
  scoreMode: ScoreMode;

  /** Short descriptive headline for the threat alert. */
  title?: string;

  /** Contextual overview of why the process was flagged. */
  description?: string;

  /** Detailed memory evidence backing this alert, if applicable. */
  memoryEvidence?: MemoryEvidence;

  /** Detailed behavioral evidence backing this alert, if applicable. */
  behaviorEvidence?: BehaviorEvidence;

  /** Detailed correlation analysis backing this alert, if applicable. */
  correlationEvidence?: CorrelationEvidence;

  /** Timestamp when the threat alert was generated. */
  detectedAt: string;

  /** Triage and investigation lifecycle status. */
  status?: "NEW" | "INVESTIGATING" | "RESOLVED" | "DISMISSED";

  /** Prescriptive, non-destructive investigation and containment steps. */
  recommendedActions?: string[];

  // Optional presentation compatibility fields for legacy UI
  process?: string;
  threatScore?: number;
  threatLevel?: string;
  application?: string;
  behaviorScore?: number;
  memoryScore?: number;
  correlation?: string;
  timestamp?: string;
}

/**
 * Comprehensive result of a complete PhantomTrace endpoint scan execution.
 * Represents real scanner output encompassing inspected processes and generated alerts.
 */
export interface ScanResult {
  /** Unique scan execution session identifier. */
  scanId: string;

  /** Timestamp when the scan was executed. */
  timestamp: string;

  /** Scan execution duration in milliseconds. */
  durationMs?: number;

  /** Engine and rule version of the PhantomTrace scanner. */
  scannerVersion?: string;

  /** Host operating system platform string (e.g., 'Windows 11 Pro 64-bit'). */
  platform?: string;

  /** Total number of active processes enumerated and analyzed. */
  totalProcesses: number;

  /** Total virtual memory inspected across all processes in megabytes. */
  memoryScanned?: number;

  /** Number of processes where memory inspection encountered ACCESS_DENIED. */
  memoryAccessDenied?: number;

  /** Highest single threat score recorded among all processes during the scan. */
  highestScore: number;

  /** Categorical distribution of process threat classifications. */
  counts: {
    normal: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
  };

  /** Array of all inspected process entities. */
  processes: Process[];

  /** Array of elevated alerts generated during the scan. */
  alerts: ThreatAlert[];

  // Optional presentation compatibility fields for dashboard view
  threatAlertsCount?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  highestThreatScore?: number;
  scanTime?: string;
  duration?: string;
  memoryInspectedMb?: number;
  engineVersion?: string;
  scanMode?: string;
  readOnlyEngineEnforced?: boolean;
}

/**
 * Summary record of a past or ongoing scan execution used by the Scan History view.
 */
export interface ScanHistory {
  /** Unique historical scan identifier. */
  id: string;

  /** Timestamp when the scan initiated. */
  startedAt: string;

  /** Timestamp when the scan concluded, if finished. */
  completedAt?: string;

  /** Total scan duration in milliseconds. */
  durationMs?: number;

  /** Execution state of the scan. */
  status: "RUNNING" | "COMPLETED" | "FAILED" | string;

  /** Total processes analyzed during the scan. */
  totalProcesses: number;

  /** Total threat alerts generated during the scan. */
  totalAlerts: number;

  /** Highest threat score recorded during the scan. */
  highestScore?: number;

  /** Maximum threat level observed across all processes in the scan. */
  highestThreatLevel?: ThreatLevel | string;

  /** Version of the scanner engine utilized. */
  scannerVersion?: string;

  // Optional presentation compatibility fields for history table
  scanDate?: string;
  processes?: number;
  alerts?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  duration?: string;
  engineVersion?: string;
}

/**
 * Formatted security report generated from scan findings for analyst review and export.
 */
export interface Report {
  /** Unique report identifier. */
  id: string;

  /** Identifier of the scan session from which this report was generated. */
  scanId: string;

  /** Creation timestamp of the report. */
  createdAt: string;

  /** Title of the forensic report. */
  title: string;

  /** Executive summary synthesized from scan observations. */
  summary: string;

  /** Total number of processes covered in the report. */
  totalProcesses: number;

  /** Total number of elevated threat alerts detailed in the report. */
  totalAlerts: number;

  /** Peak threat score recorded. */
  highestScore: number;

  /** Peak threat severity classification. */
  highestThreatLevel: ThreatLevel | string;

  /** Collection of threat alerts documented within the report. */
  alerts: ThreatAlert[];

  /** Designator of the generating engine. */
  generatedBy?: "PHANTOMTRACE";

  // Optional presentation compatibility fields for reports page
  name?: string;
  type?: 'json' | 'txt' | string;
  size?: string;
  lastModified?: string;
  description?: string;
  content?: string;
  recordCount?: number;
}
