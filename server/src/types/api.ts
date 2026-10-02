import type { Request } from "express";

export type ThreatLevel =
  | "NORMAL"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type ScoreMode =
  | "MEMORY_ONLY"
  | "BEHAVIOR_ONLY"
  | "CORRELATED"
  | "BASELINE_ADJUSTED"
  | "NONE";

export interface AuthenticatedUser {
  uid: string;
  email?: string;
  displayName?: string;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
  ownerUid?: string;
}

export interface UserDocument {
  uid: string;
  email: string;
  displayName: string;
  role: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Firestore Document Model: endpoints/{endpointId}
 */
export interface EndpointDocument {
  endpointId: string;
  ownerUid: string;
  name: string;
  platform: string;
  scannerVersion: string;
  lastSeenAt: string;
  createdAt: string;
}

/**
 * Firestore Document Model: scans/{scanId}
 */
export interface ScanDocument {
  scanId: string;
  endpointId: string;
  ownerUid: string;
  timestamp: string;
  durationMs?: number;
  scannerVersion?: string;
  platform?: string;
  totalProcesses: number;
  memoryScanned?: number;
  memoryAccessDenied?: number;
  highestScore: number;
  counts: {
    normal: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

/**
 * Memory Evidence Substructure
 */
export interface MemoryEvidencePayload {
  present: boolean;
  strength?: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  indicators: string[];
  suspiciousRegions?: number;
  rwxRegions?: number;
  privateExecutableRegions?: number;
  executableWritableRegions?: number;
  scanStatus?: "SCANNED" | "ACCESS_DENIED" | "NOT_SCANNED";
  accessDenied?: boolean;
  details?: string[];
  timestamp?: string;
}

/**
 * Behavior Evidence Substructure
 */
export interface BehaviorEvidencePayload {
  present: boolean;
  score?: number;
  indicators: string[];
  suspiciousCommandLine?: boolean;
  suspiciousParent?: boolean;
  commandLine?: string;
  parentProcess?: string;
  details?: string[];
  timestamp?: string;
}

/**
 * Correlation Evidence Substructure
 */
export interface CorrelationEvidencePayload {
  present: boolean;
  score?: number;
  memoryEvidencePresent: boolean;
  behaviorEvidencePresent: boolean;
  correlatedIndicators: string[];
  explanation?: string;
  timestamp?: string;
}

/**
 * Firestore Document Model: processes/{processId}
 */
export interface ProcessDocument {
  processId: string;
  scanId: string;
  endpointId: string;
  ownerUid: string;
  pid: number;
  name: string;
  executablePath?: string;
  applicationName?: string;
  parentPid?: number;
  parentName?: string;
  threatScore: number;
  threatLevel: ThreatLevel;
  scoreMode: ScoreMode;
  behaviorScore?: number;
  memoryScore?: number;
  correlationScore?: number;
  memoryEvidence?: MemoryEvidencePayload;
  behaviorEvidence?: BehaviorEvidencePayload;
  correlationEvidence?: CorrelationEvidencePayload;
  timestamp: string;
  commandLine?: string;
  userContext?: string;
  integrityLevel?: string;
  responseRecommendation?: {
    whyFlagged: string;
    investigationSteps: string[];
    mitreReferences: string[];
    containmentGuidance: string;
    readOnlyNotice: string;
  };
}

/**
 * Firestore Document Model: threatAlerts/{alertId}
 */
export interface ThreatAlertDocument {
  id: string;
  scanId: string;
  endpointId: string;
  ownerUid: string;
  pid: number;
  processName: string;
  score: number;
  level: ThreatLevel;
  scoreMode: ScoreMode;
  title?: string;
  description?: string;
  memoryEvidence?: MemoryEvidencePayload;
  behaviorEvidence?: BehaviorEvidencePayload;
  correlationEvidence?: CorrelationEvidencePayload;
  detectedAt: string;
  status?: "NEW" | "INVESTIGATING" | "RESOLVED" | "DISMISSED";
  recommendedActions?: string[];
}

/**
 * Firestore Document Model: reports/{reportId}
 */
export interface ReportDocument {
  id: string;
  scanId: string;
  endpointId: string;
  ownerUid: string;
  createdAt: string;
  title: string;
  summary: string;
  totalProcesses: number;
  totalAlerts: number;
  highestScore: number;
  highestThreatLevel: ThreatLevel | string;
  alerts: ThreatAlertDocument[];
  generatedBy?: string;
  type?: string;
  size?: string;
  recordCount?: number;
}

/**
 * =====================================================================
 * PHASE 4: RAW WINDOWS SCANNER JSON & INGESTION CONTRACTS
 * =====================================================================
 */

export interface RawScannerMemoryRegion {
  base_address: number;
  region_size: number;
  state: number;
  protection: number;
  protection_name: string;
  memory_type: number;
  memory_type_name: string;
  suspicious: boolean;
  indicators: string[];
}

export interface RawScannerMemory {
  pid: number;
  name: string;
  executable?: string;
  status: string;
  total_regions?: number;
  executable_regions?: number;
  writable_executable_regions?: number;
  private_executable_regions?: number;
  suspicious_regions?: number;
  indicators?: string[];
  regions?: RawScannerMemoryRegion[];
  error?: string | null;
  threat_score?: number;
  evidence_strength?: string;
}

export interface RawScannerBehaviorIndicator {
  type: string;
  description: string;
  evidence?: unknown;
}

export interface RawScannerBehavior {
  score: number;
  status: string;
  indicator_count: number;
  indicators: string[];
  raw_indicators?: RawScannerBehaviorIndicator[];
  path_unavailable?: boolean;
}

export interface RawScannerProcess {
  pid: number;
  name: string;
  executable?: string;
  parent?: {
    pid: number | null;
    name: string | null;
  };
  behavior?: RawScannerBehavior;
  memory?: RawScannerMemory;
  application_context?: string;
  behavior_score?: number;
  memory_score?: number;
  process_score?: number;
  correlation_bonus?: number;
  correlation_findings?: string[];
  memory_evidence_strength?: string;
  memory_context_adjustment?: string;
  context_adjusted?: boolean;
  memory_only?: boolean;
  score_mode?: string;
  raw_score?: number;
  score: number;
  level: string;
  indicators?: string[];
  has_behavior_evidence?: boolean;
  has_memory_evidence?: boolean;
}

export interface RawScannerAlert {
  pid: number;
  name: string;
  score: number;
  level: string;
  application_context?: string;
  score_mode?: string;
  behavior_score?: number;
  memory_score?: number;
  process_score?: number;
  correlation_bonus?: number;
  memory_evidence_strength?: string;
  indicators?: string[];
}

export interface RawScannerSummary {
  total_processes: number;
  normal: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
  threat_alerts?: RawScannerAlert[];
  highest_score: number;
}

export interface RawScannerResult {
  phantomtrace_version?: string;
  platform?: string;
  scan_time_seconds?: number;
  timestamp?: string;
  endpoint_id?: string;
  machine_id?: string;
  summary: RawScannerSummary;
  results: RawScannerProcess[];
}

export interface IngestedScanBundle {
  endpoint: EndpointDocument;
  scan: ScanDocument;
  processes: ProcessDocument[];
  threatAlerts: ThreatAlertDocument[];
  report: ReportDocument;
  isDuplicate?: boolean;
}

export interface IngestResponse {
  success: boolean;
  scanId: string;
  endpointId: string;
  processesImported: number;
  alertsImported: number;
  highestScore: number;
  duplicate?: boolean;
  message?: string;
}


