/**
 * PhantomTrace Types Index
 *
 * Exports real Phase 2.1 data models representing PhantomTrace endpoint telemetry,
 * as well as legacy UI/mock interfaces used by the current dashboard presentation layer.
 */

// Phase 2.1 — Real PhantomTrace TypeScript Data Models
export * from './phantomtrace';

// =====================================================================
// Legacy UI & Presentation Layer Models (Phase 1 Mock Support)
// Retained to support existing dashboard views until Phase 2.2 adapter integration.
// =====================================================================

export type ApplicationTrust = 
  | 'Trusted System'
  | 'Verified Third-Party'
  | 'Unverified Binary'
  | 'Script Host'
  | 'System Utility';

export interface MemoryEvidenceItem {
  id: string;
  type: string; // e.g. 'PAGE_EXECUTE_READWRITE Region', 'Unbacked Executable Memory', 'PE Header Discrepancy', 'Inline API Hook', 'Injected Thread Context'
  address: string;
  size: string;
  protection: string;
  details: string;
  severity: import('./phantomtrace').ThreatLevel | 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
}

export interface BehaviorEvidenceItem {
  id: string;
  category: string;
  description: string;
  mitreTechnique?: string;
  timestamp: string;
  confidence: 'High' | 'Medium' | 'Low';
}

export interface ProcessItem {
  pid: number;
  name: string;
  path: string;
  parentPid: number;
  parentName: string;
  commandLine: string;
  userContext: string;
  threatScore: number; // 0 - 100
  threatLevel: import('./phantomtrace').ThreatLevel | 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  application: ApplicationTrust;
  scoreMode: import('./phantomtrace').ScoreMode | 'Correlated' | 'Memory Only' | 'Behavior Only' | 'Baseline';
  behaviorScore: number;
  memoryScore: number;
  correlationSummary: string;
  memoryEvidenceCount: number;
  behaviorEvidenceCount: number;
  memoryIndicators: string[];
  memoryEvidence: MemoryEvidenceItem[];
  behaviorEvidence: BehaviorEvidenceItem[];
  timestamp: string;
  integrityLevel: 'System' | 'High' | 'Medium' | 'Low';
  startTime: string;
  responseRecommendation: {
    whyFlagged: string;
    investigationSteps: string[];
    mitreReferences: string[];
    containmentGuidance: string;
    readOnlyNotice: string;
  };
}

export interface ScanOverview {
  totalProcesses: number;
  threatAlertsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  normalCount?: number;
  highestThreatScore: number;
  scanTime: string;
  duration: string;
  memoryInspectedMb: number;
  engineVersion: string;
  scanMode: string;
  readOnlyEngineEnforced: boolean;
  scanId?: string;
  endpointId?: string;
  endpointName?: string;
}

export interface ScanHistoryItem {
  id: string;
  scanDate: string;
  processes: number;
  alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  highestScore: number;
  duration: string;
  status: 'Completed' | 'Investigation Flags' | 'Verified Clean';
  engineVersion: string;
}

export interface ReportItem {
  id: string;
  name: 'scan_results.json' | 'phantomtrace_validation_report.txt' | 'alert_history.json';
  type: 'json' | 'txt';
  size: string;
  lastModified: string;
  description: string;
  content: string;
  recordCount?: number;
}

export interface SystemSettings {
  scanner: {
    scannerId: string;
    engineMode: string;
    pollingIntervalSeconds: number;
    readOnlyEnforced: boolean;
    targetArchitecture: string;
    bufferMemoryLimitMb: number;
    telemetryProtocol: string;
  };
  api: {
    endpointUrl: string;
    apiKeyMasked: string;
    timeoutSeconds: number;
    ingestionStatus: string;
    corsOrigin: string;
    version: string;
  };
  firebase: {
    projectId: string;
    firestoreCollection: string;
    authDomain: string;
    storageBucket: string;
    realtimeSync: boolean;
    syncStatus: string;
  };
  auth: {
    currentAnalyst: string;
    role: string;
    organization: string;
    sessionExpiry: string;
    auditLoggingEnabled: boolean;
  };
}
