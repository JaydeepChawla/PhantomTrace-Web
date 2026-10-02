import type {
  Process,
  ThreatAlert,
  MemoryEvidence,
  BehaviorEvidence,
  CorrelationEvidence,
  ScanResult,
  ScanHistory,
  Report,
  ThreatLevel,
  ScoreMode,
} from './index';

/**
 * Interface verifying that all 10 PhantomTrace models and types are imported and accessible.
 */
export interface ValidationModelFixture {
  threatLevel: ThreatLevel;
  scoreMode: ScoreMode;
  memoryEvidence: MemoryEvidence;
  behaviorEvidence: BehaviorEvidence;
  correlationEvidence: CorrelationEvidence;
  process: Process;
  threatAlert: ThreatAlert;
  scanResult: ScanResult;
  scanHistory: ScanHistory;
  report: Report;
}

export const sampleThreatLevel: ThreatLevel = "CRITICAL";
export const sampleScoreMode: ScoreMode = "CORRELATED";

export const sampleMemoryEvidence: MemoryEvidence = {
  present: true,
  strength: "HIGH",
  indicators: ["PAGE_EXECUTE_READWRITE allocation at non-module address"],
  suspiciousRegions: 2,
  rwxRegions: 1,
  privateExecutableRegions: 1,
  executableWritableRegions: 1,
  scanStatus: "SCANNED",
  accessDenied: false,
  details: ["Unbacked executable payload"],
  timestamp: "2026-10-02T12:00:00Z",
};

export const sampleBehaviorEvidence: BehaviorEvidence = {
  present: true,
  score: 85,
  indicators: ["Suspicious command line parameter -W Hidden"],
  suspiciousCommandLine: true,
  suspiciousParent: true,
  commandLine: "powershell.exe -W Hidden -Exec Bypass",
  parentProcess: "wscript.exe",
  details: ["Process Lineage Anomaly"],
  timestamp: "2026-10-02T12:00:00Z",
};

export const sampleCorrelationEvidence: CorrelationEvidence = {
  present: true,
  score: 90,
  memoryEvidencePresent: true,
  behaviorEvidencePresent: true,
  correlatedIndicators: ["PAGE_EXECUTE_READWRITE allocation", "Suspicious command line"],
  explanation: "Elevated correlation between unbacked memory allocation and obfuscated script invocation.",
  timestamp: "2026-10-02T12:00:00Z",
};

export const sampleProcess: Process = {
  pid: 4892,
  name: "powershell.exe",
  executablePath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  applicationName: "Windows PowerShell",
  parentPid: 3104,
  parentName: "wscript.exe",
  commandLine: "powershell.exe -NoP -NonI -W Hidden",
  threatScore: 94,
  threatLevel: "CRITICAL",
  scoreMode: "CORRELATED",
  behaviorScore: 92,
  memoryScore: 96,
  correlationScore: 94,
  memoryEvidence: sampleMemoryEvidence,
  behaviorEvidence: sampleBehaviorEvidence,
  correlationEvidence: sampleCorrelationEvidence,
  timestamp: "2026-10-02T12:00:00Z",
};

export const sampleThreatAlert: ThreatAlert = {
  id: "alt-001",
  pid: 4892,
  processName: "powershell.exe",
  score: 94,
  level: "CRITICAL",
  scoreMode: "CORRELATED",
  title: "In-Memory Payload Injection",
  description: "Unbacked RWX allocation detected with obfuscated script parentage.",
  memoryEvidence: sampleMemoryEvidence,
  behaviorEvidence: sampleBehaviorEvidence,
  correlationEvidence: sampleCorrelationEvidence,
  detectedAt: "2026-10-02T12:00:00Z",
  status: "NEW",
  recommendedActions: ["Isolate host", "Preserve memory dump"],
};

export const sampleScanResult: ScanResult = {
  scanId: "scan-20261002-001",
  timestamp: "2026-10-02T12:00:00Z",
  durationMs: 4200,
  scannerVersion: "v2.4.1-core",
  platform: "Windows 11 Pro 64-bit",
  totalProcesses: 150,
  memoryScanned: 3200,
  memoryAccessDenied: 2,
  highestScore: 94,
  counts: {
    normal: 140,
    low: 4,
    medium: 3,
    high: 2,
    critical: 1,
  },
  processes: [sampleProcess],
  alerts: [sampleThreatAlert],
};

export const sampleScanHistory: ScanHistory = {
  id: "hist-001",
  startedAt: "2026-10-02T12:00:00Z",
  completedAt: "2026-10-02T12:00:04Z",
  durationMs: 4200,
  status: "COMPLETED",
  totalProcesses: 150,
  totalAlerts: 1,
  highestScore: 94,
  highestThreatLevel: "CRITICAL",
  scannerVersion: "v2.4.1-core",
};

export const sampleReport: Report = {
  id: "rep-001",
  scanId: "scan-20261002-001",
  createdAt: "2026-10-02T12:01:00Z",
  title: "Endpoint Forensic Validation Report",
  summary: "Comprehensive scan completed. 1 critical threat identified.",
  totalProcesses: 150,
  totalAlerts: 1,
  highestScore: 94,
  highestThreatLevel: "CRITICAL",
  alerts: [sampleThreatAlert],
  generatedBy: "PHANTOMTRACE",
};

export const validationFixture: ValidationModelFixture = {
  threatLevel: sampleThreatLevel,
  scoreMode: sampleScoreMode,
  memoryEvidence: sampleMemoryEvidence,
  behaviorEvidence: sampleBehaviorEvidence,
  correlationEvidence: sampleCorrelationEvidence,
  process: sampleProcess,
  threatAlert: sampleThreatAlert,
  scanResult: sampleScanResult,
  scanHistory: sampleScanHistory,
  report: sampleReport,
};
