/**
 * =====================================================================
 * PHANTOMTRACE WEB THREAT MONITOR — THREAT INTELLIGENCE TYPES
 * =====================================================================
 */

export type ThreatClassification =
  | "BENIGN"
  | "PHISHING"
  | "MALWARE"
  | "SUSPICIOUS_HEURISTIC"
  | "UNWANTED_SOFTWARE"
  | "POLICY_VIOLATION"
  | "UNKNOWN";

export type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NORMAL";

export type ThreatDetectionSource =
  | "THREAT_INTEL"
  | "HEURISTIC"
  | "REPUTATION_CACHE"
  | "POLICY_RULE"
  | "UNKNOWN";

export type ProviderCheckStatus =
  | "SUCCESS"
  | "TIMEOUT"
  | "OFFLINE"
  | "ERROR";

export interface ThreatIntelResult {
  domain: string;
  normalizedUrl?: string;
  verdict: ThreatClassification;
  severity: ThreatSeverity;
  score: number; // 0 - 100
  confidence: "HIGH" | "MEDIUM" | "LOW";
  source: ThreatDetectionSource;
  provider: string;
  status: ProviderCheckStatus;
  ruleId?: string;
  explanation: string;
  checkedAt: string;
  cached?: boolean;
}

export interface ThreatIntelProvider {
  readonly name: string;
  checkDomain(domain: string, normalizedUrl?: string): Promise<ThreatIntelResult>;
}
