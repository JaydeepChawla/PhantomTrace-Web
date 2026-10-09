import type {
  ThreatIntelProvider,
  ThreatIntelResult,
  ThreatClassification,
  ThreatSeverity,
} from "./types";

interface KnownDomainRecord {
  verdict: ThreatClassification;
  severity: ThreatSeverity;
  score: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  explanation: string;
  ruleId: string;
}

/**
 * Controlled mock threat intelligence provider.
 * Allows deterministic automated testing of malicious, benign, timeout, and offline states
 * without relying on external third-party network APIs.
 */
export class MockThreatIntelProvider implements ThreatIntelProvider {
  public readonly name = "PhantomTrace-Mock-ThreatIntel";
  private timeoutDurationMs = 2000;
  private forceOffline = false;

  private knownDomains: Map<string, KnownDomainRecord> = new Map([
    [
      "phishing-bank-login.com",
      {
        verdict: "PHISHING",
        severity: "HIGH",
        score: 85,
        confidence: "HIGH",
        explanation: "Domain matches confirmed financial phishing threat indicator feed (TI-RULE-7412).",
        ruleId: "TI-RULE-7412",
      },
    ],
    [
      "malware-drop-test.xyz",
      {
        verdict: "MALWARE",
        severity: "CRITICAL",
        score: 95,
        confidence: "HIGH",
        explanation: "Confirmed active malware distribution host serving malicious second-stage binaries.",
        ruleId: "TI-RULE-8801",
      },
    ],
    [
      "credential-harvest-portal.info",
      {
        verdict: "PHISHING",
        severity: "HIGH",
        score: 82,
        confidence: "HIGH",
        explanation: "Confirmed credential harvesting landing page mimicking corporate SSO.",
        ruleId: "TI-RULE-6109",
      },
    ],
    [
      "fake-update-installer.top",
      {
        verdict: "UNWANTED_SOFTWARE",
        severity: "HIGH",
        score: 78,
        confidence: "HIGH",
        explanation: "Deceptive installer distributing unwanted software bundles.",
        ruleId: "TI-RULE-5231",
      },
    ],
    [
      "google.com",
      {
        verdict: "BENIGN",
        severity: "NORMAL",
        score: 0,
        confidence: "HIGH",
        explanation: "Verified benign domain with positive global reputation.",
        ruleId: "REPUTATION-VERIFIED",
      },
    ],
    [
      "microsoft.com",
      {
        verdict: "BENIGN",
        severity: "NORMAL",
        score: 0,
        confidence: "HIGH",
        explanation: "Verified benign domain with positive global reputation.",
        ruleId: "REPUTATION-VERIFIED",
      },
    ],
    [
      "github.com",
      {
        verdict: "BENIGN",
        severity: "NORMAL",
        score: 0,
        confidence: "HIGH",
        explanation: "Verified benign domain with positive global reputation.",
        ruleId: "REPUTATION-VERIFIED",
      },
    ],
    [
      "example.com",
      {
        verdict: "BENIGN",
        severity: "NORMAL",
        score: 0,
        confidence: "HIGH",
        explanation: "IANA reserved benign documentation domain.",
        ruleId: "REPUTATION-RESERVED",
      },
    ],
    [
      "phantomtrace.security",
      {
        verdict: "BENIGN",
        severity: "NORMAL",
        score: 0,
        confidence: "HIGH",
        explanation: "PhantomTrace official security namespace.",
        ruleId: "REPUTATION-INTERNAL",
      },
    ],
  ]);

  /** Configure offline simulation mode */
  public setOffline(offline: boolean): void {
    this.forceOffline = offline;
  }

  /**
   * Check domain against the controlled threat intelligence repository.
   */
  async checkDomain(domain: string, normalizedUrl?: string): Promise<ThreatIntelResult> {
    const checkedAt = new Date().toISOString();

    if (this.forceOffline || domain === "offline-test.phantomtrace.local") {
      return {
        domain,
        normalizedUrl,
        verdict: "UNKNOWN",
        severity: "NORMAL",
        score: 0,
        confidence: "LOW",
        source: "THREAT_INTEL",
        provider: this.name,
        status: "OFFLINE",
        explanation: "Threat intelligence service is currently offline or unreachable.",
        checkedAt,
      };
    }

    if (domain === "timeout-test.phantomtrace.local") {
      // Return TIMEOUT status
      return {
        domain,
        normalizedUrl,
        verdict: "UNKNOWN",
        severity: "NORMAL",
        score: 0,
        confidence: "LOW",
        source: "THREAT_INTEL",
        provider: this.name,
        status: "TIMEOUT",
        explanation: `Reputation check timed out after ${this.timeoutDurationMs}ms.`,
        checkedAt,
      };
    }

    const match = this.knownDomains.get(domain);
    if (match) {
      return {
        domain,
        normalizedUrl,
        verdict: match.verdict,
        severity: match.severity,
        score: match.score,
        confidence: match.confidence,
        source: "THREAT_INTEL",
        provider: this.name,
        status: "SUCCESS",
        ruleId: match.ruleId,
        explanation: match.explanation,
        checkedAt,
      };
    }

    // Domain is not in the threat intelligence dataset: return UNKNOWN
    return {
      domain,
      normalizedUrl,
      verdict: "UNKNOWN",
      severity: "NORMAL",
      score: 0,
      confidence: "LOW",
      source: "THREAT_INTEL",
      provider: this.name,
      status: "SUCCESS",
      explanation: "No known threat intelligence match or reputation record found.",
      checkedAt,
    };
  }
}
