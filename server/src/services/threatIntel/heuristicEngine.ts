import type { ThreatIntelResult } from "./types";
import type { NormalizedUrlResult } from "./urlNormalizer";

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "buzz", "click", "work", "loan", "tk", "ml", "ga", "cf", "gq"
]);

const SENSITIVE_KEYWORDS = [
  "login", "signin", "verify", "account", "security", "update", "banking",
  "secure", "wallet", "authenticate", "credential", "recover", "support"
];

const TARGETED_BRANDS = [
  "paypal", "microsoft", "google", "apple", "amazon", "chase", "bankofamerica",
  "wellsfargo", "netflix", "phantomtrace", "binance", "coinbase"
];

export interface HeuristicEvaluation {
  isSuspicious: boolean;
  score: number;
  ruleId?: string;
  explanation: string;
}

/**
 * Analyzes normalized URLs using conservative heuristics.
 * Flags suspicious patterns for review without classifying unknown domains as malicious.
 */
export function evaluateHeuristics(parsed: NormalizedUrlResult): HeuristicEvaluation {
  if (!parsed.valid || !parsed.domain) {
    return {
      isSuspicious: false,
      score: 0,
      explanation: "Unable to evaluate heuristics on invalid URL.",
    };
  }

  const domain = parsed.domain.toLowerCase();

  // 1. Direct Public IP Address Navigation
  if (parsed.isIpAddress) {
    // Exempt local development loopback addresses
    if (domain === "127.0.0.1" || domain === "::1" || domain === "localhost") {
      return {
        isSuspicious: false,
        score: 0,
        explanation: "Loopback address is exempted from heuristics.",
      };
    }

    return {
      isSuspicious: true,
      score: 45,
      ruleId: "HEUR-DIRECT-IP",
      explanation: "Direct IP address navigation detected without a verified domain name.",
    };
  }

  // 2. Brand Typosquatting / Combination with Security Keywords
  // e.g. "paypal-security-update.com" or "microsoft-verify-login.xyz"
  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  const domainBody = parts.slice(0, -1).join(".");

  for (const brand of TARGETED_BRANDS) {
    // Skip if domain IS the legitimate brand domain (e.g. google.com, paypal.com)
    if (parts.length === 2 && parts[0] === brand) {
      continue;
    }
    if (parts.length >= 2 && parts[parts.length - 2] === brand) {
      continue;
    }

    if (domainBody.includes(brand)) {
      // Check if also includes suspicious phishing keywords
      const matchedKeyword = SENSITIVE_KEYWORDS.find((k) => domainBody.includes(k));
      if (matchedKeyword) {
        return {
          isSuspicious: true,
          score: 65,
          ruleId: "HEUR-BRAND-IMPERSONATION",
          explanation: `Suspicious brand impersonation pattern detected targeting '${brand}' with keyword '${matchedKeyword}'.`,
        };
      }

      // If suspicious TLD is used alongside the brand
      if (SUSPICIOUS_TLDS.has(tld)) {
        return {
          isSuspicious: true,
          score: 55,
          ruleId: "HEUR-BRAND-SUSPICIOUS-TLD",
          explanation: `Brand name '${brand}' detected under high-risk TLD '.${tld}'.`,
        };
      }
    }
  }

  // 3. Deceptive Subdomain Nesting with High-Risk TLD
  // e.g. login.secure.bank.account.malicious.xyz
  if (parts.length >= 5 && SUSPICIOUS_TLDS.has(tld)) {
    const hasSensitiveWord = SENSITIVE_KEYWORDS.some((kw) => domain.includes(kw));
    if (hasSensitiveWord) {
      return {
        isSuspicious: true,
        score: 50,
        ruleId: "HEUR-DECEPTIVE-SUBDOMAINS",
        explanation: "Deeply nested subdomain structure combined with authentication keywords on a high-risk TLD.",
      };
    }
  }

  // If no conservative heuristics matched, it is NOT suspicious
  return {
    isSuspicious: false,
    score: 0,
    explanation: "Conservative heuristic review passed. No high-risk patterns identified.",
  };
}

/**
 * Converts heuristic evaluation into a ThreatIntelResult.
 */
export function heuristicToResult(
  domain: string,
  heuristic: HeuristicEvaluation,
  normalizedUrl?: string
): ThreatIntelResult {
  return {
    domain,
    normalizedUrl,
    verdict: heuristic.isSuspicious ? "SUSPICIOUS_HEURISTIC" : "UNKNOWN",
    severity: heuristic.isSuspicious ? "MEDIUM" : "NORMAL",
    score: heuristic.score,
    confidence: "MEDIUM",
    source: "HEURISTIC",
    provider: "PhantomTrace-HeuristicEngine",
    status: "SUCCESS",
    ruleId: heuristic.ruleId,
    explanation: heuristic.explanation,
    checkedAt: new Date().toISOString(),
  };
}
