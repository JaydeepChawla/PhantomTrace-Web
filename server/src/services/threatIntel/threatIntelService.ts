import type {
  ThreatIntelProvider,
  ThreatIntelResult,
  ProviderCheckStatus,
} from "./types";
import { normalizeUrlSafely } from "./urlNormalizer";
import { MockThreatIntelProvider } from "./mockProvider";
import { evaluateHeuristics, heuristicToResult } from "./heuristicEngine";

interface CacheEntry {
  result: ThreatIntelResult;
  expiresAt: number;
}

export class ThreatIntelService {
  private provider: ThreatIntelProvider;
  private cache: Map<string, CacheEntry> = new Map();
  private cacheTtlMs = 10 * 60 * 1000; // 10 minutes cache
  private errorTtlMs = 30 * 1000; // 30 seconds cache for errors
  private maxCacheSize = 1000;

  constructor(provider?: ThreatIntelProvider) {
    this.provider = provider || new MockThreatIntelProvider();
  }

  /**
   * Allows setting a custom threat intelligence provider (e.g. for testing).
   */
  public setProvider(provider: ThreatIntelProvider): void {
    this.provider = provider;
    this.cache.clear();
  }

  /**
   * Retrieves current provider name and cache statistics.
   */
  public getStatus(): { provider: string; cachedCount: number } {
    return {
      provider: this.provider.name,
      cachedCount: this.cache.size,
    };
  }

  /**
   * Clears the in-memory reputation cache.
   */
  public clearCache(): void {
    this.cache.clear();
  }

  /**
   * Checks a URL or domain against threat intelligence and conservative heuristics.
   */
  public async check(urlOrDomain: string): Promise<ThreatIntelResult> {
    const parsed = normalizeUrlSafely(urlOrDomain);

    if (!parsed.valid) {
      return {
        domain: parsed.domain || urlOrDomain,
        normalizedUrl: parsed.normalizedUrl,
        verdict: "UNKNOWN",
        severity: "NORMAL",
        score: 0,
        confidence: "LOW",
        source: "UNKNOWN",
        provider: this.provider.name,
        status: "ERROR",
        explanation: parsed.error || "Invalid or unsupported URL format.",
        checkedAt: new Date().toISOString(),
      };
    }

    const cacheKey = parsed.domain;
    const now = Date.now();

    // Check cache
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return {
        ...cached.result,
        cached: true,
      };
    }

    let tiResult: ThreatIntelResult;
    try {
      // Execute provider check with timeout safeguard (2500ms max)
      const timeoutPromise = new Promise<ThreatIntelResult>((_, reject) => {
        setTimeout(() => reject(new Error("PROVIDER_TIMEOUT")), 2500);
      });

      tiResult = await Promise.race([
        this.provider.checkDomain(parsed.domain, parsed.normalizedUrl),
        timeoutPromise,
      ]);
    } catch (err: any) {
      const isTimeout = err?.message === "PROVIDER_TIMEOUT";
      const status: ProviderCheckStatus = isTimeout ? "TIMEOUT" : "OFFLINE";
      tiResult = {
        domain: parsed.domain,
        normalizedUrl: parsed.normalizedUrl,
        verdict: "UNKNOWN",
        severity: "NORMAL",
        score: 0,
        confidence: "LOW",
        source: "THREAT_INTEL",
        provider: this.provider.name,
        status,
        explanation: isTimeout
          ? "Threat intelligence check timed out after 2500ms."
          : `Threat intelligence provider error: ${err?.message || "Connection failed"}`,
        checkedAt: new Date().toISOString(),
      };
    }

    let finalResult: ThreatIntelResult;

    // Handle provider check statuses
    if (tiResult.status === "TIMEOUT" || tiResult.status === "OFFLINE" || tiResult.status === "ERROR") {
      finalResult = tiResult;
      this._saveToCache(cacheKey, finalResult, this.errorTtlMs);
      return finalResult;
    }

    // If provider matched a known threat or benign domain
    if (tiResult.verdict !== "UNKNOWN") {
      finalResult = tiResult;
    } else {
      // No definitive threat intel match: run conservative heuristics
      const heuristic = evaluateHeuristics(parsed);
      if (heuristic.isSuspicious) {
        finalResult = heuristicToResult(parsed.domain, heuristic, parsed.normalizedUrl);
      } else {
        // Unknown domain with no suspicious heuristics -> return benign/unknown with score 0
        finalResult = {
          domain: parsed.domain,
          normalizedUrl: parsed.normalizedUrl,
          verdict: "UNKNOWN",
          severity: "NORMAL",
          score: 0,
          confidence: "LOW",
          source: "HEURISTIC",
          provider: this.provider.name,
          status: "SUCCESS",
          explanation: "Domain evaluated. No threat intelligence match or suspicious heuristic indicators found.",
          checkedAt: new Date().toISOString(),
        };
      }
    }

    this._saveToCache(cacheKey, finalResult, this.cacheTtlMs);
    return finalResult;
  }

  private _saveToCache(key: string, result: ThreatIntelResult, ttlMs: number): void {
    if (this.cache.size >= this.maxCacheSize) {
      // Evict oldest entry
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, {
      result,
      expiresAt: Date.now() + ttlMs,
    });
  }
}

export const threatIntelService = new ThreatIntelService();
