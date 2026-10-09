import { Router, Request, Response } from "express";
import crypto from "crypto";
import { authMiddleware } from "../middleware/auth";
import { threatIntelService } from "../services/threatIntel/threatIntelService";
import { normalizeUrlSafely } from "../services/threatIntel/urlNormalizer";
import { postgresService } from "../services/postgresService";
import { isValidIdentifier } from "../utils/validation";
import type { AuthenticatedRequest, WebThreatEventDocument } from "../types/api";

export const webThreatsRouter = Router();

/**
 * GET /api/web-threats/status
 * Service health & active threat-intelligence provider status.
 */
webThreatsRouter.get("/status", (_req: Request, res: Response): void => {
  const status = threatIntelService.getStatus();
  res.status(200).json({
    status: "ok",
    service: "PhantomTrace Web Threat Monitor",
    ...status,
  });
});

/**
 * POST /api/web-threats/check
 * Evaluates domain / URL reputation against threat intelligence and heuristics.
 * Safe public / authenticated endpoint. Query parameters and fragments are completely stripped.
 */
webThreatsRouter.post("/check", async (req: Request, res: Response): Promise<void> => {
  try {
    const rawTarget = req.body?.url || req.body?.domain;
    if (!rawTarget || typeof rawTarget !== "string") {
      res.status(400).json({
        error: {
          code: "INVALID_REQUEST",
          message: "Field 'url' or 'domain' is required and must be a non-empty string.",
        },
      });
      return;
    }

    const result = await threatIntelService.check(rawTarget);
    res.status(200).json({ result });
  } catch (err: any) {
    console.error("[WebThreats] Error checking URL reputation:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to evaluate web threat reputation.",
      },
    });
  }
});

/**
 * All endpoints below require authenticated user, device, or SOC owner.
 */
webThreatsRouter.use(authMiddleware);

/**
 * GET /api/web-threats/events
 * Retrieve persisted web threat events for authenticated user/device.
 */
webThreatsRouter.get("/events", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const events = await postgresService.getWebThreatEvents(uid);
    res.status(200).json({ events });
  } catch (err: any) {
    console.error("[WebThreats] Error listing web threat events:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to list web threat events.",
      },
    });
  }
});

/**
 * POST /api/web-threats/events
 * Ingests a detected browser web threat event.
 */
webThreatsRouter.post("/events", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const body = req.body || {};

    const rawDomain = body.domain || body.url;
    if (!rawDomain || typeof rawDomain !== "string") {
      res.status(400).json({
        error: {
          code: "INVALID_INPUT",
          message: "A valid 'domain' or 'url' is required.",
        },
      });
      return;
    }

    const normalized = normalizeUrlSafely(rawDomain);
    if (!normalized.valid) {
      res.status(400).json({
        error: {
          code: "MALFORMED_URL",
          message: normalized.error || "The supplied URL/domain is invalid.",
        },
      });
      return;
    }

    // Input sanitization and validations
    const validClassifications = new Set([
      "PHISHING",
      "MALWARE",
      "SUSPICIOUS_HEURISTIC",
      "UNWANTED_SOFTWARE",
      "UNKNOWN",
    ]);
    const classification = validClassifications.has(body.classification)
      ? body.classification
      : "SUSPICIOUS_HEURISTIC";

    const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL"]);
    const severity = validSeverities.has(body.severity) ? body.severity : "MEDIUM";

    const score = typeof body.score === "number" && body.score >= 0 && body.score <= 100
      ? body.score
      : (severity === "CRITICAL" ? 90 : severity === "HIGH" ? 75 : 50);

    const eventId =
      body.id && isValidIdentifier(body.id)
        ? body.id
        : `wte-${crypto.randomBytes(8).toString("hex")}`;

    const eventDoc: WebThreatEventDocument = {
      id: eventId,
      ownerUid: uid,
      deviceId: req.deviceId || body.deviceId || undefined,
      timestamp: body.timestamp && !isNaN(Date.parse(body.timestamp))
        ? new Date(body.timestamp).toISOString()
        : new Date().toISOString(),
      domain: normalized.domain,
      url: normalized.normalizedUrl,
      classification,
      severity,
      score,
      confidence: body.confidence === "HIGH" || body.confidence === "LOW" ? body.confidence : "MEDIUM",
      detectionSource: body.detectionSource || "THREAT_INTEL",
      ruleId: body.ruleId || undefined,
      explanation: typeof body.explanation === "string" ? body.explanation.slice(0, 500) : "Web threat detected.",
      browser: typeof body.browser === "string" ? body.browser.slice(0, 80) : undefined,
      notified: Boolean(body.notified),
      status: "ACTIVE",
    };

    await postgresService.createWebThreatEvent(eventDoc);

    res.status(201).json({
      success: true,
      eventId: eventDoc.id,
      message: "Web threat event recorded successfully.",
    });
  } catch (err: any) {
    console.error("[WebThreats] Error creating web threat event:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to ingest web threat event.",
      },
    });
  }
});

/**
 * POST /api/web-threats/events/:eventId/dismiss
 * Dismisses an active web threat event.
 */
webThreatsRouter.post("/events/:eventId/dismiss", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { eventId } = req.params;

    if (!isValidIdentifier(eventId)) {
      res.status(400).json({
        error: {
          code: "INVALID_IDENTIFIER",
          message: "Invalid eventId parameter format.",
        },
      });
      return;
    }

    const dismissed = await postgresService.dismissWebThreatEvent(uid, eventId);
    if (!dismissed) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Web threat event '${eventId}' not found or already dismissed.`,
        },
      });
      return;
    }

    res.status(200).json({
      success: true,
      eventId,
      status: "DISMISSED",
    });
  } catch (err: any) {
    console.error("[WebThreats] Error dismissing web threat event:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to dismiss web threat event.",
      },
    });
  }
});
