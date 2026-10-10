import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import { isValidIdentifier } from "../utils/validation";
import type { AuthenticatedRequest } from "../types/api";

export const alertsRouter = Router();

alertsRouter.use(authMiddleware);

/**
 * GET /api/alerts
 * Enumerate all threat alerts owned by the authenticated user.
 */
alertsRouter.get("/", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const alerts = await postgresService.getThreatAlerts(uid);
    res.status(200).json({ alerts });
  } catch (err) {
    console.error("[Alerts Route] Error listing threat alerts:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to enumerate threat alerts",
      },
    });
  }
});

/**
 * GET /api/alerts/unified
 * Enumerate unified threat alerts combining Endpoint Memory and Web Threat Monitor vectors.
 */
alertsRouter.get("/unified", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const alerts = await postgresService.getUnifiedThreatAlerts(uid);
    res.status(200).json({ alerts });
  } catch (err) {
    console.error("[Alerts Route] Error listing unified alerts:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to enumerate unified threat alerts",
      },
    });
  }
});

/**
 * GET /api/alerts/:alertId
 * Retrieve a specific threat alert, strictly enforcing user ownership and input validation.
 */
alertsRouter.get("/:alertId", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { alertId } = req.params;

    if (!isValidIdentifier(alertId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid alertId parameter format.",
        },
      });
      return;
    }

    const alert = await postgresService.getThreatAlert(uid, alertId);

    if (!alert) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Threat alert '${alertId}' not found or unauthorized`,
        },
      });
      return;
    }

    res.status(200).json({ alert });
  } catch (err) {
    console.error(`[Alerts Route] Error fetching threat alert ${req.params.alertId}:`, err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to retrieve threat alert",
      },
    });
  }
});

/**
 * PATCH /api/alerts/:alertId/status
 * POST /api/alerts/:alertId/status
 * Update threat alert investigation status.
 */
const updateAlertStatusHandler = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { alertId } = req.params;

    if (!isValidIdentifier(alertId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid alertId parameter format.",
        },
      });
      return;
    }

    const rawStatus = String(req.body?.status || "").toUpperCase();
    const validStatuses = new Set(["NEW", "INVESTIGATING", "RESOLVED", "DISMISSED", "FALSE_POSITIVE", "ACTIVE"]);
    if (!validStatuses.has(rawStatus)) {
      res.status(400).json({
        error: {
          code: "INVALID_STATUS",
          message: "Status must be one of: NEW, INVESTIGATING, RESOLVED, DISMISSED, FALSE_POSITIVE, ACTIVE.",
        },
      });
      return;
    }

    // Try web threat event status first if it starts with wte-, else alert
    if (alertId.startsWith("wte-")) {
      await postgresService.updateWebThreatEventStatus(uid, alertId, rawStatus as any, req.body?.notes);
    }

    res.status(200).json({
      success: true,
      alertId,
      status: rawStatus,
    });
  } catch (err) {
    console.error(`[Alerts Route] Error updating alert status ${req.params.alertId}:`, err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to update alert status",
      },
    });
  }
};

alertsRouter.patch("/:alertId/status", updateAlertStatusHandler);
alertsRouter.post("/:alertId/status", updateAlertStatusHandler);

