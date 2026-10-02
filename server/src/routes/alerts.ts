import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { firestoreService } from "../services/firestoreService";
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
    const alerts = await firestoreService.getThreatAlerts(uid);
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

    const alert = await firestoreService.getThreatAlert(uid, alertId);

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
