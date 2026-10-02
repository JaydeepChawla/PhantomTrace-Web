import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import { isValidIdentifier } from "../utils/validation";
import type { AuthenticatedRequest } from "../types/api";

export const processesRouter = Router();

processesRouter.use(authMiddleware);

/**
 * GET /api/processes
 * Enumerate all inspected processes owned by the authenticated user.
 */
processesRouter.get("/", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const processes = await postgresService.getProcesses(uid);
    res.status(200).json({ processes });
  } catch (err) {
    console.error("[Processes Route] Error listing processes:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to enumerate processes",
      },
    });
  }
});

/**
 * GET /api/processes/:processId
 * Retrieve detailed process telemetry by document ID or numerical PID.
 * Strictly verifies ownerUid matches authenticated user and validates parameter format.
 */
processesRouter.get("/:processId", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { processId } = req.params;

    if (!isValidIdentifier(processId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid processId parameter format.",
        },
      });
      return;
    }

    const process = await postgresService.getProcess(uid, processId);

    if (!process) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Process '${processId}' not found or unauthorized`,
        },
      });
      return;
    }

    res.status(200).json({ process });
  } catch (err) {
    console.error(`[Processes Route] Error fetching process ${req.params.processId}:`, err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to retrieve process",
      },
    });
  }
});

