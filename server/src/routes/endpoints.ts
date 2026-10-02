import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { firestoreService } from "../services/firestoreService";
import { isValidIdentifier } from "../utils/validation";
import type { AuthenticatedRequest } from "../types/api";

export const endpointsRouter = Router();

// All endpoint routes strictly require Firebase authentication
endpointsRouter.use(authMiddleware);

/**
 * GET /api/endpoints
 * Enumerate all endpoints owned by the authenticated user.
 */
endpointsRouter.get("/", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const endpoints = await firestoreService.getEndpoints(uid);
    res.status(200).json({ endpoints });
  } catch (err) {
    console.error("[Endpoints Route] Error listing endpoints:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to enumerate endpoints",
      },
    });
  }
});

/**
 * GET /api/endpoints/:endpointId
 * Retrieve a specific endpoint, strictly enforcing user ownership and input validation.
 */
endpointsRouter.get("/:endpointId", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { endpointId } = req.params;

    if (!isValidIdentifier(endpointId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid endpointId parameter format.",
        },
      });
      return;
    }

    const endpoint = await firestoreService.getEndpoint(uid, endpointId);

    if (!endpoint) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Endpoint '${endpointId}' not found or unauthorized`,
        },
      });
      return;
    }

    res.status(200).json({ endpoint });
  } catch (err) {
    console.error(`[Endpoints Route] Error fetching endpoint ${req.params.endpointId}:`, err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to retrieve endpoint",
      },
    });
  }
});
