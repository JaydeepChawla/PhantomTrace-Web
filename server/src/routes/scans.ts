import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import { scannerAdapter, ScannerValidationError } from "../services/scannerAdapter";
import type { AuthenticatedRequest } from "../types/api";

export const scansRouter = Router();

// All scan operations require verified Firebase authentication
scansRouter.use(authMiddleware);

/**
 * POST /api/scans/ingest
 * Ingests completed PhantomTrace Windows scanner telemetry (scan_results.json).
 * Strictly requires authentication; derives ownerUid from verified Firebase ID token.
 */
scansRouter.post("/ingest", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const ownerUid = req.ownerUid!;
    const rawPayload = req.body;

    if (!rawPayload || typeof rawPayload !== "object" || Object.keys(rawPayload).length === 0) {
      res.status(400).json({
        error: {
          code: "INVALID_SCAN",
          message: "Invalid PhantomTrace scan data: Request body is empty or malformed JSON.",
        },
      });
      return;
    }

    // Optional client-provided metadata overrides (safe non-authority fields)
    const customTimestamp =
      typeof req.headers["x-scan-timestamp"] === "string"
        ? req.headers["x-scan-timestamp"]
        : typeof rawPayload.timestamp === "string"
        ? rawPayload.timestamp
        : undefined;

    const customEndpointId =
      req.deviceId ||
      (typeof req.headers["x-endpoint-id"] === "string"
        ? req.headers["x-endpoint-id"]
        : typeof rawPayload.endpoint_id === "string"
        ? rawPayload.endpoint_id
        : undefined);

    // Parse and adapt scanner telemetry into PhantomTrace models
    const bundle = scannerAdapter.parseScanResult(
      rawPayload,
      ownerUid,
      customTimestamp,
      customEndpointId
    );

    // Ingest into Firestore & user-scoped persistent stores
    const ingestResult = await postgresService.ingestScanBundle(bundle);

    const statusCode = ingestResult.duplicate ? 200 : 201;

    res.status(statusCode).json({
      success: true,
      scanId: ingestResult.scanId,
      endpointId: ingestResult.endpointId,
      processesImported: ingestResult.processesImported,
      alertsImported: ingestResult.alertsImported,
      highestScore: ingestResult.highestScore,
      duplicate: ingestResult.duplicate || false,
      message: ingestResult.message || "Scan successfully ingested and indexed.",
    });
  } catch (err: unknown) {
    if (err instanceof ScannerValidationError) {
      res.status(400).json({
        error: {
          code: err.code,
          message: err.message,
        },
      });
      return;
    }

    console.error("[Scans Ingest Route] Error ingesting scan:", err);
    res.status(500).json({
      error: {
        code: "INGESTION_ERROR",
        message: "An internal server error occurred while processing scan data.",
      },
    });
  }
});

/**
 * GET /api/scans
 * Enumerate all scan executions owned by the authenticated user.
 */
scansRouter.get("/", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const scans = await postgresService.getScans(uid);
    res.status(200).json({ scans });
  } catch (err) {
    console.error("[Scans Route] Error listing scans:", err);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to enumerate scans",
    });
  }
});

import { isValidIdentifier } from "../utils/validation";

/**
 * GET /api/scans/:scanId
 * Retrieve a specific scan session, strictly enforcing user ownership and input validation.
 */
scansRouter.get("/:scanId", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { scanId } = req.params;

    if (!isValidIdentifier(scanId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid scanId parameter format.",
        },
      });
      return;
    }

    const scan = await postgresService.getScan(uid, scanId);

    if (!scan) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Scan '${scanId}' not found or unauthorized`,
        },
      });
      return;
    }

    res.status(200).json({ scan });
  } catch (err) {
    console.error(`[Scans Route] Error fetching scan ${req.params.scanId}:`, err);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to retrieve scan",
    });
  }
});

