import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import { isValidIdentifier } from "../utils/validation";
import type { AuthenticatedRequest } from "../types/api";

export const reportsRouter = Router();

reportsRouter.use(authMiddleware);

/**
 * GET /api/reports
 * Enumerate all forensic reports owned by the authenticated user.
 */
reportsRouter.get("/", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const reports = await postgresService.getReports(uid);
    res.status(200).json({ reports });
  } catch (err) {
    console.error("[Reports Route] Error listing reports:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to enumerate reports",
      },
    });
  }
});

/**
 * POST /api/reports/generate-unified
 * Synthesize and generate an authoritative unified SOC incident and threat audit report.
 */
reportsRouter.post("/generate-unified", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const report = await postgresService.generateUnifiedSocReport(uid);
    res.status(201).json({
      success: true,
      report,
      message: "Unified SOC incident report successfully compiled.",
    });
  } catch (err: any) {
    console.error("[Reports Route] Error generating unified SOC report:", err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to generate unified SOC report.",
      },
    });
  }
});

/**
 * GET /api/reports/:reportId
 * Retrieve a specific forensic report, strictly enforcing user ownership and input validation.
 */
reportsRouter.get("/:reportId", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const { reportId } = req.params;

    if (!isValidIdentifier(reportId)) {
      res.status(400).json({
        error: {
          code: "INVALID_PARAMETER",
          message: "Invalid reportId parameter format.",
        },
      });
      return;
    }

    const report = await postgresService.getReport(uid, reportId);

    if (!report) {
      res.status(404).json({
        error: {
          code: "NOT_FOUND",
          message: `Report '${reportId}' not found or unauthorized`,
        },
      });
      return;
    }

    res.status(200).json({ report });
  } catch (err) {
    console.error(`[Reports Route] Error fetching report ${req.params.reportId}:`, err);
    res.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to retrieve report",
      },
    });
  }
});

