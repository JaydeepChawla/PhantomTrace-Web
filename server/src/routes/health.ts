import { Router, Request, Response } from "express";
import { postgresPool } from "../config/postgres";

export const healthRouter = Router();

/**
 * GET /api/health
 * Public diagnostic health check endpoint.
 * Reports API and PostgreSQL availability without exposing secrets.
 */
healthRouter.get("/", async (_req: Request, res: Response) => {
  try {
    await postgresPool.query("SELECT 1");

    res.status(200).json({
      status: "ok",
      service: "PhantomTrace API",
      version: "1.0.0",
      database: "postgresql",
      databaseConnected: true,
    });
  } catch (error) {
    console.error("[Health] PostgreSQL check failed:", (error as Error).message);

    // In production, return 503 so cloud platforms/orchestrators detect database unavailability.
    // In local development, return 200 with degraded status to allow local UI testing with in-memory fallback.
    const isProduction = process.env.NODE_ENV === "production";
    const statusCode = isProduction ? 503 : 200;

    res.status(statusCode).json({
      status: "degraded",
      service: "PhantomTrace API",
      version: "1.0.0",
      database: "postgresql",
      databaseConnected: false,
    });
  }
});
