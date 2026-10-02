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
    console.error("[Health] PostgreSQL check failed:", error);

    res.status(503).json({
      status: "degraded",
      service: "PhantomTrace API",
      version: "1.0.0",
      database: "postgresql",
      databaseConnected: false,
    });
  }
});
