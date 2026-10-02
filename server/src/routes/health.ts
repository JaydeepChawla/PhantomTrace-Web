import { Router, Request, Response } from "express";
import { isFirebaseConfigured } from "../config/firebaseAdmin";

export const healthRouter = Router();

/**
 * GET /api/health
 * Public diagnostic health check endpoint.
 * Returns service operational status without leaking credentials or secrets.
 */
healthRouter.get("/", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    service: "PhantomTrace API",
    version: "1.0.0",
    firebaseConfigured: isFirebaseConfigured,
  });
});
