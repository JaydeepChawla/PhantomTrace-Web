import { Router, Response } from "express";
import crypto from "crypto";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import type { AuthenticatedRequest, UserDocument, UserSessionDocument } from "../types/api";

export const authRouter = Router();

/**
 * POST /api/auth/session
 * Public User Registration / Session Initiation
 * Allows public web users to establish an authenticated tenant account
 * without needing the private owner API key.
 */
authRouter.post("/session", async (req, res: Response): Promise<void> => {
  try {
    const rawEmail = typeof req.body?.email === "string" ? req.body.email.trim() : "";
    const rawName = typeof req.body?.displayName === "string" ? req.body.displayName.trim() : "";

    // Generate or derive unique user identifier
    const email = rawEmail || `user_${crypto.randomBytes(4).toString("hex")}@phantomtrace.local`;
    const displayName = rawName || "Security Analyst";
    const uid = typeof req.body?.uid === "string" && req.body.uid.trim()
      ? req.body.uid.trim()
      : `usr_${crypto.randomBytes(8).toString("hex")}`;

    // Issue cryptographic session token
    const rawSessionToken = `pt_usr_${crypto.randomBytes(32).toString("hex")}`;
    const tokenHash = crypto.createHash("sha256").update(rawSessionToken).digest("hex");
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

    const session: UserSessionDocument = {
      tokenHash,
      uid,
      email,
      displayName,
      createdAt: new Date().toISOString(),
      expiresAt,
    };

    await postgresService.createUserSession(session);

    const userDoc: UserDocument = {
      uid,
      email,
      displayName,
      role: "Security Analyst",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await postgresService.upsertUser(userDoc);

    res.status(200).json({
      success: true,
      user: {
        uid,
        email,
        displayName,
      },
      sessionToken: rawSessionToken,
      expiresAt,
    });
  } catch (err) {
    console.error("[Auth Route] Error creating user session:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to establish user session",
    });
  }
});

/**
 * GET /api/auth/me
 * Retrieves active session profile
 */
authRouter.get("/me", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  res.status(200).json({
    user: req.user,
    authType: req.authType,
    deviceId: req.deviceId,
  });
});
