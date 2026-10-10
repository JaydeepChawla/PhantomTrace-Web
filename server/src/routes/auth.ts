import { Router, Response } from "express";
import crypto from "crypto";
import { authMiddleware, safeEqual } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import type { AuthenticatedRequest, UserDocument, UserSessionDocument } from "../types/api";

export const authRouter = Router();

/**
 * POST /api/auth/session
 * Public User Registration / Guest Session Initiation
 * Strictly generates a cryptographically random, unprivileged tenant UID.
 * Never accepts or impersonates a client-supplied UID or 'phantomtrace-owner'.
 */
authRouter.post("/session", async (req, res: Response): Promise<void> => {
  try {
    const rawEmail = typeof req.body?.email === "string" ? req.body.email.trim() : "";
    const rawName = typeof req.body?.displayName === "string" ? req.body.displayName.trim() : "";

    // Generate cryptographically random, unprivileged user identifier (128-bit entropy)
    // Client-supplied UIDs are strictly ignored to prevent account impersonation / IDOR.
    const uid = `usr_${crypto.randomBytes(16).toString("hex")}`;
    const email = rawEmail || `${uid}@phantomtrace.local`;
    const displayName = rawName || "Security Analyst";

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
 * POST /api/auth/login
 * Authenticated Administrative Sign-In
 * Allows an authorized administrator to access 'phantomtrace-owner' records
 * strictly by presenting and cryptographically verifying the master API key.
 */
authRouter.post("/login", async (req, res: Response): Promise<void> => {
  try {
    const rawApiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";
    const serverApiKey = process.env.PHANTOMTRACE_API_KEY;

    if (!serverApiKey || !rawApiKey || !safeEqual(rawApiKey, serverApiKey)) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid administrator credentials.",
      });
      return;
    }

    const ownerUid = process.env.PHANTOMTRACE_OWNER_UID?.trim() || "phantomtrace-owner";
    const rawSessionToken = `pt_usr_${crypto.randomBytes(32).toString("hex")}`;
    const tokenHash = crypto.createHash("sha256").update(rawSessionToken).digest("hex");
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

    const session: UserSessionDocument = {
      tokenHash,
      uid: ownerUid,
      email: process.env.PHANTOMTRACE_OWNER_EMAIL?.trim() || "owner@phantomtrace.local",
      displayName: process.env.PHANTOMTRACE_OWNER_NAME?.trim() || "PhantomTrace Owner",
      createdAt: new Date().toISOString(),
      expiresAt,
    };

    await postgresService.createUserSession(session);

    const userDoc: UserDocument = {
      uid: ownerUid,
      email: session.email || "owner@phantomtrace.local",
      displayName: session.displayName || "PhantomTrace Owner",
      role: "Administrator",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await postgresService.upsertUser(userDoc);

    res.status(200).json({
      success: true,
      user: {
        uid: ownerUid,
        email: session.email,
        displayName: session.displayName,
        role: "Administrator",
      },
      sessionToken: rawSessionToken,
      expiresAt,
    });
  } catch (err) {
    console.error("[Auth Route] Error during administrator login:", err);
    res.status(500).json({
      error: "InternalServerError",
      message: "Failed to establish administrator session",
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
