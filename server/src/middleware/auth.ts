import type { Response, NextFunction } from "express";
import { auth, isFirebaseConfigured } from "../config/firebaseAdmin";
import type { AuthenticatedRequest } from "../types/api";

/**
 * =====================================================================
 * FIREBASE AUTHENTICATION MIDDLEWARE
 * =====================================================================
 * Reads Authorization header: Bearer <Firebase ID Token>
 * Verifies token via Firebase Admin SDK.
 * Attaches verified UID to request as req.ownerUid and req.user.
 * Rejects with 401 if token is missing or invalid.
 * =====================================================================
 */
export async function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Missing or malformed Authorization header. Expected Bearer <Firebase ID token>",
    });
    return;
  }

  const token = authHeader.split("Bearer ")[1]?.trim();

  if (!token) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Authentication token empty",
    });
    return;
  }

  try {
    // If Firebase Admin has live credentials, verify via Admin SDK
    if (isFirebaseConfigured) {
      const decodedToken = await auth.verifyIdToken(token);
      req.user = decodedToken;
      // Derive UID strictly from verified token, never client params
      req.ownerUid = decodedToken.uid;
      next();
      return;
    }

    // In local development when live service account is not yet configured:
    // Allow standard verifyIdToken attempt first
    try {
      const decodedToken = await auth.verifyIdToken(token);
      req.user = decodedToken;
      req.ownerUid = decodedToken.uid;
      next();
      return;
    } catch (adminVerifyErr) {
      // If running dev without live credentials, support test token for local offline testing
      if (
        process.env.NODE_ENV !== "production" &&
        (token.startsWith("dev-") || token === "test-token" || process.env.ALLOW_DEV_AUTH === "true")
      ) {
        req.ownerUid = token.startsWith("dev-") ? `uid-${token}` : "dev-analyst-001";
        req.user = {
          uid: req.ownerUid,
          email: "analyst@phantomtrace.local",
          name: "PhantomTrace Dev Analyst",
          auth_time: Math.floor(Date.now() / 1000),
          iss: "https://securetoken.google.com/phantomtrace-dev",
          aud: "phantomtrace-dev",
          sub: req.ownerUid,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          firebase: { identities: {}, sign_in_provider: "custom" },
        };
        next();
        return;
      }

      console.warn("[Auth Middleware] Firebase token verification rejected:", adminVerifyErr);
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid or expired Firebase ID token",
      });
      return;
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "Authentication error";
    console.error("[Auth Middleware] Authentication failed:", errorMsg);
    res.status(401).json({
      error: "Unauthorized",
      message: "Token verification failed",
    });
  }
}
